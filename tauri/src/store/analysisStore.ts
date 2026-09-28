import { create } from "zustand";

import { api } from "../api";
import type {
	AsmResult,
	DataRegions,
	DecompileAnnotation,
	Function,
	Import,
	R2String,
} from "../types";
import { useUiStore } from "./uiStore";

interface AnalysisState {
	funcs: Function[];
	selected: Function | null;
	asm: AsmResult | null;
	/** Disassembly cache keyed by function address for instant tab switches. */
	asmByAddr: Record<number, AsmResult>;
	/** In-flight requests are shared when switching away and back quickly. */
	asmPending: Record<number, Promise<AsmResult>>;
	asmLoading: boolean;
	strings: R2String[];
	imports: Import[];
	/**
	 * Analyst names for locals and arguments, as `"<func>:<key>" -> name`.
	 *
	 * The key is the frame offset for a local and the register for an argument,
	 * scoped by function: two functions may both use `-0x18` for entirely
	 * different things, so a name belongs to one of them and not the other.
	 */
	variableNames: Record<string, string>;
	/**
	 * The image's non-executable regions. Empty until a binary is opened, and
	 * for a backend that does not report them at all.
	 */
	dataRegions: DataRegions;
	decompiled: string | null;
	decompiledAnnotations: DecompileAnnotation[];
	decompileError: string | null;
	decompiling: boolean;

	/** Record one variable's name, or drop it when the name is blank. */
	setVariableName: (func: number, key: string | number, name: string) => void;
	beginOpen: () => void;
	setAll: (data: {
		funcs: Function[];
		strings: R2String[];
		imports: Import[];
		variableNames: Record<string, string>;
		dataRegions: DataRegions;
	}) => void;
	setFunctions: (funcs: Function[]) => void;
	renameFunction: (addr: number, name: string) => Promise<void>;
	reset: () => void;
	selectFn: (fn: Function) => void;
	refreshDisasm: () => Promise<void>;
	decompile: () => Promise<void>;
	clearDecompiled: () => void;
}

const initial = {
	funcs: [] as Function[],
	selected: null as Function | null,
	asm: null as AsmResult | null,
	asmByAddr: {} as Record<number, AsmResult>,
	asmPending: {} as Record<number, Promise<AsmResult>>,
	asmLoading: false,
	strings: [] as R2String[],
	imports: [] as Import[],
	variableNames: {} as Record<string, string>,
	dataRegions: { sections: [], boundaries: [] } as DataRegions,
	decompiled: null as string | null,
	decompiledAnnotations: [] as DecompileAnnotation[],
	decompileError: null as string | null,
	decompiling: false,
};

const setErr = (e: string) => useUiStore.getState().setErr(e);

export const useAnalysisStore = create<AnalysisState>((set, get) => ({
	...initial,

	beginOpen: () => set({ ...initial }),

	setAll: ({ funcs, strings, imports, variableNames, dataRegions }) =>
		set({ funcs, strings, imports, variableNames, dataRegions }),
	/** Record one variable's name, or drop it when the name is blank. */
	setVariableName: (func: number, key: string | number, name: string) =>
		set((s) => {
			const record = `${func}:${key}`;
			const next = { ...s.variableNames };
			const trimmed = name.trim();
			if (trimmed) next[record] = trimmed;
			else delete next[record];
			return { variableNames: next };
		}),

	setFunctions: (funcs) =>
		set((state) => ({
			funcs,
			selected: state.selected
				? (funcs.find((f) => f.addr === state.selected?.addr) ??
					state.selected)
				: null,
		})),

	renameFunction: async (addr, name) => {
		const trimmed = name.trim();
		await api.renameFunction(addr, trimmed);
		const sel = get().selected;
		if (!trimmed) {
			// Clearing restores the engine's original name.
			const funcs = await api.functions();
			set({
				funcs,
				selected:
					sel?.addr === addr
						? (funcs.find((f) => f.addr === addr) ?? sel)
						: sel,
			});
		} else {
			set({
				funcs: get().funcs.map((f) =>
					f.addr === addr ? { ...f, name: trimmed } : f,
				),
				selected: sel?.addr === addr ? { ...sel, name: trimmed } : sel,
			});
		}
		// Disassembly comments embed function names, so re-fetch the open
		// function so the rename shows up there too (the graph already
		// re-fetches because it depends on `funcs`).
		if (sel?.addr === addr) await get().refreshDisasm();
	},

	reset: () => set({ ...initial, decompiling: false }),

	selectFn: (fn) => {
		// UI concern: switch to disassembly tab when a function is picked.
		useUiStore.getState().setTab("disasm");
		const cached = get().asmByAddr[fn.addr];
		set(() => ({
			selected: fn,
			asm: cached ?? null,
			asmLoading: !cached,
			decompiled: null,
			decompiledAnnotations: [],
			decompileError: null,
			decompiling: false,
		}));
		const addr = fn.addr;
		if (
			cached ||
			Object.prototype.hasOwnProperty.call(get().asmPending, addr)
		)
			return;
		const request = api.functionDisasm(addr);
		set((state) => ({
			asmPending: { ...state.asmPending, [addr]: request },
		}));
		request
			.then((asm) => {
				set((state) => ({
					asmByAddr: { ...state.asmByAddr, [addr]: asm },
					...(state.selected?.addr === addr ? { asm } : {}),
				}));
			})
			.catch((e) => {
				if (get().selected?.addr === addr) {
					set({ asm: null });
					setErr(String(e));
				}
			})
			.finally(() => {
				set((state) => {
					const { [addr]: _finished, ...pending } = state.asmPending;
					return {
						asmPending: pending,
						...(state.selected?.addr === addr
							? { asmLoading: false }
							: {}),
					};
				});
			});
	},

	refreshDisasm: async () => {
		const sel = get().selected;
		if (!sel) return;
		const addr = sel.addr;
		set({ asmLoading: true });
		try {
			const asm = await api.functionDisasm(addr);
			set((state) => ({
				asmByAddr: { ...state.asmByAddr, [addr]: asm },
				...(state.selected?.addr === addr ? { asm } : {}),
			}));
		} catch (e) {
			if (get().selected?.addr === addr) setErr(String(e));
		} finally {
			if (get().selected?.addr === addr) set({ asmLoading: false });
		}
	},

	decompile: async () => {
		const sel = get().selected;
		if (!sel) return;
		const addr = sel.addr;
		set({
			decompiling: true,
			decompiled: null,
			decompiledAnnotations: [],
			decompileError: null,
		});
		try {
			const out = await api.decompile(addr);
			if (get().selected?.addr !== addr) return;
			const code =
				typeof out === "string"
					? out
					: (out?.code ?? JSON.stringify(out, null, 2));
			const annotations =
				typeof out === "string" ? [] : (out.annotations ?? []);
			set({ decompiled: code, decompiledAnnotations: annotations });
		} catch (e) {
			if (get().selected?.addr !== addr) return;
			set({
				decompileError: `${e}\n\nThe decompiler plugin is not available on this install.`,
			});
		} finally {
			if (get().selected?.addr === addr) set({ decompiling: false });
		}
	},

	clearDecompiled: () =>
		set({
			decompiled: null,
			decompiledAnnotations: [],
			decompileError: null,
			decompiling: false,
		}),
}));
