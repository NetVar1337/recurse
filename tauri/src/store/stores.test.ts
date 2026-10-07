import { beforeEach, describe, expect, it, vi } from "vitest";

// Node has no localStorage; settingsStore reads it at module init.
const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
	getItem: (k: string) => store.get(k) ?? null,
	setItem: (k: string, v: string) => void store.set(k, v),
	removeItem: (k: string) => void store.delete(k),
});

// Stores hit the Tauri backend through ../api; mock the whole module so
// tests drive pure state logic and race guards without a runtime.
vi.mock("../api", () => ({
	api: {
		functionDisasm: vi.fn(),
		decompile: vi.fn(),
		setZoom: vi.fn().mockResolvedValue(undefined),
		renameVariable: vi.fn().mockResolvedValue(undefined),
		setVariableType: vi.fn().mockResolvedValue(undefined),
	},
}));

import { useAnalysisStore } from "./analysisStore";
import { useContextStore } from "./contextStore";
import {
	clampDebugContext,
	DEBUG_CONTEXT_DEFAULT,
	DEBUG_CONTEXT_MAX,
	DEBUG_CONTEXT_MIN,
	readInitialTheme,
	useSettingsStore,
} from "./settingsStore";
import { api } from "../api";

const flush = () => new Promise((r) => setTimeout(r, 0));

const mockedDisasm = vi.mocked(api.functionDisasm);

function deferred<T>() {
	let resolve!: (v: T) => void;
	const promise = new Promise<T>((r) => (resolve = r));
	return { promise, resolve };
}

describe("analysisStore selectFn stale-response guard", () => {
	beforeEach(() => {
		useAnalysisStore.getState().reset();
		mockedDisasm.mockReset();
	});

	it("applies only the newest selection when responses race", async () => {
		const first = deferred();
		const second = deferred();
		mockedDisasm
			.mockReturnValueOnce(first.promise as never)
			.mockReturnValueOnce(second.promise as never);

		useAnalysisStore.getState().selectFn({ addr: 0x1000 } as never);
		useAnalysisStore.getState().selectFn({ addr: 0x2000 } as never);

		// Old response lands last-in-real-time? No: resolve OLD first — the
		// guard must still keep it from clobbering the newer selection.
		first.resolve({ instructions: [{ text: "old" }] });
		await Promise.resolve();
		expect(useAnalysisStore.getState().asm).toBeNull(); // discarded
		expect(useAnalysisStore.getState().selected?.addr).toBe(0x2000);

		second.resolve({ instructions: [{ text: "new" }] });
		await flush();
		expect(useAnalysisStore.getState().asm).toEqual({
			instructions: [{ text: "new" }],
		});
		expect(useAnalysisStore.getState().asmLoading).toBe(false);
	});

	it("reuses cached disassembly when switching back to a function", async () => {
		mockedDisasm
			.mockResolvedValueOnce({ name: "one" } as never)
			.mockResolvedValueOnce({ name: "two" } as never);
		useAnalysisStore.getState().selectFn({ addr: 0x1000 } as never);
		await flush();
		useAnalysisStore.getState().selectFn({ addr: 0x2000 } as never);
		await flush();
		useAnalysisStore.getState().selectFn({ addr: 0x1000 } as never);
		expect(mockedDisasm).toHaveBeenCalledTimes(2);
		expect(useAnalysisStore.getState().asm).toEqual({ name: "one" });
		expect(useAnalysisStore.getState().asmLoading).toBe(false);
	});

	it("clears loading on error for the current selection", async () => {
		mockedDisasm.mockRejectedValueOnce(new Error("boom"));
		useAnalysisStore.getState().selectFn({ addr: 0x3000 } as never);
		await flush();
		const s = useAnalysisStore.getState();
		expect(s.asmLoading).toBe(false);
	});
});

describe("analysisStore variable names", () => {
	beforeEach(() => {
		useAnalysisStore.setState({ variableNames: {} });
		vi.mocked(api.renameVariable).mockReset();
		vi.mocked(api.renameVariable).mockResolvedValue(undefined);
	});

	it("records a name against the function and the variable's own key", () => {
		// The key is the frame offset, or the register for an argument: a local
		// has no address, and two functions may both use `-0x18`.
		useAnalysisStore
			.getState()
			.setVariableName(0x401000, "-24", "flag_len");
		expect(useAnalysisStore.getState().variableNames).toEqual({
			[`${0x401000}:-24`]: "flag_len",
		});
	});

	it("keeps each function's names apart", () => {
		useAnalysisStore
			.getState()
			.setVariableName(0x401000, "-24", "flag_len");
		useAnalysisStore.getState().setVariableName(0x402000, "-24", "length");
		expect(useAnalysisStore.getState().variableNames).toEqual({
			[`${0x401000}:-24`]: "flag_len",
			[`${0x402000}:-24`]: "length",
		});
	});

	it("forgets a name when it is cleared", () => {
		useAnalysisStore
			.getState()
			.setVariableName(0x401000, "-24", "flag_len");
		useAnalysisStore.getState().setVariableName(0x401000, "-24", "   ");
		expect(useAnalysisStore.getState().variableNames).toEqual({});
	});
});

describe("analysisStore variable types", () => {
	beforeEach(() => {
		useAnalysisStore.setState({ variableTypes: {} });
		vi.mocked(api.setVariableType).mockReset();
		vi.mocked(api.setVariableType).mockResolvedValue(undefined);
	});

	it("records a type against the same key a name uses", () => {
		// A name says what a datum is called and a type says what it holds, so
		// the two are separate records over one identity — which is what lets a
		// local be named without being typed.
		useAnalysisStore.getState().setVariableName(0x401000, "-24", "buf");
		useAnalysisStore.getState().setVariableType(0x401000, "-24", "char[8]");
		const s = useAnalysisStore.getState();
		expect(s.variableNames).toEqual({ [`${0x401000}:-24`]: "buf" });
		expect(s.variableTypes).toEqual({ [`${0x401000}:-24`]: "char[8]" });
	});

	it("keys the return value separately from any local", () => {
		useAnalysisStore
			.getState()
			.setVariableType(0x401000, "<RETURN>", "int");
		expect(useAnalysisStore.getState().variableTypes).toEqual({
			[`${0x401000}:<RETURN>`]: "int",
		});
	});

	it("trims what the analyst typed", () => {
		useAnalysisStore
			.getState()
			.setVariableType(0x401000, "rdi", " char * ");
		expect(useAnalysisStore.getState().variableTypes).toEqual({
			[`${0x401000}:rdi`]: "char *",
		});
	});

	it("forgets a type when it is cleared", () => {
		useAnalysisStore.getState().setVariableType(0x401000, "-24", "char[8]");
		useAnalysisStore.getState().setVariableType(0x401000, "-24", "  ");
		expect(useAnalysisStore.getState().variableTypes).toEqual({});
	});

	it("keeps each function's types apart", () => {
		useAnalysisStore.getState().setVariableType(0x401000, "-24", "char[8]");
		useAnalysisStore
			.getState()
			.setVariableType(0x402000, "-24", "uint64_t");
		expect(useAnalysisStore.getState().variableTypes).toEqual({
			[`${0x401000}:-24`]: "char[8]",
			[`${0x402000}:-24`]: "uint64_t",
		});
	});
});

describe("contextStore", () => {
	it("commitPending appends and clears pending", () => {
		useContextStore.getState().clear();
		useContextStore.getState().setPending({
			source: "disasm",
			label: "main",
			text: "push rbp",
		} as never);
		useContextStore.getState().commitPending();
		const items = useContextStore.getState().items;
		expect(items).toHaveLength(1);
		expect(items[0].label).toBe("main");
		expect(useContextStore.getState().pending).toBeNull();
	});
});

describe("settingsStore zoom clamps", () => {
	it("zoomIn stops at MAX", async () => {
		useSettingsStore.setState({ zoomLevel: 8 });
		await useSettingsStore.getState().zoomIn();
		expect(useSettingsStore.getState().zoomLevel).toBe(8);
	});

	it("zoomOut stops at MIN", async () => {
		useSettingsStore.setState({ zoomLevel: -5 });
		await useSettingsStore.getState().zoomOut();
		expect(useSettingsStore.getState().zoomLevel).toBe(-5);
	});
});

describe("settingsStore debugger context depth", () => {
	it("starts at the default", () => {
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_DEFAULT,
		);
	});

	it("uses the documented range", () => {
		// The slider runs from no context at all to most of the pane, so these
		// are exact values, not just relative bounds: a wider default or cap
		// would be a visible change.
		expect(DEBUG_CONTEXT_MIN).toBe(0);
		expect(DEBUG_CONTEXT_MAX).toBe(20);
		expect(DEBUG_CONTEXT_DEFAULT).toBe(5);
	});

	it("keeps the default inside the range", () => {
		expect(DEBUG_CONTEXT_DEFAULT).toBeGreaterThanOrEqual(DEBUG_CONTEXT_MIN);
		expect(DEBUG_CONTEXT_DEFAULT).toBeLessThanOrEqual(DEBUG_CONTEXT_MAX);
	});

	it("clamps into the supported range", () => {
		const { setDebugContext } = useSettingsStore.getState();
		setDebugContext(-40);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_MIN,
		);
		setDebugContext(99999);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_MAX,
		);
	});

	it("keeps zero, which means no context above the counter", () => {
		useSettingsStore.getState().setDebugContext(0);
		expect(useSettingsStore.getState().debugContext).toBe(0);
	});

	it("rounds a fractional depth", () => {
		useSettingsStore.getState().setDebugContext(3.6);
		expect(useSettingsStore.getState().debugContext).toBe(4);
	});

	it("falls back to the default for a non-finite depth", () => {
		useSettingsStore.getState().setDebugContext(Number.NaN);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_DEFAULT,
		);
	});

	it("nudges and stops at the bounds", () => {
		const { nudgeDebugContext, setDebugContext } =
			useSettingsStore.getState();
		setDebugContext(5);
		nudgeDebugContext(3);
		expect(useSettingsStore.getState().debugContext).toBe(8);
		nudgeDebugContext(-100);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_MIN,
		);
		nudgeDebugContext(9999);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_MAX,
		);
	});

	it("accepts every value the slider can reach", () => {
		for (let n = DEBUG_CONTEXT_MIN; n <= DEBUG_CONTEXT_MAX; n++) {
			useSettingsStore.getState().setDebugContext(n);
			expect(useSettingsStore.getState().debugContext).toBe(n);
		}
	});

	it("persists the depth so it survives a reload", () => {
		useSettingsStore.getState().setDebugContext(8);
		expect(store.get("recurse.debugContext")).toBe("8");
	});

	it("clamps a depth saved under a different range", () => {
		// A value persisted before the range changed must not escape it.
		useSettingsStore.getState().setDebugContext(64);
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_MAX,
		);
		expect(store.get("recurse.debugContext")).toBe(
			String(DEBUG_CONTEXT_MAX),
		);
	});

	it("resets to the default and forgets the saved value", () => {
		useSettingsStore.getState().setDebugContext(9);
		useSettingsStore.getState().resetDebugContext();
		expect(useSettingsStore.getState().debugContext).toBe(
			DEBUG_CONTEXT_DEFAULT,
		);
		expect(store.get("recurse.debugContext")).toBeUndefined();
	});
});

describe("settingsStore theme", () => {
	beforeEach(() => {
		store.clear();
	});

	it("applies a named theme and persists its id", () => {
		useSettingsStore.getState().setTheme("tokyo-night");
		expect(useSettingsStore.getState().theme).toBe("tokyo-night");
		expect(store.get("recurse.theme")).toBe("tokyo-night");
	});

	it("falls back to the default rather than storing an unknown theme", () => {
		// An id that is not a theme has no palette behind it. Writing it would
		// leave the reader on the second run with every token resolving to
		// nothing, so it is refused on the way in rather than on the way out.
		useSettingsStore.getState().setTheme("nope");
		expect(useSettingsStore.getState().theme).toBe("recurse-dark");
		expect(store.get("recurse.theme")).toBe("recurse-dark");
	});

	it("toggles across the light/dark line rather than through the list", () => {
		// Stepping through ten themes in order would make a two-press switch a
		// ten-press one whose second press lands nowhere near the inverse.
		useSettingsStore.getState().setTheme("dracula");
		useSettingsStore.getState().toggleTheme();
		expect(useSettingsStore.getState().theme).toBe("recurse-light");
		useSettingsStore.getState().toggleTheme();
		expect(useSettingsStore.getState().theme).toBe("recurse-dark");
	});

	it("keeps a light theme from toggling to another light theme", () => {
		useSettingsStore.getState().setTheme("solarized-light");
		useSettingsStore.getState().toggleTheme();
		expect(useSettingsStore.getState().theme).toBe("recurse-dark");
	});
});

describe("settingsStore theme migration", () => {
	beforeEach(() => {
		store.clear();
	});

	// The theme was "light" or "dark" before there were themes. Reinterpreting
	// those keeps the reader on the side they asked for; overwriting them with a
	// fresh default would re-ask a question they had answered, in the one
	// setting where that is least forgivable.
	it("reads an old 'light' as Recurse Light", () => {
		store.set("recurse.theme", "light");
		expect(readInitialTheme()).toBe("recurse-light");
	});

	it("reads an old 'dark' as Recurse Dark", () => {
		store.set("recurse.theme", "dark");
		expect(readInitialTheme()).toBe("recurse-dark");
	});

	it("reads an unreadable stored value as the default, not as a theme", () => {
		store.set("recurse.theme", "{not json");
		expect(readInitialTheme()).toBe("recurse-dark");
	});
});

describe("clampDebugContext", () => {
	it("passes through values already in range", () => {
		for (let n = DEBUG_CONTEXT_MIN; n <= DEBUG_CONTEXT_MAX; n++) {
			expect(clampDebugContext(n)).toBe(n);
		}
	});

	it("bounds values outside the range", () => {
		expect(clampDebugContext(-1)).toBe(DEBUG_CONTEXT_MIN);
		expect(clampDebugContext(21)).toBe(DEBUG_CONTEXT_MAX);
		expect(clampDebugContext(500)).toBe(DEBUG_CONTEXT_MAX);
	});

	it("rounds, then bounds", () => {
		expect(clampDebugContext(4.4)).toBe(4);
		expect(clampDebugContext(4.5)).toBe(5);
		expect(clampDebugContext(19.7)).toBe(DEBUG_CONTEXT_MAX);
	});

	it("treats any non-finite value as unset and uses the default", () => {
		// Not "clamp to the bound": a NaN or Infinity from a corrupt value means
		// there is no usable preference, so the default is the safe answer.
		expect(clampDebugContext(Number.NaN)).toBe(DEBUG_CONTEXT_DEFAULT);
		expect(clampDebugContext(Number.POSITIVE_INFINITY)).toBe(
			DEBUG_CONTEXT_DEFAULT,
		);
		expect(clampDebugContext(Number.NEGATIVE_INFINITY)).toBe(
			DEBUG_CONTEXT_DEFAULT,
		);
	});
});
