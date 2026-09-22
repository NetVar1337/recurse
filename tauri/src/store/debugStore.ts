import { create } from "zustand";

import { api } from "../api";
import type {
	DebugBreakpoint,
	DebugFrame,
	DebugRegisters,
	DebugStatus,
	DebugStop,
} from "../types";

/** Ops whose result is a fresh stop (registers + reason). */
const STOP_OPS = new Set(["launch", "attach", "continue", "step"]);

interface DebugState {
	active: boolean;
	pid: number | null;
	state: string;
	stop: DebugStop | null;
	registers: DebugRegisters | null;
	breakpoints: DebugBreakpoint[];
	frames: DebugFrame[];
	output: string;
	log: string[];
	busy: boolean;
	error: string | null;

	/** Run one debugger op and fold its result into the store. */
	run: (op: string, args?: Record<string, unknown>) => Promise<unknown>;
	/** Send text to the debuggee's stdin. */
	sendStdin: (text: string) => Promise<void>;
	/** Drain the debuggee's captured output into `output`. */
	pollOutput: () => Promise<void>;
	launch: (path: string) => Promise<void>;
	attach: (pid: number) => Promise<void>;
	detach: () => Promise<void>;
	kill: () => Promise<void>;
	reset: () => void;
}

const initial = {
	active: false,
	pid: null as number | null,
	state: "idle",
	stop: null as DebugStop | null,
	registers: null as DebugRegisters | null,
	breakpoints: [] as DebugBreakpoint[],
	frames: [] as DebugFrame[],
	output: "",
	log: [] as string[],
	busy: false,
	error: null as string | null,
};

/** Append a line to the capped debug log. */
function appendLog(line: string): void {
	useDebugStore.setState((s) => ({ log: [...s.log, line].slice(-300) }));
}

/** Re-fetch the breakpoint list. */
async function refreshBreakpoints(): Promise<void> {
	try {
		const bps = (await api.debugCommand(
			"breakpoints",
		)) as DebugBreakpoint[];
		useDebugStore.setState({ breakpoints: bps ?? [] });
	} catch {
		/* leave the previous list */
	}
}

/** Re-fetch the backtrace. */
async function refreshFrames(): Promise<void> {
	try {
		const frames = (await api.debugCommand("backtrace")) as DebugFrame[];
		useDebugStore.setState({ frames: frames ?? [] });
	} catch {
		useDebugStore.setState({ frames: [] });
	}
}

/** Fold a stop result into the store and refresh derived state. */
async function applyStop(stop: DebugStop): Promise<void> {
	useDebugStore.setState({
		active: true,
		pid: stop.pid || null,
		state: "stopped",
		stop,
		registers: stop.registers,
	});
	await refreshBreakpoints();
	await refreshFrames();
}

export const useDebugStore = create<DebugState>((set, get) => ({
	...initial,

	run: async (op, args) => {
		set({ busy: true, error: null });
		appendLog(`> ${op}${args ? ` ${JSON.stringify(args)}` : ""}`);
		try {
			const out = await api.debugCommand(op, args);
			appendLog(JSON.stringify(out));
			if (STOP_OPS.has(op)) {
				await applyStop(out as DebugStop);
			} else if (op === "detach" || op === "kill") {
				set({ ...initial, log: get().log });
			} else if (op === "break" || op === "unbreak") {
				await refreshBreakpoints();
			} else if (op === "regs") {
				set({ registers: out as DebugRegisters });
			} else if (op === "backtrace") {
				set({ frames: (out as DebugFrame[]) ?? [] });
			} else if (op === "status") {
				const st = out as DebugStatus;
				set({
					pid: st.pid ?? null,
					state: st.state,
					breakpoints: st.breakpoints ?? [],
				});
			}
			return out;
		} catch (e) {
			set({ error: String(e) });
			appendLog(`! ${e}`);
			throw e;
		} finally {
			set({ busy: false });
		}
	},

	launch: async (path) => {
		await get().run("launch", { path });
	},

	sendStdin: async (text) => {
		try {
			await api.debugCommand("stdin", { data: text });
		} catch (e) {
			set({ error: String(e) });
		}
	},

	pollOutput: async () => {
		try {
			const out = (await api.debugCommand("output")) as {
				text?: string;
			};
			const text = out?.text ?? "";
			if (text) {
				set((s) => ({ output: (s.output + text).slice(-20000) }));
			}
		} catch {
			/* the worker may be busy; try again next tick */
		}
	},

	attach: async (pid) => {
		await get().run("attach", { pid });
	},

	detach: async () => {
		await get().run("detach");
	},

	kill: async () => {
		await get().run("kill");
	},

	reset: () => set({ ...initial }),
}));
