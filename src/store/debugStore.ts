import { create } from "zustand";

import type { CenterTab } from "../types";
import { useUiStore } from "./uiStore";

/**
 * Shared debug-run state so the Shell tab can host the program's I/O
 * terminal and the app can auto-navigate around interactive prompts:
 *
 * - `started` — a debugger session is live (drives the Program terminal).
 * - `busy` — a continue/step is in flight (the program may be running).
 * - `awaitingIo` — program output arrived mid-run, so the UI jumped to the
 *   Shell tab to show the prompt; when the run finishes we switch back to
 *   `returnTab`.
 */
interface DebugState {
	started: boolean;
	busy: boolean;
	awaitingIo: boolean;
	returnTab: CenterTab;
	/** Bumped whenever the UI should surface the program terminal. */
	ioFocusTick: number;
	setStarted: (b: boolean) => void;
	beginRun: () => void;
	/** First output chunk of a run: jump to the Shell tab (once per run). */
	noteIoPrompt: () => void;
	/** Run over (breakpoint/exit/interrupt): return to where we came from. */
	endRun: () => void;
	focusProgram: () => void;
}

export const useDebugStore = create<DebugState>((set, get) => ({
	started: false,
	busy: false,
	awaitingIo: false,
	returnTab: "debug",
	ioFocusTick: 0,
	setStarted: (started) => set({ started }),
	beginRun: () => set({ busy: true, awaitingIo: false }),
	noteIoPrompt: () => {
		const { busy, awaitingIo, focusProgram } = get();
		const ui = useUiStore.getState();
		if (!busy || awaitingIo || ui.tab === "shell") {
			if (busy && !awaitingIo && ui.tab === "shell") focusProgram();
			return;
		}
		set((s) => ({
			awaitingIo: true,
			returnTab: ui.tab,
			ioFocusTick: s.ioFocusTick + 1,
		}));
		ui.setTab("shell");
	},
	endRun: () => {
		const { awaitingIo, returnTab } = get();
		if (awaitingIo) {
			useUiStore.getState().setTab(returnTab);
		}
		set({ busy: false, awaitingIo: false });
	},
	focusProgram: () => set((s) => ({ ioFocusTick: s.ioFocusTick + 1 })),
}));
