import { create } from "zustand";

/**
 * Navigation history for address jumps.
 *
 * Only the addresses are kept; a caller that wants one back as a function
 * resolves it itself. Nothing moves the cursor yet — `push` is the whole of
 * the recorded history, kept so a back/forward control has something to read
 * when one is added.
 */
interface NavState {
	/** Visited addresses, oldest first. */
	history: number[];
	/** Index of the current address within `history`; -1 when empty. */
	cursor: number;
	/**
	 * Record a visit. Selecting the address already at the cursor is a no-op,
	 * so revisiting an address does not push a duplicate.
	 *
	 * @param addr - The address being visited.
	 */
	push: (addr: number) => void;
	/** Drop the whole history, e.g. when a new target is opened. */
	reset: () => void;
}

export const useNavStore = create<NavState>((set) => ({
	history: [],
	cursor: -1,
	push: (addr) =>
		set((s) => {
			if (s.history[s.cursor] === addr) return s;
			const history = s.history.slice(0, s.cursor + 1);
			history.push(addr);
			return { history, cursor: history.length - 1 };
		}),
	reset: () => set({ history: [], cursor: -1 }),
}));


