import { create } from "zustand";

/**
 * Navigation history for address jumps — the back/forward arrows a reverse
 * engineering tool puts beside the listing. Only the addresses are kept; the
 * caller resolves one back to a function when it navigates.
 */
interface NavState {
	/** Visited addresses, oldest first. */
	history: number[];
	/** Index of the current address within `history`; -1 when empty. */
	cursor: number;
	/**
	 * Record a visit. Selecting the address already at the cursor is a no-op,
	 * so returning via back/forward does not push a duplicate.
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

/**
 * Move the cursor one entry back.
 *
 * @returns The address to navigate to, or `null` at the start of history.
 */
export function navBack(): number | null {
	const { history, cursor } = useNavStore.getState();
	if (cursor <= 0) return null;
	const next = cursor - 1;
	useNavStore.setState({ cursor: next });
	return history[next] ?? null;
}

/**
 * Move the cursor one entry forward.
 *
 * @returns The address to navigate to, or `null` at the end of history.
 */
export function navForward(): number | null {
	const { history, cursor } = useNavStore.getState();
	if (cursor >= history.length - 1) return null;
	const next = cursor + 1;
	useNavStore.setState({ cursor: next });
	return history[next] ?? null;
}
