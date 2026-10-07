/**
 * Batching for event streams that arrive faster than the screen refreshes.
 *
 * A streamed reply and a debuggee's stdout both deliver events as fast as the
 * host can read them, which is routinely faster than a frame. Committing each
 * one on its own is a render per event, and a render per event is the
 * difference between a stream that reads as continuous and one that stutters.
 *
 * A batcher collects what arrives and hands it over once per frame instead.
 * Order is preserved exactly: items are applied in the order they were pushed,
 * because for both callers the order *is* the content — a token after a tool
 * call is a different message than the same token before it.
 */

/** A collect-and-commit queue tied to one animation frame. */
export interface FrameBatch<T> {
	/**
	 * Queue an item, scheduling a commit if one is not already scheduled.
	 *
	 * @param item - The item to queue.
	 */
	push: (item: T) => void;
	/**
	 * Commit everything queued right now, in order.
	 *
	 * Called on the terminal paths of a stream, so that state a caller is about
	 * to read or branch on has already caught up with the wire.
	 */
	flush: () => void;
	/**
	 * Discard everything queued without committing it.
	 *
	 * For a stream that has been abandoned: its items describe a run that is no
	 * longer the current one, and applying them would resurrect it.
	 */
	drop: () => void;
	/** How many items are waiting to be committed. */
	readonly size: number;
}

/**
 * The longest a commit may be deferred, in milliseconds.
 *
 * A window that is occluded, minimized, or on another workspace stops being
 * given animation frames — so waiting for one alone can hold a stream for as
 * long as the window stays hidden. The timer is a floor under the frame, not a
 * substitute for it: whichever arrives first commits, and the other is
 * cancelled.
 */
export const FRAME_FLOOR_MS = 100;

/**
 * Collect pushed items and commit them once per frame.
 *
 * @param apply - Receives everything queued, oldest first, and commits it. Must
 *   not push back into the same batcher.
 * @returns The batcher.
 *
 * @example
 * const batch = createFrameBatch<string>((items) => log(items.join("")));
 * batch.push("a");
 * batch.push("b");
 * batch.size; // => 2
 * batch.flush();
 * // log was called once, with "ab" — two pushes, one commit
 */
export function createFrameBatch<T>(
	apply: (items: T[]) => void,
): FrameBatch<T> {
	let buffer: T[] = [];
	let frame: number | null = null;
	let timer: ReturnType<typeof setTimeout> | null = null;

	const cancelScheduled = () => {
		if (frame !== null && typeof cancelAnimationFrame === "function") {
			cancelAnimationFrame(frame);
		}
		frame = null;
		if (timer !== null) clearTimeout(timer);
		timer = null;
	};

	const commit = () => {
		cancelScheduled();
		if (buffer.length === 0) return;
		// Taken before the call: an `apply` that pushes again must queue onto a
		// buffer that is no longer the one being read.
		const items = buffer;
		buffer = [];
		apply(items);
	};

	const schedule = () => {
		if (frame !== null || timer !== null) return;
		timer = setTimeout(commit, FRAME_FLOOR_MS);
		if (typeof requestAnimationFrame === "function") {
			frame = requestAnimationFrame(commit);
		}
	};

	return {
		push(item) {
			buffer.push(item);
			schedule();
		},
		flush: commit,
		drop() {
			cancelScheduled();
			buffer = [];
		},
		get size() {
			return buffer.length;
		},
	};
}
