/**
 * How a stack of panes divides the height it is given.
 *
 * Kept apart from the component because it is the part with a right answer: a
 * pane whose list is longer than the space it was given should open with the
 * room its content needs, and a pane the analyst has made small should stay
 * small until they drag it again.
 */

/** Smallest share any one pane may take, so no pane can vanish entirely. */
export const MIN_SHARE = 0.08;

/** Largest share one pane may take, so the others always keep some room. */
export const MAX_SHARE = 0.6;

/** How a stack may be divided. */
export interface ShareOptions {
	/** Smallest share a pane may take. */
	min?: number;
	/** Largest share a pane may take. */
	max?: number;
}

/**
 * The pane on the far side of the divider that follows pane `index`.
 *
 * A divider sits between two panes and drags one against the other, so the pane
 * it trades with is the one on its own side — not the first pane in the stack,
 * which is only the same pane when there are only two. With three panes, a
 * divider that charged its movement to the first pane would shift two panes'
 * worth of boundary for one divider's worth of drag, and the middle pane would
 * look like the thing that was being dragged.
 *
 * ```
 * neighbourOf(0, 2)  // => 1
 * neighbourOf(0, 3)  // => 1
 * neighbourOf(1, 3)  // => 2 — the last pane, not the first
 * neighbourOf(2, 3)  // => 1 — nothing to the right, so the left
 * ```
 *
 * @param index - The pane whose following divider is being moved.
 * @param count - How many panes the stack holds.
 * @returns The index of the pane the divider trades height with, or -1 for a
 *   stack of one, which has no divider to move.
 */
export function neighbourOf(index: number, count: number): number {
	return index + 1 < count ? index + 1 : index - 1;
}

/**
 * Divide a fixed height between panes in proportion to what each needs.
 *
 * A pane asking for less than its share — a short list, a boundary table of
 * three — is given what it asked for and the remainder goes to the panes that
 * need it, so a nineteen-row section list does not push a three-row marker list
 * off screen. A pane asking for more is capped, and the excess is redistributed
 * rather than discarded, so an overflowing list still leaves the others usable.
 *
 * The shares always sum to 1, because the panes fill a fixed height: a set that
 * summed to less would leave a gap, and one that summed to more would overflow.
 *
 * ```
 * distribute([400, 100, 100])          // => [0.667, 0.167, 0.167]
 * distribute([100, 100])                // => [0.5, 0.5]
 * distribute([10_000, 100, 100])        // => the long pane capped at 0.6
 * ```
 *
 * @param needs - The height each pane's content wants, in pixels.
 * @param options - Bounds on one pane's share.
 * @returns One share per pane, summing to 1.
 */
export function distribute(
	needs: readonly number[],
	{ min = MIN_SHARE, max = MAX_SHARE }: ShareOptions = {},
): number[] {
	const panes = needs.length;
	if (panes === 0) return [];
	if (panes === 1) return [1];
	const wants = needs.map((n) => (n > 0 ? n : 0));
	if (wants.every((w) => w === 0)) return wants.map(() => 1 / panes);

	// Bounds that cannot all hold at once — three panes each wanting a third
	// minimum — would make a valid division impossible, so the bounds yield to
	// an equal share rather than the other way round.
	const equal = 1 / panes;
	const lo = Math.min(min, equal);
	const hi = Math.max(max, equal);

	const shares = wants.map(() => 0);
	const fixed = wants.map(() => false);
	// Clamped proportional allocation: fix whatever falls outside its bound, hand
	// the rest of the height to the panes still asking, and repeat. At most one
	// pane is fixed per round, so this cannot run away.
	for (let round = 0; round <= panes; round++) {
		let fixedSum = 0;
		let openWant = 0;
		for (let i = 0; i < panes; i++) {
			if (fixed[i]) fixedSum += shares[i];
			else openWant += wants[i];
		}
		const remaining = 1 - fixedSum;
		if (openWant <= 0) {
			// Nothing left to ask for: split what remains evenly.
			let open = 0;
			for (let i = 0; i < panes; i++) if (!fixed[i]) open += 1;
			if (open === 0) break;
			for (let i = 0; i < panes; i++)
				if (!fixed[i]) shares[i] = remaining / open;
			break;
		}
		let clamped = false;
		for (let i = 0; i < panes; i++) {
			if (fixed[i]) continue;
			const ideal = (wants[i] / openWant) * remaining;
			if (ideal < lo) {
				shares[i] = lo;
				fixed[i] = true;
				clamped = true;
			} else if (ideal > hi) {
				shares[i] = hi;
				fixed[i] = true;
				clamped = true;
			} else {
				shares[i] = ideal;
			}
		}
		if (!clamped) break;
	}

	// Clamping can leave the stack short: panes pinned to a bound may add up to
	// less than the whole. The deficit is shared out again, in proportion to
	// what the panes that still have room asked for, so two panes wanting the
	// same end up with the same and the stack is exactly full — a gap below the
	// last pane would look like a rendering fault.
	for (let guard = 0; guard < panes * 4; guard++) {
		const deficit = 1 - shares.reduce((a, b) => a + b, 0);
		if (deficit <= 1e-9) break;
		const open = shares
			.map((_, i) => i)
			.filter((i) => shares[i] < hi - 1e-9);
		if (open.length === 0) break;
		const wanted = open.reduce((a, i) => a + wants[i], 0);
		for (const i of open) {
			const add =
				wanted > 0
					? deficit * (wants[i] / wanted)
					: deficit / open.length;
			shares[i] = Math.min(shares[i] + add, hi);
		}
	}
	return shares;
}
