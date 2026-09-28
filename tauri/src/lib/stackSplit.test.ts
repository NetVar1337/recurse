import { describe, expect, it } from "vitest";

import { distribute, neighbourOf, MAX_SHARE, MIN_SHARE } from "./stackSplit";

/** A share list summing to 1, to within float noise. */
function sumsToOne(shares: number[]): boolean {
	return Math.abs(shares.reduce((a, b) => a + b, 0) - 1) < 1e-6;
}

describe("neighbourOf", () => {
	it("trades height between the two panes a divider separates", () => {
		expect(neighbourOf(0, 2)).toBe(1);
	});

	it("uses the pane on the divider's own side, not the first in the stack", () => {
		// The divider after the middle pane is between the middle and the last, so
		// dragging it must move the middle against the last. Against the first, the
		// middle would appear to move and the divider would follow it.
		expect(neighbourOf(0, 3)).toBe(1);
		expect(neighbourOf(1, 3)).toBe(2);
	});

	it("falls back to the left for a divider with nothing to its right", () => {
		expect(neighbourOf(2, 3)).toBe(1);
		expect(neighbourOf(0, 1)).toBe(-1);
	});
});

describe("distribute", () => {
	it("gives equal shares to panes that want the same", () => {
		const shares = distribute([100, 100, 100]);
		expect(shares[0]).toBeCloseTo(1 / 3, 6);
		expect(shares[1]).toBeCloseTo(1 / 3, 6);
		expect(shares[2]).toBeCloseTo(1 / 3, 6);
	});

	it("gives a short pane what it needs and the rest to the long one", () => {
		// A boundary list of three rows must not be pushed off screen by a
		// section list of nineteen: the short pane keeps its share and the long
		// one takes the rest, in proportion to what each asked for.
		const shares = distribute([300, 100, 100]);
		expect(shares[0]).toBeCloseTo(0.6, 6);
		expect(shares[1]).toBeCloseTo(0.2, 6);
		expect(shares[2]).toBeCloseTo(0.2, 6);
	});

	it("stops a long pane at the cap and hands the rest on", () => {
		// A section list that wants four times the room cannot take it all, or
		// the panes below would be a strip. The excess goes to those still
		// asking rather than being thrown away.
		const shares = distribute([400, 100, 100]);
		expect(shares[0]).toBeCloseTo(MAX_SHARE, 6);
		expect(shares[1]).toBeCloseTo(0.2, 6);
		expect(shares[2]).toBeCloseTo(0.2, 6);
	});

	it("always fills the height it was given", () => {
		for (const needs of [
			[1, 1],
			[5000, 3],
			[0, 0],
			[900, 800, 700],
			[1, 1, 1, 1, 1, 1],
		]) {
			expect(sumsToOne(distribute(needs))).toBe(true);
		}
	});

	it("caps one pane so the others keep usable room", () => {
		const shares = distribute([10_000, 100, 100]);
		expect(shares[0]).toBeLessThanOrEqual(MAX_SHARE + 1e-6);
		expect(shares[1]).toBeGreaterThanOrEqual(MIN_SHARE - 1e-6);
		expect(sumsToOne(shares)).toBe(true);
		// The excess went to the panes that were still asking.
		expect(shares[1]).toBeGreaterThan(100 / 10_200);
	});

	it("never lets a pane vanish, however small its content", () => {
		const shares = distribute([1000, 1, 1]);
		expect(shares.every((s) => s > 0)).toBe(true);
		expect(shares[1]).toBeCloseTo(shares[2], 6);
		expect(sumsToOne(shares)).toBe(true);
	});

	it("divides evenly when there is nothing to measure", () => {
		const shares = distribute([0, 0, 0]);
		expect(shares[0]).toBeCloseTo(1 / 3, 6);
		// A pane asking for zero is a hidden one, not a request for no height;
		// treating it as zero would let the others take the lot and leave a gap.
		expect(sumsToOne(distribute([0, 100]))).toBe(true);
	});

	it("honours bounds that a single pane cannot take alone", () => {
		// Three panes cannot each hold a third minimum, so the bound yields to
		// the equal share rather than making a valid division impossible.
		const shares = distribute([100, 100, 100], { min: 0.5, max: 0.9 });
		expect(sumsToOne(shares)).toBe(true);
		expect(shares.every((s) => s > 0)).toBe(true);
	});

	it("handles no panes, and one pane", () => {
		expect(distribute([])).toEqual([]);
		expect(distribute([42])).toEqual([1]);
	});
});
