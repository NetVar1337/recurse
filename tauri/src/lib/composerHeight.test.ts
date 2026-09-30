import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
	COMPOSER_FALLBACK_LINE,
	COMPOSER_MAX_HEIGHT,
	COMPOSER_MAX_LINES,
	COMPOSER_MIN_HEIGHT,
	composerHeight,
	composerLines,
} from "./composerHeight";

const css = readFileSync(new URL("../chrome.css", import.meta.url), "utf8");

/** The line height the app's composer actually renders at. */
const LH = 15.95;

describe("composerHeight", () => {
	it("shows one line when empty", () => {
		expect(composerHeight(LH, 1)).toBeGreaterThanOrEqual(
			COMPOSER_MIN_HEIGHT,
		);
	});

	it("grows with the text, a line at a time", () => {
		// Measured against the real line height rather than a round number, which
		// is the whole point: 11px on 1.45 is 15.95, and 20 would be a quarter
		// too tall on every line. Padding is added once, not per line, or a
		// one-line box comes out two lines tall.
		expect(composerHeight(LH, 3)).toBeCloseTo(3 * LH + 8, 5);
		expect(composerHeight(LH, 4)).toBeCloseTo(4 * LH + 8, 5);
	});

	it("stops at the ceiling however much is typed", () => {
		// A composer with no ceiling eventually takes the window, and the
		// transcript is the thing it is talking about.
		expect(composerHeight(LH, 6)).toBe(COMPOSER_MAX_HEIGHT);
		expect(composerHeight(LH, 50)).toBe(COMPOSER_MAX_HEIGHT);
		expect(composerHeight(LH, 10_000)).toBe(COMPOSER_MAX_HEIGHT);
	});

	it("never goes below one line", () => {
		expect(composerHeight(LH, 0)).toBeGreaterThanOrEqual(
			COMPOSER_MIN_HEIGHT,
		);
		expect(composerHeight(LH, -5)).toBeGreaterThanOrEqual(
			COMPOSER_MIN_HEIGHT,
		);
	});

	it("treats an unusable line count as empty rather than as NaN", () => {
		// NaN into a style collapses the box to nothing, which is worse than
		// showing one line.
		for (const bad of [NaN, Infinity, -Infinity]) {
			expect(composerHeight(LH, bad)).toBeGreaterThanOrEqual(
				COMPOSER_MIN_HEIGHT,
			);
		}
	});

	it("still grows when the line height cannot be read", () => {
		// A text box that has not been laid out reports line-height: normal,
		// which parses as NaN. Falling back keeps the box usable rather than
		// freezing it at one line.
		expect(composerHeight(NaN, 3)).toBeCloseTo(
			3 * COMPOSER_FALLBACK_LINE + 8,
			5,
		);
		expect(composerHeight(0, 3)).toBeCloseTo(
			3 * COMPOSER_FALLBACK_LINE + 8,
			5,
		);
		expect(composerHeight(NaN, 3)).toBeLessThanOrEqual(COMPOSER_MAX_HEIGHT);
	});

	it("rounds a fractional line count rather than truncating it", () => {
		// Truncating would set two lines for three lines of text and hide the
		// third behind the ceiling.
		expect(composerHeight(LH, 2.4)).toBe(composerHeight(LH, 2));
		expect(composerHeight(LH, 2.6)).toBe(composerHeight(LH, 3));
	});
});

describe("composerLines", () => {
	it("counts the lines the content is actually tall enough for", () => {
		// `scrollHeight` includes the box's padding, so a real three-line box
		// measures three lines plus 8px. A count that forgot to take the padding
		// off would call it three and a half and round to four.
		expect(composerLines(1 * LH + 8, LH)).toBe(1);
		expect(composerLines(3 * LH + 8, LH)).toBe(3);
		expect(composerLines(5 * LH + 8, LH)).toBe(5);
	});

	it("rounds a content height that is not a whole number of lines", () => {
		// Two-and-a-bit lines is three lines of text, and rounding down here
		// would set the box two lines tall and clip the third.
		expect(composerLines(3 * LH + 8 - 1, LH)).toBe(3);
		expect(composerLines(3 * LH + 8 + 1, LH)).toBe(3);
	});

	it("reports one line for a box holding only its padding", () => {
		// An empty text box measures its padding and nothing else, which is less
		// than one line; without a floor it would report zero.
		expect(composerLines(8, LH)).toBe(1);
	});

	it("reports one line for an empty or unreadable box", () => {
		expect(composerLines(0, LH)).toBe(1);
		expect(composerLines(NaN, LH)).toBe(1);
		expect(composerLines(-4, LH)).toBe(1);
	});

	it("uses the fallback when the line height cannot be read", () => {
		expect(composerLines(3 * COMPOSER_FALLBACK_LINE + 8, NaN)).toBe(3);
	});
});

describe("the ceiling", () => {
	it("is the same height whether reached at 5 lines or 500", () => {
		// The two must be equal or the box jumps as it crosses the ceiling.
		expect(composerHeight(LH, COMPOSER_MAX_LINES)).toBe(
			composerHeight(LH, 500),
		);
	});

	it("is reachable by the line count the box is given", () => {
		// Guards the constant against a MAX_HEIGHT that no line count can reach,
		// which would make the box scroll from the first line.
		const atCeiling = composerHeight(LH, COMPOSER_MAX_LINES);
		expect(atCeiling).toBe(COMPOSER_MAX_HEIGHT);
		expect(composerHeight(LH, COMPOSER_MAX_LINES + 1)).toBe(
			COMPOSER_MAX_HEIGHT,
		);
	});
});

describe("the stylesheet and the arithmetic agree", () => {
	// The ceiling is enforced twice: by the arithmetic that stops growing and by
	// the `max-height` that stops the element. If they disagree the box either
	// scrolls from the first line or grows past the ceiling with nothing to stop
	// it, and neither failure is visible in a unit test of one side alone.
	/**
	 * The `max-height` declared for the composer's textarea, in pixels.
	 *
	 * @returns The value, or 0 when the rule does not declare one.
	 */
	function cssMaxHeight(): number {
		const rule = css.slice(
			css.indexOf(".ui-composer textarea {"),
			css.indexOf("}", css.indexOf(".ui-composer textarea {")),
		);
		const m = rule.match(/max-height:\s*([\d.]+)px/);
		return m ? parseFloat(m[1]) : 0;
	}

	it("gives the textarea the same ceiling the arithmetic stops at", () => {
		expect(cssMaxHeight()).toBe(COMPOSER_MAX_HEIGHT);
	});

	it("lets the textarea scroll, so the ceiling has something to do", () => {
		// Without `overflow-y: auto` the box would clip the text past the ceiling
		// rather than scrolling it, and the analyst would type into a void.
		const rule = css.slice(
			css.indexOf(".ui-composer textarea {"),
			css.indexOf("}", css.indexOf(".ui-composer textarea {")),
		);
		expect(rule).toContain("overflow-y: auto");
	});

	it("reserves the scrollbar gutter, so crossing the ceiling shifts nothing", () => {
		const rule = css.slice(
			css.indexOf(".ui-composer textarea {"),
			css.indexOf("}", css.indexOf(".ui-composer textarea {")),
		);
		expect(rule).toContain("scrollbar-gutter: stable");
	});
});
