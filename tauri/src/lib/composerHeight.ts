/**
 * How tall the composer's text box should be, for the text in it.
 *
 * The composer grows as a message is written and stops at a ceiling, then
 * scrolls. Both halves of that are decisions rather than CSS defaults, so they
 * are arithmetic here where they can be tested: a box that never grows wastes
 * the transcript, and a box with no ceiling eventually takes the window.
 *
 * The line height is *measured*, never assumed. The app's type scale is dense —
 * 11px text on a 1.45 line height is 15.95px, not the 20px a round number
 * suggests — and a hard-coded line height is 4px wrong on every line, which is
 * a box 20% too tall for the text it is holding.
 */

/** How many lines the box will show before it stops growing. */
export const COMPOSER_MAX_LINES = 5;

/**
 * The line height used when the element's own cannot be read.
 *
 * A text box that has not been laid out reports "normal" for `line-height`,
 * which is not a number at all; 16px is the browser's usual rendering of an
 * 11–12px font, and it keeps the box one line tall rather than collapsing it.
 */
export const COMPOSER_FALLBACK_LINE = 16;

/**
 * The line height the app's composer renders at, used only to derive the
 * ceiling. The box measures its own at runtime; this is what keeps the ceiling
 * and the line count from drifting into two different answers.
 */
const COMPOSER_RENDERED_LINE = 15.95;

/**
 * The box's vertical padding, in pixels: 4px top and bottom from `py-1`.
 *
 * Counted separately because `scrollHeight` includes padding while the line
 * count does not. Adding it once to the total is right; adding it per line
 * makes a one-line box two lines tall.
 */
const COMPOSER_PADDING = 8;

/** The smallest the box is ever allowed to be: one line, plus its padding. */
export const COMPOSER_MIN_HEIGHT = COMPOSER_RENDERED_LINE + COMPOSER_PADDING;

/**
 * The tallest the box is ever allowed to be, in pixels.
 *
 * Exactly the height the line count produces, not a round number near it. A
 * ceiling rounded up leaves a fraction of a pixel the box can grow into and
 * then be clipped by the stylesheet's `max-height`; rounded down clips the
 * fifth line. `chrome.css` declares the same value, and a test reads it back
 * out of the stylesheet so the two cannot part company.
 */
export const COMPOSER_MAX_HEIGHT =
	COMPOSER_RENDERED_LINE * COMPOSER_MAX_LINES + COMPOSER_PADDING;

/**
 * The composer's height for a given line count.
 *
 * Clamped at both ends. A non-finite count is treated as empty rather than
 * propagating `NaN` into a style, which would collapse the box to nothing.
 *
 * A count past the ceiling gets exactly the ceiling, never more: the box
 * scrolls instead, because a composer that grows without limit eventually
 * leaves no room for the transcript it is talking about.
 *
 * @param lineHeight - The box's own computed line height in pixels. Read from
 *   the element rather than assumed, because a hard-coded value is 4px wrong at
 *   this type size and being wrong makes every line 20% too tall.
 * @param lines - How many lines of text the box is holding.
 * @returns A height in pixels: the lines, plus the box's padding once.
 *
 * @example
 * composerHeight(15.95, 1)   // => 24
 * composerHeight(15.95, 3)   // => 56
 * composerHeight(15.95, 5)   // => 88 — the ceiling
 * composerHeight(15.95, 50)  // => 88 — it scrolls instead
 * composerHeight(15.95, NaN) // => 24
 * composerHeight(0, 3)       // => 56 — an unreadable line height still grows
 */
export function composerHeight(lineHeight: number, lines: number): number {
	// An unreadable line height must not produce an unreadable height, and 0
	// would collapse the box to nothing, so both fall back to a whole line.
	const lh =
		Number.isFinite(lineHeight) && lineHeight > 0
			? lineHeight
			: COMPOSER_FALLBACK_LINE;
	const n = Number.isFinite(lines) && lines > 0 ? Math.round(lines) : 1;
	return Math.min(
		COMPOSER_MAX_HEIGHT,
		Math.max(COMPOSER_MIN_HEIGHT, n * lh + COMPOSER_PADDING),
	);
}

/**
 * How many lines of text a box is holding, from the height of its content.
 *
 * Divides and rounds, so a box whose content is 55.85px across three 15.95px
 * lines counts as three lines and not three-and-a-bit — which would have set
 * the height to four lines and left a gap under the last one.
 *
 * The padding comes off first, because `scrollHeight` includes it and a line
 * count that included it would report a box holding one line as holding one
 * and a half.
 *
 * @param scrollHeight - The box's `scrollHeight` read with its height cleared,
 *   so this is the content's height and not the box's.
 * @param lineHeight - The box's computed line height, in pixels.
 * @returns The line count, at least one.
 *
 * @example
 * composerLines(3 * 15.95 + 8, 15.95) // => 3
 * composerLines(11, 15.95)            // => 1
 */
export function composerLines(
	scrollHeight: number,
	lineHeight: number,
): number {
	const lh =
		Number.isFinite(lineHeight) && lineHeight > 0
			? lineHeight
			: COMPOSER_FALLBACK_LINE;
	if (!Number.isFinite(scrollHeight) || scrollHeight <= 0) return 1;
	return Math.max(1, Math.round((scrollHeight - COMPOSER_PADDING) / lh));
}
