import { CHAT_MAX, CHAT_MIN, chatWidth } from "@/lib/chatWidth";
import { SIDEBAR_MAX, SIDEBAR_MIN, sidebarWidth } from "@/lib/sidebarWidth";

/** Which way a column's divider runs, and which edge of it the panel is on. */
export type ColumnSide = "start" | "end";

/** What one resizable column needs to know about itself. */
export interface ColumnSpec {
	/** Stable name, and the half of the CSS variable it writes. */
	key: string;
	/** Which edge of the panel the divider sits on. */
	side: ColumnSide;
	/** Narrower than this and the column's own contents are cut off. */
	min: number;
	/** Wider than this and the panel beside it is the one being squeezed. */
	max: number;
	/** The width to start from, given the window. */
	initial: (windowWidth: number) => number;
	/**
	 * The column on the other side of the centre, whose width this one has to
	 * charge the centre's floor against.
	 */
	sibling?: string;
}

/**
 * Every resizable column, in one place.
 *
 * A column reads its sibling out of this rather than out of a callback into the
 * sibling's React state, which keeps the two from having to know about each
 * other's render order: each measures what the other is actually holding.
 */
export const COLUMNS: Record<string, ColumnSpec> = {
	sidebar: {
		key: "sidebar",
		side: "start",
		sibling: "chat",
		min: SIDEBAR_MIN,
		max: SIDEBAR_MAX,
		initial: sidebarWidth,
	},
	chat: {
		key: "chat",
		side: "end",
		sibling: "sidebar",
		min: CHAT_MIN,
		max: CHAT_MAX,
		initial: chatWidth,
	},
};

/**
 * The CSS variable a column's width is written to, and read back from.
 *
 * @param key - The column's name.
 * @returns A custom property name.
 */
export function columnVariable(key: string): string {
	return `--recurse-${key}`;
}

/**
 * What a column is currently holding, read from the grid.
 *
 * The grid is the shared object between the columns: a drag writes the width
 * there as a CSS variable, so the sibling's width is one property read away and
 * needs no coordination between the two components. Before a column has ever
 * been sized — on the first paint, the sidebar runs before the chat is laid out
 * — it reports the width it would open at, which is a better guess than zero.
 *
 * ```
 * readColumn(null, "chat", 1920)  // => 340 — nothing has been sized yet
 * ```
 *
 * @param grid - The grid holding the columns, or null before it is mounted.
 * @param key - The column to measure.
 * @param windowWidth - The window's width, for the unmeasured case.
 * @returns The width in force, in pixels.
 */
export function readColumn(
	grid: HTMLDivElement | null,
	key: string,
	windowWidth: number,
): number {
	const written = Number.parseFloat(
		grid?.style.getPropertyValue(columnVariable(key)) ?? "",
	);
	if (Number.isFinite(written) && written > 0) return written;
	return COLUMNS[key]?.initial(windowWidth) ?? 0;
}

/**
 * The width of one resizable column, within the bounds the window allows.
 *
 * Both edges of the range are stated as what they cost something else, because
 * that is the only form in which they are arguable: a column has to stay wide
 * enough for its own contents, and it may not take the space the panel it is read
 * alongside needs to be readable at all.
 */

/** How much room the centre of the window keeps, however wide a column is. */
export const CENTRE_MIN = 480;

/** A step of a pixel, and a coarse one for a shift-drag. */
export const DRAG_STEP = 8;
export const DRAG_STEP_COARSE = 40;

/**
 * `next`, brought inside what this window can afford.
 *
 * The centre's floor is the binding bound on a narrow window, which is the point:
 * a remembered 600px sidebar is honoured on a wide window and quietly reduced on
 * a half-screen one, rather than squeezing the disassembly to nothing.
 *
 * `reserved` is what the column *beside* this one is already taking. Two columns
 * that each protect the floor on their own can both be at their maximum and
 * squeeze the centre anyway — 640 + 720 leaves 240px of a 1600px window — so the
 * floor is charged once, against the width the other column is holding.
 *
 * ```
 * fitColumn(900, { min: 220, max: 640, windowWidth: 1200 })               // => 480
 * fitColumn(900, { min: 220, max: 640, windowWidth: 1200, reserved: 340 }) // => 360
 * ```
 *
 * @param next - The width asked for.
 * @param bounds - The column's own limits, the window's width, and the sibling's.
 * @returns A width in pixels.
 */
export function fitColumn(
	next: number,
	{
		min,
		max,
		windowWidth,
		floor = CENTRE_MIN,
		reserved = 0,
	}: {
		min: number;
		max: number;
		windowWidth: number;
		floor?: number;
		reserved?: number;
	},
): number {
	if (!Number.isFinite(next) || !Number.isFinite(windowWidth)) return min;
	const ceiling = Math.max(
		min,
		Math.min(max, windowWidth - floor - reserved),
	);
	return Math.max(min, Math.min(Math.round(next), ceiling));
}
