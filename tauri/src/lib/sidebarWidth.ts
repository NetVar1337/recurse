/**
 * How wide the left sidebar may be.
 *
 * Kept as arithmetic with its bounds in one place because the bounds are the
 * part worth arguing about: too narrow and a section's name is truncated, too
 * wide and the code view it is read alongside has nowhere to go. Both ends are
 * stated as what they cost something else, not as magic numbers.
 */

/** Narrower than this and a section name is cut off, so it is not offered. */
export const SIDEBAR_MIN = 220;

/** Wider than this and the code view is the thing being squeezed instead. */
export const SIDEBAR_MAX = 640;

/** What the sidebar is before the window has been measured. */
export const SIDEBAR_DEFAULT = 260;

/**
 * How much room the code view keeps, however wide the sidebar is dragged.
 *
 * The sidebar exists to be read alongside code, so a width that leaves nothing
 * to read is a width the analyst did not ask for however far they dragged.
 */
const CODE_MIN = 480;

/**
 * The sidebar's width for a window `windowWidth` across.
 *
 * A share of the window, bounded at both ends: it never goes below the point
 * where names are cut off, never above the cap, and never far enough to take
 * the code view's floor. Monotone in the window width, so widening the window
 * always widens the sidebar and never narrows it.
 *
 * ```
 * sidebarWidth(600)   // => 220 — the floor; the rest would be too little to read
 * sidebarWidth(1200)  // => 400 — a third
 * sidebarWidth(1920)  // => 640 — the cap
 * ```
 *
 * @param windowWidth - The window's width in pixels.
 * @returns A width within the bounds.
 */
export function sidebarWidth(windowWidth: number): number {
	if (!Number.isFinite(windowWidth) || windowWidth <= 0) {
		return SIDEBAR_DEFAULT;
	}
	// The sidebar may not take the code view below its floor, so on a narrow
	// window the ceiling is the binding bound rather than the cap.
	const ceiling = Math.max(SIDEBAR_MIN, windowWidth - CODE_MIN);
	const share = windowWidth / 3;
	return Math.min(
		Math.max(share, Math.min(SIDEBAR_MIN, ceiling)),
		Math.min(SIDEBAR_MAX, ceiling),
	);
}
