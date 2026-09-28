/**
 * How wide the chat column starts, and how far it may go.
 *
 * The sidebar takes a share of the window because it is read alongside code and
 * has rows to fit. The chat is a companion panel with a fixed shape — a
 * transcript and a composer — so it starts at a size that holds a readable
 * exchange and is bounded by what the code view still needs, not by a share of
 * anything.
 */

/** Narrower than this and a message wraps to one word per line. */
export const CHAT_MIN = 280;

/** Wider than this and the chat has become the window's main panel. */
export const CHAT_MAX = 720;

/** The width it opens at, before anything is remembered. */
export const CHAT_DEFAULT = 340;

/**
 * The chat's opening width for a window `windowWidth` across.
 *
 * ```
 * chatWidth(1920)  // => 340
 * chatWidth(700)   // => 220 — the window cannot afford more beside a sidebar
 * ```
 *
 * @param windowWidth - The window's width in pixels.
 * @returns A width for the chat to open at.
 */
export function chatWidth(windowWidth: number): number {
	if (!Number.isFinite(windowWidth) || windowWidth <= 0) return CHAT_DEFAULT;
	// Whatever the sidebar is likely to take, plus this, plus something to read
	// code in: on a narrow window the chat yields rather than the code view.
	const available = windowWidth - 260 - 480;
	return Math.max(220, Math.min(CHAT_DEFAULT, available));
}
