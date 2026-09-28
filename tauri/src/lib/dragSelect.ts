/**
 * Stopping a drag from selecting the text it passes over.
 *
 * Dragging a divider means moving the pointer across the page, and a browser
 * helpfully selects everything in the way: drag a sidebar wider and the section
 * names, the filter text and half a code listing come out blue. The divider owns
 * the pointer for the duration of the drag, so the selection is an accident of
 * the pointer's path rather than anything the analyst asked for.
 *
 * The suppression is a class on the body rather than a style on the divider,
 * because the selection is made in the elements the pointer crosses, not in the
 * divider. It is put on the whole document because a drag that ends off the
 * divider — released over the page, or the element unmounted mid-drag — must not
 * leave the window unselectable.
 */

/** Which way the divider runs, which is which cursor belongs to it. */
export type DragAxis = "col" | "row";

/** The class put on `body` for a drag; the rules live in `chrome.css`. */
export function dragSelectClass(axis: DragAxis): string {
	return axis === "col"
		? "dragging-suppress-select"
		: "dragging-suppress-select-row";
}

/** Suppress text selection, for as long as the drag lasts. */
export function beginDragSuppressSelect(axis: DragAxis = "col"): void {
	// `document` is absent in the node test environment.
	if (typeof document === "undefined") return;
	document.body?.classList.add(dragSelectClass(axis));
}

/** Undo [`beginDragSuppressSelect`]. */
export function endDragSuppressSelect(axis: DragAxis = "col"): void {
	if (typeof document === "undefined") return;
	document.body?.classList.remove(dragSelectClass(axis));
}
