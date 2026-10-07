/** Class names backed by tokens in `src/chrome.css`. */
export const chrome = {
	bar: "ui-bar",
	sep: "ui-sep",
	seg: "ui-seg",
	press: "ui-press",
	selected: "ui-selected",
	/** Draggable value input. */
	slider: "ui-slider",
	/** Debugger: the code leading into the program counter. */
	past: "ui-past",
	/** Debugger: a register that moved at the last stop. */
	changed: "ui-changed",
	/** Debugger: a conditional branch the cursor is about to take. */
	taken: "ui-taken",
	/** Debugger: a conditional branch it is about to skip. */
	fall: "ui-fall",
	/** Debugger: the code a taken branch is about to land in. */
	peek: "ui-peek",
	composer: "ui-composer",
	/** The window's own minimise, maximise and close, at the end of the header. */
	windowControls: "ui-window-controls",
	windowButton: "ui-window-button",
	/** The close button, which is the one that reads as a way out. */
	windowClose: "ui-window-close",
	/** The row of menus across the top of the window. */
	menuBar: "ui-menu-bar",
	/** One menu's name in that row, or the way out of the project. */
	menuItem: "ui-menu-item",
	/** A rule between the bar's way back and its menus. */
	menuDivider: "ui-menu-divider",
	menuLabel: "ui-menu-label",
	kbd: "ui-kbd",
	panelTitle: "ui-panel-title",
	/** One row in any data list. */
	row: "data-row",
	/**
	 * A row too wide for one line: the name on top, its metadata beneath, which
	 * is the only way a narrow pane can show both without truncating either.
	 */
	row2: "data-row-2",
	/**
	 * A draggable divider between two panels. The element is the grab area; the
	 * line drawn inside it is one pixel, however wide the grab is.
	 */
	colDivider: "ui-col-divider",
	rowDivider: "ui-row-divider",
	/** Uppercase micro-heading for pane titles. */
	label: "label",
	/** Tabular numerals for columns of numbers. */
	nums: "nums",
} as const;
