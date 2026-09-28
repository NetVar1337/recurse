/** Class names backed by tokens in `src/chrome.css`. */
export const chrome = {
	bar: "ui-bar",
	headerActions: "ui-header-actions",
	sep: "ui-sep",
	seg: "ui-seg",
	press: "ui-press",
	selected: "ui-selected",
	/** Draggable value input. */
	slider: "ui-slider",
	/** Debugger: the code leading into the program counter. */
	past: "ui-past",
	/** Debugger: a conditional branch the cursor is about to take. */
	taken: "ui-taken",
	/** Debugger: a conditional branch it is about to skip. */
	fall: "ui-fall",
	/** Debugger: the code a taken branch is about to land in. */
	peek: "ui-peek",
	composer: "ui-composer",
	menuLabel: "ui-menu-label",
	kbd: "ui-kbd",
	panelTitle: "ui-panel-title",
	/** One row in any data list. */
	row: "data-row",
	/** Uppercase micro-heading for pane titles. */
	label: "label",
	/** Tabular numerals for columns of numbers. */
	nums: "nums",
} as const;
