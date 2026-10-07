import type { DisasmViewOptions } from "@/components/DisasmBytes";
import type { MenuSection } from "@/lib/menuRegistry";

/** The columns and marks the disassembly can be asked to show or hide. */
const DISPLAY_TOGGLES: { key: keyof DisasmViewOptions; label: string }[] = [
	{ key: "showRawBytes", label: "Section bytes (hex)" },
	{ key: "showAscii", label: "ASCII column" },
	{ key: "showAddresses", label: "Virtual addresses" },
	{ key: "showInstructionBytes", label: "Instruction bytes" },
	{ key: "showComments", label: "Comments" },
	{ key: "showFunctionMarkers", label: "Function markers" },
	{ key: "showSectionHeaders", label: "Section / segment metadata" },
	{ key: "wideSpacing", label: "Horizontal whitespace" },
];

/** The disassembly's state and the commands that act on it. */
export interface DisasmMenuState {
	viewMode: "linear" | "graph";
	viewOptions: DisasmViewOptions;
	canDecompile: boolean;
	decompiling: boolean;
	xrefsOpen: boolean;
	toolBusy: boolean;
	asmLoading: boolean;
	hasSelection: boolean;
	onViewModeChange: (mode: "linear" | "graph") => void;
	onOptionChange: (key: keyof DisasmViewOptions, value: boolean) => void;
	onDecompile: () => void;
	onToggleXrefs: () => void;
	onGenerateSignature: () => void;
	onShowSimilar: () => void;
	onIndexBinary: () => void;
	onRefresh: () => void;
}

/**
 * What the disassembly offers its menus.
 *
 * The three groups are the ones a reader of code wants in this order: how the
 * code is drawn, what of it is drawn, and then what to do about the function
 * under the cursor. Anything that cannot run right now says so on the item rather
 * than disappearing, because a command that vanishes between two visits is one
 * nobody waits for.
 *
 * @example
 * disasmMenuSections({ ...state, hasSelection: false }).at(-1)?.items[0].disabled
 * // => true — "Decompile" with nothing selected
 *
 * @param state - The disassembly's state and its commands.
 * @returns The sections, in the order the menu shows them.
 */
export function disasmMenuSections(state: DisasmMenuState): MenuSection[] {
	return [
		{
			label: "Disassembly",
			items: [
				{
					id: "view-linear",
					label: "Linear",
					checked: state.viewMode === "linear",
					run: () => state.onViewModeChange("linear"),
				},
				{
					id: "view-graph",
					label: "Graph",
					checked: state.viewMode === "graph",
					run: () => state.onViewModeChange("graph"),
				},
			],
		},
		{
			label: "Output filters",
			items: DISPLAY_TOGGLES.map(({ key, label }) => ({
				id: `filter-${key}`,
				label,
				checked: state.viewOptions[key],
				run: () => state.onOptionChange(key, !state.viewOptions[key]),
			})),
		},
		{
			label: "Actions",
			items: [
				{
					id: "decompile",
					label: state.decompiling ? "Decompiling…" : "Decompile",
					disabled:
						!state.canDecompile ||
						!state.hasSelection ||
						state.decompiling,
					run: state.onDecompile,
				},
				{
					id: "xrefs",
					label: state.xrefsOpen ? "Hide xrefs" : "Show xrefs",
					disabled: !state.hasSelection,
					run: state.onToggleXrefs,
				},
				{
					id: "signature",
					label: "Generate signature",
					disabled: !state.hasSelection || state.toolBusy,
					run: state.onGenerateSignature,
				},
				{
					id: "similar",
					label: "Find similar",
					disabled: !state.hasSelection || state.toolBusy,
					run: state.onShowSimilar,
				},
				{
					id: "index",
					label: "Index binary",
					disabled: state.toolBusy,
					run: state.onIndexBinary,
				},
				{
					id: "reload",
					label: state.asmLoading ? "Reloading…" : "Reload",
					disabled: state.asmLoading,
					run: state.onRefresh,
				},
			],
		},
	];
}
