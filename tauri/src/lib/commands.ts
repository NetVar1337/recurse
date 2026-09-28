import { api, pickBinary } from "@/api";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";
import { useDebugStore } from "@/store/debugStore";
import { useProjectStore } from "@/store/projectStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import type { CenterTab, Function } from "@/types";

/** One thing the app can be asked to do, wherever it is asked from. */
export interface Command {
	id: string;
	title: string;
	/** The keyboard shortcut to show beside it, when there is one. */
	hint?: string;
	run: () => void;
	/**
	 * Set for a command that shows a state rather than doing a thing, so the menu
	 * can tick the one that is in force.
	 */
	checked?: boolean;
	/** Which menu in the top bar this belongs under. */
	menu: MenuName;
	/** The heading it sits under inside that menu. */
	section: string;
}

/**
 * The menus, in the order a bar shows them.
 *
 * The names are the ones an editor of this kind has trained everyone to expect,
 * so a menu called `View` is the one holding the switches that change what you
 * see. A menu with no commands in it is not rendered at all: a header that opens
 * onto an empty panel is worse than no header, because it says there is nothing
 * here and is right.
 */
export const MENU_ORDER = ["File", "View", "Go", "Run"] as const;

/** One of the menus in `MENU_ORDER`. */
export type MenuName = (typeof MENU_ORDER)[number];

/** Every centre tab, by the name the palette and the Go menu both call it. */
export const TAB_LABEL: Record<CenterTab, string> = {
	recon: "Recon",
	disasm: "Disassembly",
	callgraph: "Call Graph",
	strings: "Strings",
	imports: "Imports",
	findings: "Findings",
	hex: "Hex view",
	debug: "Debug",
	console: "Console",
};

/**
 * Every command the app offers, resolved from the stores at the moment it is
 * asked for.
 *
 * Both places that offer commands call this — the palette and the menu bar — so
 * an action cannot exist in one and be missing from the other. Nothing here is
 * memoised because the answer depends on what is open: a command that closes the
 * project is not offered before there is one, and the debugger's step commands
 * are not offered before a session is running.
 *
 * @returns The commands, in the order they were declared.
 *
 * @example
 * buildCommands().every((c) => MENU_ORDER.includes(c.menu)) // => true
 */
export function buildCommands(): Command[] {
	const ui = useUiStore.getState();
	const bin = useBinaryStore.getState();
	const dbg = useDebugStore.getState();
	const settings = useSettingsStore.getState();

	const cmds: Command[] = [
		{
			id: "open",
			title: "Open binary…",
			hint: "Ctrl+O",
			menu: "File",
			section: "Binary",
			run: () => {
				void pickBinary().then((p) => {
					if (p) void bin.openBinary(p);
				});
			},
		},
		{
			id: "model-picker",
			title: "Switch model / provider…",
			menu: "File",
			section: "Settings",
			run: () => ui.setModelPickerOpen(true),
		},
		{
			id: "debugger-settings",
			title: "Debugger settings…",
			menu: "File",
			section: "Settings",
			// Opened on the next tick, not inline: a menu restores focus to its
			// trigger as it closes, which would immediately yank it back out of the
			// dialog that just opened.
			run: () =>
				setTimeout(
					() => useUiStore.getState().setDebuggerSettingsOpen(true),
					0,
				),
		},
	];
	if (!bin.binary) {
		cmds.push({
			id: "new-project",
			title: "New project…",
			menu: "File",
			section: "Binary",
			run: () => ui.setNewProjectOpen(true),
		});
	}
	if (bin.binary) {
		cmds.push({
			id: "close",
			title: "Close project",
			menu: "File",
			section: "Binary",
			run: () => void useProjectStore.getState().close(),
		});
		for (const tab of Object.keys(TAB_LABEL) as CenterTab[]) {
			cmds.push({
				id: `tab-${tab}`,
				title: `Go to ${TAB_LABEL[tab]}`,
				menu: "Go",
				section: "Panels",
				run: () => ui.setTab(tab),
			});
		}
		cmds.push({
			id: "chat",
			title: "Toggle agent chat",
			hint: "Ctrl+L",
			menu: "View",
			section: "Appearance",
			run: () => ui.toggleChat(),
		});
	}
	cmds.push(
		{
			id: "toggle-theme",
			title: "Toggle light / dark theme",
			menu: "View",
			section: "Appearance",
			run: () => settings.toggleTheme(),
		},
		{
			id: "zoom-in",
			title: "Zoom in",
			hint: "Ctrl +",
			menu: "View",
			section: "Zoom",
			run: () => void settings.zoomIn(),
		},
		{
			id: "zoom-out",
			title: "Zoom out",
			hint: "Ctrl −",
			menu: "View",
			section: "Zoom",
			run: () => void settings.zoomOut(),
		},
		{
			id: "zoom-reset",
			title: "Reset zoom",
			hint: "Ctrl 0",
			menu: "View",
			section: "Zoom",
			run: () => void settings.resetZoom(),
		},
	);

	// The engine in force is ticked rather than listed twice: a reader asking
	// "which engine is this" should be able to see the answer without opening a
	// menu and inferring it from which row is highlighted.
	for (const [backend, title] of [
		["native", "Native (pure Rust)"],
		["r2", "radare2"],
		["ida", "IDA Pro (Hex-Rays)"],
	] as const) {
		cmds.push({
			id: `engine-${backend}`,
			title: `Analysis engine: ${title}`,
			menu: "View",
			section: "Analysis engine",
			checked: settings.backend === backend,
			run: () => void settings.setBackend(backend),
		});
	}

	if (dbg.active) {
		cmds.push(
			{
				id: "dbg-run",
				title: "Debug: Run",
				hint: "F9",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("continue"),
			},
			{
				id: "dbg-pause",
				title: "Debug: Pause",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("interrupt"),
			},
			{
				id: "dbg-into",
				title: "Debug: Step into",
				hint: "F7",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("step", { kind: "into" }),
			},
			{
				id: "dbg-over",
				title: "Debug: Step over",
				hint: "F8",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("step", { kind: "over" }),
			},
			{
				id: "dbg-out",
				title: "Debug: Step out",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("step", { kind: "out" }),
			},
			{
				id: "dbg-detach",
				title: "Debug: Detach",
				menu: "Run",
				section: "Debug",
				run: () => void dbg.run("detach"),
			},
		);
	}

	return cmds;
}

/**
 * Resolve a typed address or symbol and select the function containing it.
 *
 * ```
 * gotoQuery("0x1000")  // asks the engine which function holds that address
 * ```
 *
 * @param query - What was typed: an address, a number, or part of a name.
 */
export function gotoQuery(query: string): void {
	const q = query.trim();
	if (!q) return;
	const addr = /^0x[0-9a-f]+$/i.test(q)
		? Number.parseInt(q.slice(2), 16)
		: /^\d+$/.test(q)
			? Number.parseInt(q, 10)
			: null;
	const analysis = useAnalysisStore.getState();
	if (addr != null) {
		api.functionAt(addr)
			.then((f) => {
				if (f) analysis.selectFn(f);
				else useUiStore.getState().setTab("disasm");
			})
			.catch(() => {});
		return;
	}
	// A symbol: the analysis engine resolves names through the same store path
	// the agent uses, so a function whose name matches is enough.
	const match = analysis.funcs.find(
		(f) =>
			(f.name ?? "").toLowerCase() === q.toLowerCase() ||
			(f.name ?? "").toLowerCase().includes(q.toLowerCase()),
	);
	if (match) analysis.selectFn(match);
}

/** What the palette lists: a command, or a function to jump to. */
export type Entry =
	{ kind: "command"; command: Command } | { kind: "function"; fn: Function };
