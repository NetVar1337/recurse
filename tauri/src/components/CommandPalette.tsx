import { useEffect, useMemo, useRef, useState } from "react";

import { api, pickBinary } from "@/api";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";
import { useDebugStore } from "@/store/debugStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import type { CenterTab } from "@/types";

interface Command {
	id: string;
	title: string;
	hint?: string;
	run: () => void;
}

const TAB_LABEL: Record<CenterTab, string> = {
	recon: "Recon",
	debug: "Debug",
	disasm: "Disassembly",
	strings: "Strings",
	imports: "Imports",
	console: "Console",
};

/** Every command the palette can run, resolved from the stores at open time. */
function buildCommands(): Command[] {
	const ui = useUiStore.getState();
	const bin = useBinaryStore.getState();
	const dbg = useDebugStore.getState();
	const settings = useSettingsStore.getState();

	const cmds: Command[] = [
		{
			id: "open",
			title: "Open binary…",
			hint: "Ctrl+O",
			run: () => {
				void pickBinary().then((p) => {
					if (p) void bin.openBinary(p);
				});
			},
		},
	];
	if (bin.binary) {
		cmds.push({
			id: "close",
			title: "Close binary",
			run: () => void bin.closeBinary(),
		});
	}
	for (const tab of Object.keys(TAB_LABEL) as CenterTab[]) {
		cmds.push({
			id: `tab-${tab}`,
			title: `Go to ${TAB_LABEL[tab]}`,
			run: () => ui.setTab(tab),
		});
	}
	cmds.push(
		{
			id: "chat",
			title: "Toggle agent chat",
			hint: "Ctrl+L",
			run: () => ui.toggleChat(),
		},
		{
			id: "engine-native",
			title: "Analysis engine: native (pure Rust)",
			run: () => void settings.setBackend("native"),
		},
		{
			id: "engine-r2",
			title: "Analysis engine: r2",
			run: () => void settings.setBackend("r2"),
		},
	);

	if (dbg.active) {
		cmds.push(
			{
				id: "dbg-run",
				title: "Debug: Run",
				hint: "F9",
				run: () => void dbg.run("continue"),
			},
			{
				id: "dbg-pause",
				title: "Debug: Pause",
				run: () => void dbg.run("interrupt"),
			},
			{
				id: "dbg-into",
				title: "Debug: Step into",
				hint: "F7",
				run: () => void dbg.run("step", { kind: "into" }),
			},
			{
				id: "dbg-over",
				title: "Debug: Step over",
				hint: "F8",
				run: () => void dbg.run("step", { kind: "over" }),
			},
			{
				id: "dbg-out",
				title: "Debug: Step out",
				run: () => void dbg.run("step", { kind: "out" }),
			},
			{
				id: "dbg-detach",
				title: "Debug: Detach",
				run: () => void dbg.run("detach"),
			},
		);
	}

	return cmds;
}

/** Resolve a typed address/symbol and select the function containing it. */
function gotoQuery(query: string): void {
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

/**
 * Ctrl+K command palette: open a binary, jump to a tab, drive the debugger, or
 * type an address/symbol to go there. The one place that reaches every action.
 */
export function CommandPalette() {
	const [open, setOpen] = useState(false);
	const [query, setQuery] = useState("");
	const [active, setActive] = useState(0);
	const listRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
				e.preventDefault();
				setOpen((o) => !o);
				setQuery("");
				setActive(0);
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, []);

	const commands = useMemo(() => (open ? buildCommands() : []), [open]);
	const filtered = useMemo(() => {
		const q = query.trim().toLowerCase();
		if (!q) return commands;
		return commands.filter((c) => c.title.toLowerCase().includes(q));
	}, [commands, query]);

	const close = () => setOpen(false);
	const run = (c: Command) => {
		close();
		c.run();
	};

	const onKeyDown = (e: React.KeyboardEvent) => {
		if (e.key === "Escape") {
			e.preventDefault();
			close();
		} else if (e.key === "ArrowDown") {
			e.preventDefault();
			setActive((a) => Math.min(a + 1, filtered.length - 1));
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			setActive((a) => Math.max(a - 1, 0));
		} else if (e.key === "Enter") {
			e.preventDefault();
			const c = filtered[active];
			if (c) run(c);
			else if (query.trim()) {
				close();
				gotoQuery(query);
			}
		}
	};

	if (!open) return null;
	return (
		<div
			className="fixed inset-0 z-50 flex justify-center bg-black/40 pt-[12vh]"
			onClick={close}
		>
			<div
				className="bg-popover border-border flex max-h-[60vh] w-[min(560px,92vw)] flex-col overflow-hidden rounded-lg border shadow-2xl"
				onClick={(e) => e.stopPropagation()}
			>
				<input
					autoFocus
					value={query}
					onChange={(e) => {
						setQuery(e.target.value);
						setActive(0);
					}}
					onKeyDown={onKeyDown}
					placeholder="Type a command, address, or symbol…"
					className="placeholder:text-muted-foreground/60 w-full bg-transparent px-3.5 py-3 text-sm outline-none"
				/>
				<div
					ref={listRef}
					className="border-border scroll-host min-h-0 overflow-auto border-t p-1"
				>
					{filtered.map((c, i) => (
						<button
							key={c.id}
							onMouseEnter={() => setActive(i)}
							onClick={() => run(c)}
							className={cn(
								chrome.row,
								"w-full rounded text-left text-sm",
								i === active
									? chrome.selected
									: "hover:bg-accent",
							)}
						>
							<span className="truncate">{c.title}</span>
							{c.hint && (
								<span className="text-kbd text-2xs ml-auto">
									{c.hint}
								</span>
							)}
						</button>
					))}
					{filtered.length === 0 && query.trim() && (
						<button
							onClick={() => {
								close();
								gotoQuery(query);
							}}
							className={cn(
								chrome.row,
								chrome.selected,
								"w-full rounded text-left text-sm",
							)}
						>
							Go to “{query.trim()}”
						</button>
					)}
				</div>
			</div>
		</div>
	);
}
