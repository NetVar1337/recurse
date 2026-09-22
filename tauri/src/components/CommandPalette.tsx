import { useEffect, useMemo, useRef, useState } from "react";

import {
	Dialog,
	DialogContent,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";
import { useProjectStore } from "@/store/projectStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import type { CenterTab } from "@/types";

function fmtAddr(a: number): string {
	return `0x${a.toString(16)}`;
}

interface Action {
	id: string;
	label: string;
	hint?: string;
	run: () => void;
}

const TAB_ACTIONS: [CenterTab, string][] = [
	["recon", "Go to Recon"],
	["disasm", "Go to Disassembly"],
	["callgraph", "Go to Call Graph"],
	["strings", "Go to Strings"],
	["imports", "Go to Imports"],
	["findings", "Go to Findings"],
	["hex", "Go to Hex view"],
	["debug", "Go to Debug"],
	["console", "Go to Console"],
];

/**
 * A Ctrl+K / Cmd+K command palette: fuzzy filter over every discovered
 * function (go to + disassemble) and a fixed list of app-wide actions
 * (switch tab, toggle chat, toggle theme, close project). Mounted once at
 * the app root; owns its own open state and global keydown listener.
 */
export function CommandPalette() {
	const [open, setOpen] = useState(false);
	const [query, setQuery] = useState("");
	const [highlight, setHighlight] = useState(0);
	const inputRef = useRef<HTMLInputElement>(null);

	const binary = useBinaryStore((s) => s.binary);
	const funcs = useAnalysisStore((s) => s.funcs);
	const selectFn = useAnalysisStore((s) => s.selectFn);
	const setTab = useUiStore((s) => s.setTab);
	const chatOpen = useUiStore((s) => s.chatOpen);
	const toggleChat = useUiStore((s) => s.toggleChat);
	const closeProject = useProjectStore((s) => s.close);
	const setNewProjectOpen = useUiStore((s) => s.setNewProjectOpen);
	const toggleTheme = useSettingsStore((s) => s.toggleTheme);

	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
				e.preventDefault();
				setOpen((o) => {
					const next = !o;
					if (next) {
						setQuery("");
						setHighlight(0);
					}
					return next;
				});
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, []);

	// Focus the input once the dialog has actually opened — an imperative
	// DOM action, not a state sync, so this is the effect's one job.
	useEffect(() => {
		if (open) {
			const id = setTimeout(() => inputRef.current?.focus(), 0);
			return () => clearTimeout(id);
		}
	}, [open]);

	const actions = useMemo<Action[]>(() => {
		const list: Action[] = [];
		if (binary) {
			for (const [tab, label] of TAB_ACTIONS) {
				list.push({ id: `tab:${tab}`, label, run: () => setTab(tab) });
			}
			list.push({
				id: "toggle-chat",
				label: chatOpen ? "Hide agent chat" : "Show agent chat",
				hint: "Ctrl+L",
				run: () => toggleChat(),
			});
			list.push({
				id: "close-project",
				label: "Close project",
				run: () => void closeProject(),
			});
		} else {
			list.push({
				id: "new-project",
				label: "New project…",
				run: () => setNewProjectOpen(true),
			});
		}
		list.push({
			id: "toggle-theme",
			label: "Toggle light / dark theme",
			run: () => toggleTheme(),
		});
		return list;
	}, [
		binary,
		chatOpen,
		closeProject,
		setNewProjectOpen,
		setTab,
		toggleChat,
		toggleTheme,
	]);

	const q = query.trim().toLowerCase();

	const matchedFunctions = useMemo(() => {
		if (!q || !binary) return [];
		return funcs
			.filter((f) => (f.name ?? "").toLowerCase().includes(q))
			.slice(0, 30);
	}, [funcs, q, binary]);

	const matchedActions = useMemo(
		() =>
			q
				? actions.filter((a) => a.label.toLowerCase().includes(q))
				: actions,
		[actions, q],
	);

	type Entry =
		| { kind: "action"; action: Action }
		| { kind: "function"; fn: (typeof matchedFunctions)[number] };

	const entries: Entry[] = [
		...matchedFunctions.map((fn) => ({ kind: "function" as const, fn })),
		...matchedActions.map((action) => ({
			kind: "action" as const,
			action,
		})),
	];

	const runEntry = (entry: Entry) => {
		if (entry.kind === "action") entry.action.run();
		else selectFn(entry.fn);
		setOpen(false);
	};

	const onKeyDown = (e: React.KeyboardEvent) => {
		if (entries.length === 0) return;
		if (e.key === "ArrowDown") {
			e.preventDefault();
			setHighlight((h) => Math.min(h + 1, entries.length - 1));
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			setHighlight((h) => Math.max(h - 1, 0));
		} else if (e.key === "Enter") {
			e.preventDefault();
			const entry = entries[Math.min(highlight, entries.length - 1)];
			if (entry) runEntry(entry);
		}
	};

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogContent className="max-w-lg gap-0 overflow-hidden p-0">
				<DialogHeader className="border-border border-b px-4 py-3">
					<DialogTitle className="text-sm">
						Go to function or run a command
					</DialogTitle>
				</DialogHeader>
				<div className="p-2">
					<Input
						ref={inputRef}
						value={query}
						onChange={(e) => {
							setQuery(e.target.value);
							setHighlight(0);
						}}
						onKeyDown={onKeyDown}
						placeholder={
							binary
								? "type a function name, or an action…"
								: "type a command…"
						}
					/>
				</div>
				<div className="scroll-host max-h-80 min-h-0 overflow-auto px-1 pb-2">
					{entries.length === 0 && (
						<div className="text-muted-foreground px-3 py-6 text-center text-xs">
							No matches.
						</div>
					)}
					{entries.map((entry, i) => (
						<button
							key={
								entry.kind === "action"
									? entry.action.id
									: `fn-${entry.fn.addr}`
							}
							type="button"
							onClick={() => runEntry(entry)}
							onMouseEnter={() => setHighlight(i)}
							className={cn(
								"flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-xs",
								i === highlight
									? "bg-accent"
									: "hover:bg-accent/50",
							)}
						>
							{entry.kind === "action" ? (
								<>
									<span>{entry.action.label}</span>
									{entry.action.hint && (
										<span className="text-muted-foreground font-mono text-[10px]">
											{entry.action.hint}
										</span>
									)}
								</>
							) : (
								<>
									<span className="min-w-0 flex-1 truncate">
										{entry.fn.name ??
											`sub_${entry.fn.addr.toString(16)}`}
									</span>
									<span className="text-muted-foreground font-mono text-[10px]">
										{fmtAddr(entry.fn.addr)}
									</span>
								</>
							)}
						</button>
					))}
				</div>
			</DialogContent>
		</Dialog>
	);
}
