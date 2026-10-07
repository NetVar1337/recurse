import { useEffect, useMemo, useRef, useState } from "react";

import { buildCommands, gotoQuery, type Entry } from "@/lib/commands";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";

/** How many function matches the palette will ever show at once. */
const PALETTE_LIMIT = 30;

/**
 * Format an address the way the palette and its rows both write it.
 *
 * @param a - The address.
 * @returns The address as `0x` plus lowercase hex.
 *
 * @example
 * fmtAddr(4096); // => "0x1000"
 */
function fmtAddr(a: number): string {
	return `0x${a.toString(16)}`;
}

/**
 * Ctrl+K command palette: open a binary, jump to a tab or function, drive the
 * debugger, or type an address/symbol to go there. The one place that reaches
 * every action. Mounted once at the app root; owns its own open state and
 * global keydown listener.
 */
export function CommandPalette() {
	const [open, setOpen] = useState(false);
	const [query, setQuery] = useState("");
	const [active, setActive] = useState(0);
	const listRef = useRef<HTMLDivElement>(null);

	const binary = useBinaryStore((s) => s.binary);
	const funcs = useAnalysisStore((s) => s.funcs);
	const selectFn = useAnalysisStore((s) => s.selectFn);

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

	const q = query.trim().toLowerCase();

	const matchedFunctions = useMemo(() => {
		if (!q || !binary) return [];
		// Stop at the cap rather than slicing after a full scan: a binary can hold
		// tens of thousands of functions and only the first thirty are ever shown.
		const out: typeof funcs = [];
		for (const f of funcs) {
			if (out.length === PALETTE_LIMIT) break;
			if ((f.name ?? "").toLowerCase().includes(q)) out.push(f);
		}
		return out;
	}, [funcs, q, binary]);

	const matchedCommands = useMemo(
		() =>
			q
				? commands.filter((c) => c.title.toLowerCase().includes(q))
				: commands,
		[commands, q],
	);

	const entries: Entry[] = [
		...matchedFunctions.map((fn) => ({ kind: "function" as const, fn })),
		...matchedCommands.map((command) => ({
			kind: "command" as const,
			command,
		})),
	];

	const close = () => setOpen(false);
	const runEntry = (entry: Entry) => {
		close();
		if (entry.kind === "command") entry.command.run();
		else selectFn(entry.fn);
	};

	const onKeyDown = (e: React.KeyboardEvent) => {
		if (e.key === "Escape") {
			e.preventDefault();
			close();
		} else if (e.key === "ArrowDown") {
			e.preventDefault();
			setActive((a) => Math.min(a + 1, entries.length - 1));
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			setActive((a) => Math.max(a - 1, 0));
		} else if (e.key === "Enter") {
			e.preventDefault();
			const entry = entries[active];
			if (entry) runEntry(entry);
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
					placeholder={
						binary
							? "type a function name, address, or command…"
							: "type a command…"
					}
					className="placeholder:text-muted-foreground/60 w-full bg-transparent px-3.5 py-3 text-sm outline-none"
				/>
				<div
					ref={listRef}
					className="border-border scroll-host min-h-0 overflow-auto border-t p-1"
				>
					{entries.length === 0 && query.trim() === "" && (
						<div className="text-muted-foreground px-3 py-6 text-center text-xs">
							No commands.
						</div>
					)}
					{entries.map((entry, i) => (
						<button
							key={
								entry.kind === "command"
									? entry.command.id
									: `fn-${entry.fn.addr}`
							}
							onMouseEnter={() => setActive(i)}
							onClick={() => runEntry(entry)}
							className={cn(
								chrome.row,
								"w-full rounded text-left text-sm",
								i === active
									? chrome.selected
									: "hover:bg-accent",
							)}
						>
							{entry.kind === "command" ? (
								<>
									<span className="truncate">
										{entry.command.title}
									</span>
									{entry.command.hint && (
										<span className="text-kbd text-2xs ml-auto">
											{entry.command.hint}
										</span>
									)}
								</>
							) : (
								<>
									<span className="min-w-0 flex-1 truncate">
										{entry.fn.name ??
											`sub_${entry.fn.addr.toString(16)}`}
									</span>
									<span className="text-muted-foreground text-2xs ml-auto font-mono">
										{fmtAddr(entry.fn.addr)}
									</span>
								</>
							)}
						</button>
					))}
					{entries.length === 0 && query.trim() && (
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
