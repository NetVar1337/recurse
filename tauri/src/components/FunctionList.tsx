import { Loader2 } from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";
import type { Function } from "@/types";

function fmtAddr(a: number) {
	return `0x${a.toString(16)}`;
}

/** Lower rank sorts first: entry points and `main` above everything else. */
function fnRank(f: Function, entry?: number): number {
	if (typeof entry === "number" && f.addr === entry) return 0;
	const name = (f.name ?? f.realname ?? f.signature ?? "")
		.toLowerCase()
		.replace(/^(sym\.|imp\.|fcn_)/, "");
	if (name === "main" || name === "__main") return 1;
	if (
		name === "_start" ||
		name === "start" ||
		name === "entry" ||
		name === "entry0" ||
		name === "_entry"
	)
		return 2;
	if (name.includes("libc_start_main")) return 3;
	if (
		name === "_init" ||
		name === "init" ||
		name === "_fini" ||
		name === "fini"
	)
		return 4;
	return 5;
}

export function FunctionList() {
	const funcs = useAnalysisStore((s) => s.funcs);
	const selected = useAnalysisStore((s) => s.selected);
	const selectFn = useAnalysisStore((s) => s.selectFn);
	const renameFunction = useAnalysisStore((s) => s.renameFunction);
	const busy = useBinaryStore((s) => s.busy);
	const indexing = useBinaryStore((s) => s.indexing);
	const entry = useBinaryStore((s) => s.binary?.info?.bin?.entry);
	const [query, setQuery] = useState("");
	const [renaming, setRenaming] = useState<number | null>(null);
	const [draft, setDraft] = useState("");
	const skipBlur = useRef(false);

	/** Begin editing the name of the function at `addr`. */
	const startRename = (addr: number, current: string) => {
		setDraft(current);
		setRenaming(addr);
	};

	/** Save the in-progress rename (blank clears it). */
	const commitRename = async () => {
		const addr = renaming;
		if (addr === null) return;
		setRenaming(null);
		await renameFunction(addr, draft.trim());
	};

	/** Abandon the in-progress rename. */
	const cancelRename = () => {
		skipBlur.current = true;
		setRenaming(null);
	};
	const [prevFuncs, setPrevFuncs] = useState(funcs);
	if (prevFuncs !== funcs) {
		setPrevFuncs(funcs);
		setQuery("");
	}

	// Entry points and `main` float to the top; the rest stay in address order.
	const ordered = useMemo(
		() =>
			[...funcs].sort(
				(a, b) =>
					fnRank(a, entry) - fnRank(b, entry) || a.addr - b.addr,
			),
		[funcs, entry],
	);

	const filtered = useMemo(() => {
		const q = query.trim().toLowerCase();
		if (!q) return ordered;
		return ordered.filter((f) =>
			(f.name ?? f.realname ?? f.signature ?? "")
				.toLowerCase()
				.includes(q),
		);
	}, [ordered, query]);

	return (
		<div className="flex min-h-0 flex-1 flex-col">
			<div className="text-muted-foreground flex items-center gap-2 px-3 py-2 text-[11px] font-semibold tracking-wider uppercase">
				Functions
				{funcs.length > 0 && (
					<span className="text-muted-foreground/70 font-normal normal-case">
						{funcs.length}
						{indexing ? "+" : ""}
					</span>
				)}
			</div>
			{indexing && (
				<div className="text-muted-foreground/80 flex items-center gap-1.5 px-3 pb-1 text-[10px]">
					<Loader2 className="h-3 w-3 animate-spin" />
					indexing in the background — more may appear
				</div>
			)}
			<div className="px-2 pb-2">
				<Input
					placeholder="Filter functions…"
					value={query}
					onChange={(e) => setQuery(e.target.value)}
				/>
			</div>
			<ScrollArea className="flex-1">
				{/* `pr-2.5` reserves a gutter for the overlay scrollbar (w-2.5),
				    so it never covers the rename button on hover. */}
				<div className="flex flex-col pr-2.5">
					{busy && filtered.length === 0 ? (
						<div className="text-muted-foreground flex items-center gap-2 px-3 py-3 text-xs">
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
							analyzing…
						</div>
					) : (
						<>
							{filtered.map((f) => {
								const name =
									f.name ??
									f.realname ??
									f.signature ??
									`sub_${f.addr.toString(16)}`;
								const active = selected?.addr === f.addr;
								const editing = renaming === f.addr;
								return (
									<div
										key={`${f.addr}-${name}`}
										className={cn(
											"group flex items-center border-l-2 pr-1 text-xs",
											active
												? "border-foreground ui-selected"
												: "hover:bg-accent border-transparent",
										)}
									>
										{editing ? (
											<Input
												autoFocus
												value={draft}
												placeholder="name (blank clears)"
												onChange={(e) =>
													setDraft(e.target.value)
												}
												onKeyDown={(e) => {
													if (e.key === "Enter")
														e.currentTarget.blur();
													else if (e.key === "Escape")
														cancelRename();
												}}
												onBlur={() => {
													if (skipBlur.current) {
														skipBlur.current = false;
														return;
													}
													void commitRename();
												}}
												// Blend with the row: no border, no fill, and the
												// same colour as a normal function name.
												className="h-6 flex-1 border-0 bg-transparent px-3 py-0 text-xs shadow-none focus-visible:ring-0"
											/>
										) : (
											<>
												<button
													className="flex min-w-0 flex-1 items-center gap-2 px-3 py-1 text-left"
													onClick={() => selectFn(f)}
													onDoubleClick={() =>
														startRename(
															f.addr,
															name,
														)
													}
													title={`${name}\n${fmtAddr(f.addr)} · size ${f.size ?? "?"}\ndouble-click to rename`}
												>
													<span
														className={cn(
															"font-mono",
															active
																? "opacity-80"
																: "text-primary",
														)}
													>
														{fmtAddr(f.addr)}
													</span>
													<span className="truncate">
														{name}
													</span>
												</button>
												<button
													className="text-muted-foreground hover:text-foreground hidden shrink-0 px-1 text-[10px] group-hover:block"
													onClick={(e) => {
														e.stopPropagation();
														startRename(
															f.addr,
															name,
														);
													}}
												>
													Rename
												</button>
											</>
										)}
									</div>
								);
							})}
							{filtered.length === 0 && (
								<div className="text-muted-foreground px-3 py-3 text-center text-xs">
									no functions
								</div>
							)}
						</>
					)}
				</div>
			</ScrollArea>
		</div>
	);
}
