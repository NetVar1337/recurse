import { Loader2 } from "lucide-react";
import { useMemo, useState } from "react";

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
	const busy = useBinaryStore((s) => s.busy);
	const indexing = useBinaryStore((s) => s.indexing);
	const entry = useBinaryStore((s) => s.binary?.info?.bin?.entry);
	const [query, setQuery] = useState("");
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
				<div className="flex flex-col">
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
								return (
									<button
										key={`${f.addr}-${name}`}
										className={cn(
											"flex items-center gap-2 border-l-2 px-3 py-1 text-left text-xs",
											active
												? "border-primary bg-primary text-primary-foreground"
												: "hover:bg-accent border-transparent",
										)}
										onClick={() => selectFn(f)}
										title={`${name}\n${fmtAddr(f.addr)} · size ${f.size ?? "?"}`}
									>
										<span
											className={cn(
												"font-mono",
												active
													? "text-primary-foreground"
													: "text-primary",
											)}
										>
											{fmtAddr(f.addr)}
										</span>
										<span className="truncate">{name}</span>
									</button>
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
