import { Database, ListTree } from "lucide-react";
import { useState } from "react";

import { DataRegionsPanel } from "@/components/DataRegionsPanel";
import { FunctionList } from "@/components/FunctionList";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";

/** One panel the sidebar can show. */
type SidebarTab = "functions" | "data";

/**
 * The left sidebar: the function list and the image's non-debuggable regions.
 *
 * These are tabs rather than two stacked panes because they are different views
 * of the binary, not parts of one list — a reader is either looking for code to
 * read or for the memory map around it, and stacking them would halve the height
 * of both in a window that is already short. Whichever tab is up, its panel owns
 * the full column height and scrolls on its own.
 */
export function Sidebar() {
	const [tab, setTab] = useState<SidebarTab>("functions");
	// Live counts, so each tab says how much is behind it before it is opened. The
	// functions count grows a "+" while indexing is still running, which is the
	// one thing the number alone cannot say.
	const functionCount = useAnalysisStore((s) => s.funcs.length);
	const indexing = useBinaryStore((s) => s.indexing);
	const regionCount = useAnalysisStore(
		(s) => s.dataRegions.sections.length + s.dataRegions.boundaries.length,
	);

	const tabs: {
		id: SidebarTab;
		label: string;
		icon: typeof ListTree;
		/** A count is text, not a number: the functions count can be "21+". */
		count?: string;
	}[] = [
		{
			id: "functions",
			label: "Functions",
			icon: ListTree,
			count:
				functionCount > 0
					? `${functionCount}${indexing ? "+" : ""}`
					: undefined,
		},
		{
			id: "data",
			label: "Data",
			icon: Database,
			count: regionCount ? String(regionCount) : undefined,
		},
	];

	return (
		<div className="@container flex min-h-0 min-w-0 flex-1 flex-col">
			<div
				role="tablist"
				aria-label="Sidebar view"
				className={cn(
					chrome.bar,
					"border-border shrink-0 border-b px-2",
				)}
			>
				{tabs.map(({ id, label, icon: Icon, count }) => {
					const active = tab === id;
					return (
						<button
							key={id}
							role="tab"
							type="button"
							aria-selected={active}
							onClick={() => setTab(id)}
							className={cn(
								"flex h-[var(--control-h)] items-center gap-1.5 rounded-[var(--radius-control)] px-2 text-xs",
								active
									? chrome.press
									: "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
							)}
						>
							<Icon className="h-3.5 w-3.5" strokeWidth={1.5} />
							{label}
							{count !== undefined && (
								<span className="nums text-2xs opacity-70">
									{count}
								</span>
							)}
						</button>
					);
				})}
			</div>
			{tab === "functions" ? <FunctionList /> : <DataRegionsPanel />}
		</div>
	);
}
