import { Database, ListTree } from "lucide-react";
import { useState } from "react";

import { DataRegionsPanel } from "@/components/DataRegionsPanel";
import { FunctionList } from "@/components/FunctionList";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";

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
	// A live count, so the data tab says how much is in it before it is opened.
	const regionCount = useAnalysisStore(
		(s) => s.dataRegions.sections.length + s.dataRegions.boundaries.length,
	);

	const tabs: {
		id: SidebarTab;
		label: string;
		icon: typeof ListTree;
		count?: number;
	}[] = [
		{ id: "functions", label: "Functions", icon: ListTree },
		{
			id: "data",
			label: "Data",
			icon: Database,
			count: regionCount || undefined,
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
							<Icon className="h-3.5 w-3.5" />
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
