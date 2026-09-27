import { useMemo, useState } from "react";

import { Pane } from "@/components/Pane";
import { Input } from "@/components/ui/input";
import { SplitView } from "@/components/ui/split";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import type { BoundarySymbol, DataSection } from "@/types";

/** `rwx` as three glyphs, with a dash for an absent permission. */
function access(d: {
	readable: boolean;
	writable: boolean;
	executable: boolean;
}): string {
	const bit = (on: boolean) => (on ? "x" : "-");
	return `${bit(d.readable)}${bit(d.writable)}${bit(d.executable)}`;
}

/** Human byte count, so a large section is readable at a glance. */
function fmtSize(n: number): string {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtAddr(a: number): string {
	return `0x${a.toString(16)}`;
}

/** One section row: name, where it is, how big, and what may be done with it. */
function SectionRow({ section }: { section: DataSection }) {
	return (
		<div
			className={cn(
				chrome.row,
				"border-border hover:bg-accent/40 border-l-2 border-transparent",
			)}
		>
			<span className="min-w-0 flex-1 truncate" title={section.name}>
				{section.name}
			</span>
			<span className="text-muted-foreground text-2xs shrink-0">
				{section.kind}
			</span>
			<span className={cn(chrome.nums, "text-asm-addr shrink-0")}>
				{fmtAddr(section.addr)}
			</span>
			<span className={cn(chrome.nums, "text-muted-foreground shrink-0")}>
				{fmtSize(section.size)}
			</span>
			<span
				className={cn(
					chrome.nums,
					"text-muted-foreground/70 shrink-0 tabular-nums",
				)}
				title={`readable=${section.readable} writable=${section.writable} executable=${section.executable}`}
			>
				{access(section)}
			</span>
		</div>
	);
}

/** One linker boundary marker row. */
function BoundaryRow({ boundary }: { boundary: BoundarySymbol }) {
	return (
		<div
			className={cn(
				chrome.row,
				"border-border hover:bg-accent/40 border-l-2 border-transparent",
			)}
		>
			<span className="text-asm-symbol min-w-0 flex-1 truncate italic">
				{boundary.name}
			</span>
			<span className="text-muted-foreground text-2xs shrink-0">
				{boundary.kind}
			</span>
			<span className={cn(chrome.nums, "text-asm-addr shrink-0")}>
				{fmtAddr(boundary.addr)}
			</span>
		</div>
	);
}

/**
 * The image's non-debuggable regions: data sections, and the linker's boundary
 * markers.
 *
 * Split into two panes because they answer different questions and are read at
 * different rates. The sections are the map — what exists, where, how big, and
 * what may be done with it. The boundaries are the frame around that map:
 * `_edata` and `__bss_start` say where initialised data stops and zero-
 * initialised data begins, and in a stripped binary they can be the only
 * description of the image's layout. On a large binary both lists run long, so
 * each pane scrolls on its own and the divider is draggable.
 *
 * Both lists are static for the open binary, so there is nothing to keep in
 * step; the only controls are the filters, and they filter the list below them.
 */
export function DataRegionsPanel() {
	const regions = useAnalysisStore((s) => s.dataRegions);
	const [sectionQuery, setSectionQuery] = useState("");
	const [boundaryQuery, setBoundaryQuery] = useState("");

	const sections = useMemo(() => {
		const q = sectionQuery.trim().toLowerCase();
		if (!q) return regions.sections;
		return regions.sections.filter(
			(s) =>
				s.name.toLowerCase().includes(q) ||
				s.kind.toLowerCase().includes(q),
		);
	}, [regions.sections, sectionQuery]);

	const boundaries = useMemo(() => {
		const q = boundaryQuery.trim().toLowerCase();
		if (!q) return regions.boundaries;
		return regions.boundaries.filter(
			(b) =>
				b.name.toLowerCase().includes(q) ||
				b.kind.toLowerCase().includes(q),
		);
	}, [regions.boundaries, boundaryQuery]);

	const sectionsPane = (
		<Pane
			title="Sections"
			count={
				regions.sections.length > 0
					? sections.length === regions.sections.length
						? `${regions.sections.length}`
						: `${sections.length}/${regions.sections.length}`
					: undefined
			}
			scroll={false}
			bodyClassName="flex min-h-0 flex-col"
		>
			{regions.sections.length > 0 && (
				<div className="px-2 py-1.5">
					<Input
						placeholder="Filter sections…"
						value={sectionQuery}
						onChange={(e) => setSectionQuery(e.target.value)}
					/>
				</div>
			)}
			<div className="scroll-host min-h-0 flex-1 overflow-auto pr-2.5">
				{sections.length === 0 ? (
					<div className="text-muted-foreground p-3 text-xs">
						{regions.sections.length === 0
							? "no non-executable sections — this image is code only"
							: "no sections match"}
					</div>
				) : (
					sections.map((s) => <SectionRow key={s.addr} section={s} />)
				)}
			</div>
		</Pane>
	);

	const boundariesPane = (
		<Pane
			title="Boundaries"
			count={
				regions.boundaries.length > 0
					? boundaries.length === regions.boundaries.length
						? `${regions.boundaries.length}`
						: `${boundaries.length}/${regions.boundaries.length}`
					: undefined
			}
			scroll={false}
			bodyClassName="flex min-h-0 flex-col"
		>
			{regions.boundaries.length > 0 && (
				<div className="px-2 py-1.5">
					<Input
						placeholder="Filter markers…"
						value={boundaryQuery}
						onChange={(e) => setBoundaryQuery(e.target.value)}
					/>
				</div>
			)}
			<div className="scroll-host min-h-0 flex-1 overflow-auto pr-2.5">
				{boundaries.length === 0 ? (
					<div className="text-muted-foreground p-3 text-xs">
						{regions.boundaries.length === 0
							? "no linker boundary markers — stripped binaries usually carry none"
							: "no markers match"}
					</div>
				) : (
					boundaries.map((b) => (
						<BoundaryRow key={`${b.addr}:${b.name}`} boundary={b} />
					))
				)}
			</div>
		</Pane>
	);

	return (
		<SplitView
			top={sectionsPane}
			bottom={boundariesPane}
			initial={0.62}
			storageKey="recurse.dataRegions.split"
		/>
	);
}
