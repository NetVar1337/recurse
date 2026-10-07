import { useMemo, useState } from "react";

import { Pane } from "@/components/Pane";
import { Input } from "@/components/ui/input";
import { StackSplit } from "@/components/ui/stack-split";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import type { BoundarySymbol, DataSection, DataSegment } from "@/types";

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

/** The whole of a row's metadata on hover, since a row cannot hold it all. */
function details(lines: string[]): string {
	return lines.join("\n");
}

/**
 * One section row: what it is, where it is in memory and in the file, and what
 * may be done with it.
 *
 * The address and the file offset are both shown because they are different
 * numbers, and the difference between them is the first thing an analyst wants
 * to know about a region.
 */
function SectionRow({ section }: { section: DataSection }) {
	return (
		<div
			className={cn(
				chrome.row2,
				"border-border hover:bg-accent/40 border-l-2 border-transparent",
			)}
			title={details([
				`${section.name}  (${section.section_type})`,
				`address  ${fmtAddr(section.addr)}  size ${fmtSize(section.size)}`,
				`file     ${fmtAddr(section.file_offset)}  align ${fmtAddr(section.align)}`,
				`flags    ${fmtFlags(section.flags)}`,
				`kind     ${section.kind}`,
				section.uninitialized
					? "occupies no file bytes — zero-filled at load"
					: "",
			])}
		>
			<div className="flex w-full min-w-0 items-baseline gap-2">
				<span className="min-w-0 flex-1 truncate" title={section.name}>
					{section.name}
				</span>
				<span className="text-asm-symbol shrink-0 text-[10px]">
					{section.section_type}
				</span>
			</div>
			<div
				data-part="meta"
				className={cn(
					chrome.nums,
					"text-muted-foreground/80 flex shrink-0 gap-2 text-[10px]",
				)}
			>
				<span className="text-asm-addr">{fmtAddr(section.addr)}</span>
				<span>{fmtSize(section.size)}</span>
				<span title="offset in the file">
					@{fmtAddr(section.file_offset)}
				</span>
				<span
					className="ml-auto tabular-nums"
					title="read / write / execute"
				>
					{access(section)}
				</span>
			</div>
		</div>
	);
}

/**
 * One segment row: what the kernel is willing to map, and from where.
 *
 * The memory size and the file size are both shown because their difference is
 * the zero-filled tail — a segment larger than its bytes is `.bss`, and a
 * segment that is not larger than its bytes is not.
 */
function SegmentRow({ segment }: { segment: DataSegment }) {
	const zeroFilled = segment.mem_size > segment.file_size;
	return (
		<div
			className={cn(
				chrome.row2,
				"border-border hover:bg-accent/40 border-l-2 border-transparent",
			)}
			title={details([
				`${segment.kind}`,
				`virtual  ${fmtAddr(segment.addr)}  mem ${fmtSize(segment.mem_size)}`,
				`file     ${fmtAddr(segment.file_offset)}  ${fmtSize(segment.file_size)}`,
				`align    ${fmtAddr(segment.align)}`,
				`access   ${access(segment)}`,
				zeroFilled
					? `tail of ${fmtSize(segment.mem_size - segment.file_size)} is zero-filled`
					: "",
			])}
		>
			<div className="flex w-full min-w-0 items-baseline gap-2">
				<span className="text-asm-symbol min-w-0 flex-1 truncate">
					{segment.kind}
				</span>
				<span
					className={cn(
						chrome.nums,
						"shrink-0 text-[10px] tabular-nums",
						segment.writable &&
							segment.executable &&
							"text-destructive",
					)}
					title="read / write / execute"
				>
					{access(segment)}
				</span>
			</div>
			<div
				data-part="meta"
				className={cn(
					chrome.nums,
					"text-muted-foreground/80 flex shrink-0 gap-2 text-[10px]",
				)}
			>
				<span className="text-asm-addr">{fmtAddr(segment.addr)}</span>
				<span className={zeroFilled ? "text-asm-symbol" : undefined}>
					{fmtSize(segment.mem_size)}
				</span>
				<span title="bytes taken from the file">
					{fmtSize(segment.file_size)} file
				</span>
			</div>
		</div>
	);
}

/** The recognised section-flag bits, as the letters the header defines. */
function fmtFlags(flags: number): string {
	const named: [number, string][] = [
		[0x1, "WRITE"],
		[0x2, "ALLOC"],
		[0x4, "EXECINSTR"],
		[0x10, "MERGE"],
		[0x20, "STRINGS"],
		[0x40, "INFO_LINK"],
		[0x80, "LINK_ORDER"],
		[0x200, "GROUP"],
		[0x400, "TLS"],
		[0x800, "COMPRESSED"],
	];
	const on = named.filter(([bit]) => flags & bit).map(([, name]) => name);
	return on.length > 0 ? on.join(" | ") : "none";
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
 * Three panes, because the image has three views of itself and they answer
 * different questions. The **segments** are the kernel's: what it is actually
 * willing to map, which is where a writable-and-executable `LOAD` — a hardening
 * finding no section list can show — and the line between bytes read from the
 * file and bytes zero-filled at load, which is how `.bss` is accounted for. The
 * **sections** are the linker's: one per purpose, named, with the file offset
 * and alignment each carries. The **boundaries** are the frame around both:
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
	const [segmentQuery, setSegmentQuery] = useState("");
	// Memoised because it feeds a `useMemo` below: a fresh `[]` each render would
	// invalidate it on every render and with it the filter.
	const segments = useMemo(() => regions.segments ?? [], [regions.segments]);

	const shownSegments = useMemo(() => {
		const q = segmentQuery.trim().toLowerCase();
		if (!q) return segments;
		return segments.filter((g) => g.kind.toLowerCase().includes(q));
	}, [segments, segmentQuery]);

	const sections = useMemo(() => {
		const q = sectionQuery.trim().toLowerCase();
		if (!q) return regions.sections;
		return regions.sections.filter(
			(s) =>
				s.name.toLowerCase().includes(q) ||
				s.kind.toLowerCase().includes(q) ||
				// The header's own type is text like any other, and the one an
				// analyst reaches for when hunting every table of relocations or
				// every zero-filled region. The permission flags stay out: they
				// are shown in the row, and a filter that matched them would be
				// answering a different question than the one being asked.
				s.section_type.toLowerCase().includes(q),
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

	const segmentsPane = (
		<Pane
			title="Segments"
			count={
				segments.length > 0
					? shownSegments.length === segments.length
						? `${segments.length}`
						: `${shownSegments.length}/${segments.length}`
					: undefined
			}
			scroll={false}
			bodyClassName="flex min-h-0 flex-col"
		>
			{segments.length > 0 && (
				<div className="px-2 py-1.5">
					<Input
						placeholder="Filter segments…"
						value={segmentQuery}
						onChange={(e) => setSegmentQuery(e.target.value)}
					/>
				</div>
			)}
			<div className="scroll-host min-h-0 flex-1 overflow-auto pr-2.5">
				{shownSegments.length === 0 ? (
					<div className="text-muted-foreground p-3 text-xs">
						{segments.length === 0
							? "no program headers — this image is not an ELF, or carries none"
							: "no segments match"}
					</div>
				) : (
					shownSegments.map((g) => (
						<SegmentRow
							key={`${g.addr}:${g.kind}:${g.file_offset}`}
							segment={g}
						/>
					))
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
		<StackSplit
			storageKey="recurse.dataRegions"
			panes={[
				{ key: "sections", content: sectionsPane },
				{ key: "segments", content: segmentsPane },
				{ key: "boundaries", content: boundariesPane },
			]}
		/>
	);
}
