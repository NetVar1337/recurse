import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { RefObject } from "react";

import { api } from "@/api";
import {
	clearHeaderInfoCache,
	FunctionHeader,
} from "@/components/FunctionHeader";
import { DisasmComment, DisasmInstr, splitComment } from "@/lib/disasm";
import { fmtAddr } from "@/lib/listingFormat";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import type { Function, ListingRow } from "@/types";

/** Rows fetched per request. Small enough to stay snappy, large enough that a
 * fast scroll does not outrun the fetches. */
const CHUNK = 256;

/** One listing row's height, matching `--row-h`. The window relies on it being
 * fixed, and measures each rendered row to correct for a non-16px root size. */
const ROW_H = 18;

/**
 * Group a hex byte string into space-separated pairs, the way Ghidra shows
 * instruction and data bytes: `0f4c3b` becomes `0f 4c 3b`.
 *
 * @param hex - The packed hex string, or null.
 * @returns The bytes separated by single spaces.
 *
 * @example
 * groupBytes("0f4c3b") // => "0f 4c 3b"
 * groupBytes(null)     // => ""
 */
function groupBytes(hex?: string | null): string {
	if (!hex) return "";
	return hex.match(/.{1,2}/g)?.join(" ") ?? "";
}

/**
 * One row of the listing: a section header, a disassembled instruction, or a
 * run of data bytes.
 *
 * @param props.row - The row to render.
 * @param props.func - Name of the function starting at this row, if any.
 * @param props.active - Whether this row's address is selected.
 * @param props.onGoTo - Called when a named function row is activated.
 * @param props.onSelect - Called with the row's address when it is clicked.
 * @returns The row element.
 */
const ListingRowView = memo(function ListingRowView({
	row,
	func,
	active,
	onGoTo,
	onSelect,
}: {
	row: ListingRow;
	func?: Function | null;
	active: boolean;
	onGoTo?: (f: Function) => void;
	onSelect?: (addr: number) => void;
}) {
	if (row.kind === "header") {
		return (
			<div className="border-border bg-muted/40 text-asm-number flex h-[18px] items-center border-y px-3 font-mono text-[11px] font-semibold">
				{row.label ?? "section"}
			</div>
		);
	}

	const text = row.text ?? "";
	const { instr, comment } =
		row.kind === "code" ? splitComment(text) : { instr: "", comment: "" };

	return (
		<>
			{/* A function opens a region of the listing, marked the way Ghidra
			    marks it: blank space, the boxed FUNCTION banner, the signature
			    and its parameter/local storage, then the code. All as `;`
			    comments, so it reads as a header and not as either a section
			    band or an instruction. */}
			{func && <FunctionHeader func={func} onGoTo={onGoTo} />}
			<div
				className={cn(
					// Not `data-row`: its fixed height cannot hold bytes that
					// wrap to a second line, which is how a long instruction's
					// bytes stay in one narrow column instead of pushing the
					// instruction far to the right.
					"flex min-h-[18px] min-w-max items-center gap-3 py-px pl-3 font-mono whitespace-nowrap",
					active && "ui-selected border-brand border-l-2 pl-[10px]",
					"hover:bg-accent/70 cursor-pointer",
				)}
				onClick={() => onSelect?.(row.addr)}
				title={
					row.kind === "code" ? "Select instruction" : "Select data"
				}
			>
				<span className="text-asm-addr w-[19ch] shrink-0">
					{fmtAddr(row.addr)}
				</span>
				<span className="text-asm-bytes w-[26ch] shrink-0 pr-3 whitespace-pre-wrap">
					{groupBytes(row.bytes)}
				</span>
				{row.kind === "code" ? (
					<span className="text-foreground">
						<DisasmInstr text={instr} />
						<DisasmComment comment={comment} />
						{typeof row.jump === "number" && (
							<span className="text-asm-jump">
								{" "}
								→ {fmtAddr(row.jump)}
							</span>
						)}
					</span>
				) : (
					<span className="text-asm-string">{text}</span>
				)}
			</div>
		</>
	);
});

/**
 * The whole-image listing: every mapped section — code, rodata, data, bss — in
 * address order, on one scrollable surface. Rows are fetched a window at a time
 * as the view scrolls, so a multi-megabyte image is never held in the browser
 * at once.
 *
 * @param props.scrollRef - The scroll container this listing virtualizes within.
 * @param props.binaryPath - Resets the cached rows when the target changes.
 * @param props.selectedAddr - The selected row's address, for highlighting.
 * @param props.focusAddr - An address to scroll to when it changes (a function
 *   chosen elsewhere, e.g. the function list).
 * @param props.onGoTo - Called when a function row is activated.
 * @param props.onSelectAddress - Called with a row's address when it is clicked.
 * @returns The listing surface.
 */
export function ListingView({
	scrollRef,
	binaryPath,
	selectedAddr,
	focusAddr,
	onGoTo,
	onSelectAddress,
}: {
	scrollRef: RefObject<HTMLDivElement | null>;
	binaryPath?: string;
	selectedAddr?: number | null;
	focusAddr?: number | null;
	onGoTo?: (f: Function) => void;
	onSelectAddress?: (addr: number) => void;
}) {
	const funcs = useAnalysisStore((s) => s.funcs);
	const funcByAddr = useMemo(() => {
		const m = new Map<number, Function>();
		for (const f of funcs) {
			if (typeof f.addr === "number" && f.name) m.set(f.addr, f);
		}
		return m;
	}, [funcs]);

	const [chunks, setChunks] = useState<Map<number, ListingRow[]>>(new Map());
	const [total, setTotal] = useState(0);
	const [error, setError] = useState<string | null>(null);
	const inflight = useRef<Set<number>>(new Set());
	const listRef = useRef<HTMLDivElement>(null);
	const [scrollMargin, setScrollMargin] = useState(0);
	// Widest row seen. The list is sized to it so the section and function
	// bands span the whole scrollable width: sized to the viewport instead,
	// they slide left under a horizontal scroll and leave a gap, and their
	// centred headers get clipped at the edge.
	const [contentWidth, setContentWidth] = useState(0);
	const maxWidthRef = useRef(0);

	// A new target is a new address space; drop every cached row, the width, and
	// the headers derived from the old one's instructions — an address means a
	// different function here, so a cached header would describe the wrong one.
	useEffect(() => {
		setChunks(new Map());
		setTotal(0);
		setError(null);
		inflight.current = new Set();
		maxWidthRef.current = 0;
		setContentWidth(0);
		clearHeaderInfoCache();
	}, [binaryPath]);

	// TanStack's virtualizer: a hook whose result cannot be memoized, and this
	// app does not run the React Compiler, so the hazard the rule warns about
	// cannot occur. Same silence as the function list.
	// eslint-disable-next-line react-hooks/incompatible-library
	const virtualizer = useVirtualizer({
		count: total,
		getScrollElement: () => scrollRef.current,
		estimateSize: () => ROW_H,
		overscan: 24,
		scrollMargin,
	});

	const items = virtualizer.getVirtualItems();
	const firstIndex = items.length ? items[0].index : 0;
	const lastIndex = items.length ? items[items.length - 1].index : 0;

	// Measure a row for the window (its height) and for the list width (its
	// content), so the bands can span every row. The width only ever grows.
	const measureRow = useCallback(
		(node: HTMLDivElement | null) => {
			virtualizer.measureElement(node);
			if (!node) return;
			const wide = node.scrollWidth;
			if (wide > maxWidthRef.current + 8) {
				maxWidthRef.current = wide;
				setContentWidth(wide);
			}
		},
		[virtualizer],
	);

	useEffect(() => {
		const want = (index: number) => {
			const chunk = Math.floor(index / CHUNK);
			if (chunks.has(chunk) || inflight.current.has(chunk)) return;
			inflight.current.add(chunk);
			api.listing(chunk * CHUNK, CHUNK)
				.then((window) => {
					inflight.current.delete(chunk);
					setTotal(window.total);
					setChunks((prev) => {
						if (prev.has(chunk)) return prev;
						const next = new Map(prev);
						next.set(chunk, window.rows);
						return next;
					});
				})
				.catch((e) => {
					inflight.current.delete(chunk);
					setError(String(e));
				});
		};
		if (total === 0) {
			want(0);
		} else {
			want(firstIndex);
			want(lastIndex);
		}
	}, [firstIndex, lastIndex, total, chunks]);

	// Scroll to a focus address once the listing's length is known: locating a
	// row needs the built index, which exists only after the first window
	// returns a total.
	useEffect(() => {
		if (focusAddr == null || total === 0) return;
		let cancelled = false;
		api.listingLocate(focusAddr)
			.then((index) => {
				if (!cancelled) {
					virtualizer.scrollToIndex(index, { align: "start" });
				}
			})
			.catch(() => {
				/* the backend has no listing to scroll within */
			});
		return () => {
			cancelled = true;
		};
	}, [focusAddr, total, virtualizer]);

	// The list may begin below other content in the shared scroll container;
	// measure its offset so the window aligns with the rows. The state write
	// bails when unchanged, so this does not loop.
	// eslint-disable-next-line react-hooks/exhaustive-deps
	useEffect(() => {
		const el = listRef.current;
		if (!el) return;
		const margin = el.offsetTop;
		setScrollMargin((current) => (current === margin ? current : margin));
	});

	if (error) {
		return (
			<div className="text-muted-foreground px-3 py-3 text-xs">
				This backend does not provide a whole-image listing.
			</div>
		);
	}

	return (
		<div
			ref={listRef}
			className="relative"
			style={{
				height: `${virtualizer.getTotalSize()}px`,
				width: contentWidth ? `${contentWidth}px` : undefined,
			}}
		>
			{items.map((item) => {
				const chunk = chunks.get(Math.floor(item.index / CHUNK));
				const row = chunk?.[item.index % CHUNK];
				return (
					<div
						key={item.index}
						data-index={item.index}
						ref={measureRow}
						style={{
							position: "absolute",
							insetBlockStart: 0,
							insetInlineStart: 0,
							width: "100%",
							transform: `translateY(${item.start - scrollMargin}px)`,
						}}
					>
						{row ? (
							<ListingRowView
								row={row}
								func={
									row.kind === "code"
										? (funcByAddr.get(row.addr) ?? null)
										: null
								}
								active={row.addr === selectedAddr}
								onGoTo={onGoTo}
								onSelect={onSelectAddress}
							/>
						) : (
							<div className="data-row text-muted-foreground pl-3 font-mono">
								…
							</div>
						)}
					</div>
				);
			})}
		</div>
	);
}
