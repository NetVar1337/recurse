import {
	useCallback,
	useEffect,
	useLayoutEffect,
	useRef,
	type KeyboardEvent as ReactKeyboardEvent,
	type PointerEvent as ReactPointerEvent,
	type ReactNode,
} from "react";

import {
	beginDragSuppressSelect,
	endDragSuppressSelect,
} from "@/lib/dragSelect";
import {
	distribute,
	MAX_SHARE,
	MIN_SHARE,
	neighbourOf,
	type ShareOptions,
} from "@/lib/stackSplit";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";

/** One pane of a stack. */
export interface StackPane {
	/** Stable key, used to persist this pane's share. */
	key: string;
	/** The pane's content. Its height is measured, not assumed. */
	content: ReactNode;
}

/**
 * A vertical stack of panes with a draggable divider between each.
 *
 * Each pane opens with the height its content asks for, capped so a long list
 * cannot squeeze the others out, and the shares are written straight to the
 * elements rather than held in state: sizing is a layout fact, and putting it
 * through a re-render would mean every measurement pass cascading into the whole
 * panel's children. Dragging writes the same way, so a drag moves a divider
 * without re-rendering a single list row.
 *
 * The measuring is only where the stack *starts*. A divider the analyst has
 * dragged is their arrangement, persisted per binary layout and restored ahead of
 * any measuring, and they can drag a list smaller than its content or back to
 * what the content asked for — double-click, or Home/End on the handle.
 *
 * @param props.panes - The panes, top to bottom.
 * @param props.storageKey - When set, the shares are persisted under this key.
 * @param props.options - Bounds on one pane's share.
 */
export function StackSplit({
	panes,
	storageKey,
	options,
	className,
}: {
	panes: readonly StackPane[];
	storageKey?: string;
	options?: ShareOptions;
	className?: string;
}) {
	const min = options?.min ?? MIN_SHARE;
	const max = options?.max ?? MAX_SHARE;
	const container = useRef<HTMLDivElement | null>(null);
	const bases = useRef<number[] | null>(null);
	const drag = useRef<{
		index: number;
		y: number;
		/** The container's height when the drag began, so a move never reads layout. */
		height: number;
		shares: number[];
		el: HTMLDivElement;
	} | null>(null);

	/**
	 * The pane frames, in order.
	 *
	 * Read from the container rather than kept in a ref per pane: a ref written
	 * from a render callback is a ref read during render, and this is a layout
	 * fact about elements that already exist.
	 */
	const frames = useCallback((): HTMLElement[] => {
		const box = container.current;
		if (!box) return [];
		return [...box.querySelectorAll<HTMLElement>("[data-stack-pane]")];
	}, []);

	/** Write the current shares to the elements, without a render. */
	const paint = useCallback(
		(next: number[]) => {
			bases.current = next;
			for (const [i, el] of frames().entries()) {
				el.style.flexBasis = `${(next[i] ?? 0) * 100}%`;
			}
		},
		[frames],
	);

	const storageKeyFor = useCallback(
		() =>
			storageKey
				? `${storageKey}:${panes.map((p) => p.key).join(",")}`
				: null,
		[storageKey, panes],
	);

	const remember = useCallback(
		(next: number[]) => {
			const key = storageKeyFor();
			if (!key) return;
			try {
				localStorage.setItem(key, JSON.stringify(next));
			} catch {
				/* storage unavailable; the split just will not persist */
			}
		},
		[storageKeyFor],
	);

	const measure = useCallback(() => {
		const needs = frames().map((el) => el.scrollHeight);
		const next = distribute(needs, { min, max });
		paint(next);
		remember(next);
	}, [frames, paint, remember, min, max]);

	// Measured once, before the browser paints, so the panes are never laid out
	// at one size and then jumped to another. A stored arrangement is the
	// analyst's own and outranks any measuring.
	useLayoutEffect(() => {
		if (bases.current !== null) return;
		const key = storageKeyFor();
		if (key) {
			try {
				const raw = localStorage.getItem(key);
				const parsed = raw ? (JSON.parse(raw) as number[]) : null;
				if (Array.isArray(parsed) && parsed.length === panes.length) {
					paint(parsed);
					return;
				}
			} catch {
				/* unreadable or absent: measure instead */
			}
		}
		// Even division for this pass, so the measuring has something to correct.
		const even = panes.map(() => 1 / panes.length);
		paint(even);
		measure();
		// Deliberately once per arrangement of panes: the measuring is a starting
		// point, not something that re-runs as the lists change length.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [storageKeyFor]);

	// A different set of panes is a different stack, so the shares are measured
	// afresh rather than carried over from lists that no longer exist. Dropping
	// the sizes makes the first layout effect above measure again.
	const keys = panes.map((p) => p.key).join(",");
	useLayoutEffect(() => {
		bases.current = null;
	}, [keys]);

	/**
	 * Move the divider after pane `index`, taking from or giving to its neighbour.
	 *
	 * The neighbour is the pane on the far side of the divider, not the first one:
	 * with three panes the divider after the middle one moves against the last,
	 * and charging it to the first would move two panes' worth of divider for one
	 * divider's worth of drag.
	 *
	 * @param index - The pane whose trailing divider is moving.
	 * @param delta - The share to move, positive downward.
	 * @param persist - Whether to write the arrangement to storage. A drag
	 *   passes `false` and lets the release do it: storage is synchronous, and a
	 *   pointer emits sixty moves a second.
	 */
	const move = useCallback(
		(index: number, delta: number, persist = true) => {
			const shares = bases.current;
			if (!shares) return;
			const next = [...shares];
			const other = neighbourOf(index, next.length);
			if (other === undefined || other < 0) return;
			const give = next[index] - delta;
			const take = next[other] + delta;
			// Neither pane may be dragged out of existence, and neither may take
			// more than its cap: the two share the height between them.
			const allowed = Math.max(
				0,
				Math.min(give - min, max - next[other], take - min),
			);
			if (allowed === 0) return;
			next[index] = give - allowed;
			next[other] = take + allowed;
			paint(next);
			if (persist) remember(next);
		},
		[paint, remember, min, max],
	);

	const onPointerDown =
		(index: number) => (event: ReactPointerEvent<HTMLDivElement>) => {
			const shares = bases.current;
			const box = container.current;
			if (event.button !== 0 || !shares || !box) return;
			// The pointer is crossing rows of names, addresses and symbols; a drag
			// must not leave them selected behind it.
			event.preventDefault();
			beginDragSuppressSelect("row");
			drag.current = {
				index,
				y: event.clientY,
				// Measured once: the container cannot change height under a drag
				// that is not resizing it, and reading it per move would force a
				// layout between every write.
				height: box.getBoundingClientRect().height,
				shares,
				el: event.currentTarget,
			};
			// Lit for the whole drag: the pointer leaves the handle constantly, and
			// a divider that blinks out mid-drag looks broken.
			event.currentTarget.dataset.dragging = "true";
			event.currentTarget.setPointerCapture(event.pointerId);
			drag.current.el = event.currentTarget;
		};

	const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
		const state = drag.current;
		if (!state || state.height <= 0) return;
		// The drag is measured against the shares as they were when it started,
		// so a move is relative to the grab rather than compounding.
		const delta = (event.clientY - state.y) / state.height;
		const current = bases.current;
		if (!current) return;
		move(
			state.index,
			delta + (state.shares[state.index] - current[state.index]),
			false,
		);
	};

	/**
	 * Drop the drag, and the lit line with it however the drag ended.
	 *
	 * Memoized because the window-level fallback below subscribes to it, and
	 * re-subscribing on every render would leave a listener per render until the
	 * next cleanup.
	 */
	const release = useCallback(() => {
		if (drag.current === null) return;
		delete drag.current.el.dataset.dragging;
		drag.current = null;
		// The arrangement is the analyst's once the divider is let go, so this is
		// where it is written — not sixty times on the way there.
		const shares = bases.current;
		if (shares) remember(shares);
		endDragSuppressSelect("row");
	}, [remember]);

	const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
		release();
		if (event.currentTarget.hasPointerCapture(event.pointerId)) {
			event.currentTarget.releasePointerCapture(event.pointerId);
		}
	};

	// A drag that ends outside the handle — released over the window, or the
	// element unmounted mid-drag — would leave the flag set, so the next move
	// would jump the divider.
	useEffect(() => {
		const stop = () => release();
		window.addEventListener("pointerup", stop);
		window.addEventListener("pointercancel", stop);
		return () => {
			window.removeEventListener("pointerup", stop);
			window.removeEventListener("pointercancel", stop);
		};
	}, [release]);

	const onKeyDown =
		(index: number) => (event: ReactKeyboardEvent<HTMLDivElement>) => {
			const step = event.shiftKey ? 0.1 : 0.02;
			if (event.key === "ArrowUp") {
				event.preventDefault();
				move(index, -step);
			} else if (event.key === "ArrowDown") {
				event.preventDefault();
				move(index, step);
			} else if (event.key === "Home" || event.key === "End") {
				// Back to what the content asked for.
				event.preventDefault();
				measure();
			}
		};

	return (
		<div
			ref={container}
			className={cn("flex min-h-0 flex-1 flex-col", className)}
		>
			{panes.map((pane, i) => (
				<div key={pane.key} className="contents">
					<div
						data-stack-pane={pane.key}
						className="min-h-0 shrink-0 overflow-hidden"
						style={{ flexBasis: `${100 / panes.length}%` }}
					>
						{pane.content}
					</div>
					{i < panes.length - 1 && (
						<div
							role="separator"
							aria-orientation="horizontal"
							aria-label={`Resize the ${pane.key} pane`}
							// No `aria-valuenow`: the sizes live on the elements
							// rather than in state, so a render could not report an
							// honest position without also re-rendering every list in
							// the stack. The bounds and the keyboard are what a
							// splitter is actually operated by.
							aria-valuemin={Math.round(min * 100)}
							aria-valuemax={Math.round(max * 100)}
							tabIndex={0}
							onPointerDown={onPointerDown(i)}
							onPointerMove={onPointerMove}
							onPointerUp={endDrag}
							onKeyDown={onKeyDown(i)}
							onDoubleClick={measure}
							className={`${chrome.rowDivider} h-1.5 shrink-0 cursor-row-resize`}
						/>
					)}
				</div>
			))}
		</div>
	);
}
