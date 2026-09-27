import {
	useCallback,
	useEffect,
	useRef,
	useState,
	type KeyboardEvent as ReactKeyboardEvent,
	type PointerEvent as ReactPointerEvent,
	type ReactNode,
} from "react";

import { cn } from "@/lib/utils";

/** How far the divider may travel, as a fraction of the container. */
const MIN_PANE = 0.15;
const MAX_PANE = 0.85;

/**
 * Two stacked panes with a draggable divider, each scrolling on its own.
 *
 * The split is a fraction of the container height rather than a pixel height, so
 * it keeps its proportion when the window resizes and both panes stay usable at
 * any size — a fixed height would starve one of them on a short window, and a
 * large binary's two lists are exactly what needs the room.
 *
 * Pointer capture keeps the drag alive when the pointer leaves the handle or
 * the window, and the listeners go on the window rather than the element so a
 * fast drag does not outrun them. Keyboard support is on the handle itself
 * (arrows, Home/End), since a divider you can only drag is not reachable without
 * a mouse.
 *
 * @param props.top - The upper pane.
 * @param props.bottom - The lower pane.
 * @param props.initial - Starting split as a fraction of the container, 0–1.
 * @param props.min - Smallest fraction the top pane may take.
 * @param props.max - Largest fraction the top pane may take.
 * @param props.storageKey - When set, the fraction is persisted under this key.
 */
export function SplitView({
	top,
	bottom,
	initial = 0.5,
	min = MIN_PANE,
	max = MAX_PANE,
	storageKey,
	className,
}: {
	top: ReactNode;
	bottom: ReactNode;
	initial?: number;
	min?: number;
	max?: number;
	storageKey?: string;
	className?: string;
}) {
	const clamp = useCallback(
		(v: number) => Math.min(max, Math.max(min, v)),
		[min, max],
	);
	const [fraction, setFraction] = useState(() => {
		if (!storageKey) return clamp(initial);
		const saved = Number(localStorage.getItem(storageKey));
		return Number.isFinite(saved) && saved > 0
			? clamp(saved)
			: clamp(initial);
	});
	const container = useRef<HTMLDivElement | null>(null);
	const dragging = useRef(false);
	const origin = useRef({ y: 0, fraction: 0 });

	// `localStorage` is absent in the node test environment.
	const persist = useCallback(
		(v: number) => {
			if (storageKey) {
				try {
					localStorage.setItem(storageKey, String(v));
				} catch {
					/* storage unavailable; the split just will not persist */
				}
			}
		},
		[storageKey],
	);

	const apply = useCallback(
		(next: number) => {
			const v = clamp(next);
			setFraction(v);
			persist(v);
		},
		[clamp, persist],
	);

	const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
		// Primary button only, so a right-click never starts a drag.
		if (event.button !== 0) return;
		dragging.current = true;
		origin.current = {
			y: event.clientY,
			fraction,
		};
		event.currentTarget.setPointerCapture(event.pointerId);
	};

	const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
		if (!dragging.current || !container.current) return;
		const rect = container.current.getBoundingClientRect();
		if (rect.height <= 0) return;
		const delta = (event.clientY - origin.current.y) / rect.height;
		apply(origin.current.fraction + delta);
	};

	const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
		if (!dragging.current) return;
		dragging.current = false;
		if (event.currentTarget.hasPointerCapture(event.pointerId)) {
			event.currentTarget.releasePointerCapture(event.pointerId);
		}
	};

	// A drag that ends outside the handle (pointer released over the window, or
	// the element unmounted mid-drag) would otherwise leave the flag set, so the
	// next move would jump the divider.
	useEffect(() => {
		const stop = () => {
			dragging.current = false;
		};
		window.addEventListener("pointerup", stop);
		window.addEventListener("pointercancel", stop);
		return () => {
			window.removeEventListener("pointerup", stop);
			window.removeEventListener("pointercancel", stop);
		};
	}, []);

	const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
		const step = event.shiftKey ? 0.1 : 0.02;
		if (event.key === "ArrowUp") {
			event.preventDefault();
			apply(fraction - step);
		} else if (event.key === "ArrowDown") {
			event.preventDefault();
			apply(fraction + step);
		} else if (event.key === "Home") {
			event.preventDefault();
			apply(min);
		} else if (event.key === "End") {
			event.preventDefault();
			apply(max);
		}
	};

	return (
		<div
			ref={container}
			className={cn("flex min-h-0 flex-1 flex-col", className)}
		>
			<div
				className="min-h-0 shrink-0 overflow-hidden"
				style={{ flexBasis: `${fraction * 100}%` }}
			>
				{top}
			</div>
			<div
				role="separator"
				aria-orientation="horizontal"
				aria-label="Resize panes"
				aria-valuenow={Math.round(fraction * 100)}
				aria-valuemin={Math.round(min * 100)}
				aria-valuemax={Math.round(max * 100)}
				tabIndex={0}
				onPointerDown={onPointerDown}
				onPointerMove={onPointerMove}
				onPointerUp={endDrag}
				onKeyDown={onKeyDown}
				onDoubleClick={() => apply(initial)}
				title="Drag to resize · arrows to nudge · double-click to reset"
				className={cn(
					"group border-border hover:bg-accent focus-visible:bg-accent relative h-2 shrink-0 cursor-row-resize touch-none border-y",
					"focus-visible:outline-none",
				)}
			>
				{/* A visible rule that thickens on hover, so the grab area is
				    wider than the line it draws. */}
				<span
					aria-hidden
					className="bg-border group-hover:bg-muted-foreground absolute inset-x-0 top-1/2 h-px -translate-y-1/2"
				/>
			</div>
			<div className="min-h-0 flex-1 overflow-hidden">{bottom}</div>
		</div>
	);
}
