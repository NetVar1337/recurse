import {
	useCallback,
	useEffect,
	useLayoutEffect,
	useRef,
	useState,
	type KeyboardEvent as ReactKeyboardEvent,
	type PointerEvent as ReactPointerEvent,
} from "react";

import { chrome } from "@/lib/chrome";
import {
	beginDragSuppressSelect,
	endDragSuppressSelect,
} from "@/lib/dragSelect";
import {
	COLUMNS,
	columnVariable,
	DRAG_STEP,
	DRAG_STEP_COARSE,
	fitColumn,
	readColumn,
	type ColumnSpec,
} from "@/lib/resizableColumn";

export type { ColumnSpec };

/**
 * A column whose width is dragged, remembered, and bounded by the window.
 *
 * A drag writes the width to a CSS variable on the grid rather than through
 * state: moving a divider is a layout change, and a re-render per pointer move
 * would re-render the code listing and the chat sixty times a second to move a
 * border. The value in state is committed once, on release, for the handle's
 * accessible value and the remembered width.
 *
 * The bounds are recomputed from the live window on every resize, so a width
 * remembered on a maximised window is never honoured past the point where it
 * would squeeze the panel it is read alongside.
 *
 * Two columns that each protected the centre's floor on their own could both sit
 * at their maximum and squeeze it anyway, so a column charges the floor against
 * the width its sibling is holding — read from the grid, which is where the drag
 * wrote it, rather than from the sibling's React state, which is one render
 * behind it.
 *
 * @param key - The column's name, as `COLUMNS` knows it.
 * @param grid - The grid the column's width is written to, once it is mounted.
 * @returns The width in force and the divider's props.
 */
export function useResizableColumn(
	key: string,
	grid: HTMLDivElement | null,
): {
	width: number;
	/**
	 * The divider's props, built here so a caller cannot spell a second divider
	 * that differs in some small way: the role, the accessible value, the grab
	 * area and the handlers all come from the same place as the width.
	 */
	divider: {
		role: "separator";
		"aria-orientation": "vertical";
		"aria-label": string;
		"aria-valuenow": number;
		"aria-valuemin": number;
		"aria-valuemax": number;
		tabIndex: 0;
		title: string;
		className: string;
		onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
		onPointerMove: (event: ReactPointerEvent<HTMLDivElement>) => void;
		onPointerUp: (event: ReactPointerEvent<HTMLDivElement>) => void;
		onKeyDown: (event: ReactKeyboardEvent<HTMLDivElement>) => void;
		onDoubleClick: () => void;
	};
} {
	const spec = COLUMNS[key];
	const { side, min, max, initial } = spec;
	const storageKey = `recurse.${key}.width`;
	const variable = columnVariable(key);
	const [width, setWidth] = useState(() => initial(window.innerWidth));
	const handleEl = useRef<HTMLDivElement | null>(null);
	const dragging = useRef(false);
	/** The grid's edges as of the drag's first move, so a move never reads layout. */
	const origin = useRef<DOMRect | null>(null);
	/** The width, as the grid sees it. */
	const paint = useCallback(
		(next: number) => {
			grid?.style.setProperty(variable, `${next}px`);
		},
		[grid, variable],
	);

	const fit = useCallback(
		(next: number) =>
			fitColumn(next, {
				min,
				max,
				windowWidth: window.innerWidth,
				reserved: readColumn(
					grid,
					spec.sibling ?? "",
					window.innerWidth,
				),
			}),
		[grid, min, max, spec.sibling],
	);

	const remember = useCallback(
		(next: number) => {
			try {
				localStorage.setItem(storageKey, String(next));
			} catch {
				/* storage unavailable: the width just will not persist */
			}
		},
		[storageKey],
	);

	// The starting width follows the window, and a remembered width is the
	// analyst's own, bounded by that same window.
	useLayoutEffect(() => {
		const apply = () => {
			let next = initial(window.innerWidth);
			try {
				const saved = Number(localStorage.getItem(storageKey));
				if (Number.isFinite(saved) && saved > 0) next = saved;
			} catch {
				/* storage unavailable: the measured width is fine */
			}
			const fitted = fit(next);
			setWidth(fitted);
			paint(fitted);
		};
		apply();
		window.addEventListener("resize", apply);
		return () => window.removeEventListener("resize", apply);
	}, [fit, paint, initial, storageKey]);

	/**
	 * The width a drag at `clientX` asks for, in this column's direction.
	 *
	 * Measured against the grid rather than the panel: a column is flush to one
	 * edge of the grid — the sidebar to its left, the chat to its right — so the
	 * two share the same edges, and the grid is a value the caller already has.
	 * A divider that needed a ref to its own panel to find its own edge would be
	 * a divider that could not answer a drag before it had been mounted.
	 *
	 * A drag reuses the edges captured when it began. Measuring per move would
	 * interleave a read with the write `paint` makes and force the browser to
	 * lay the whole grid out again between every frame, which is the one thing
	 * a sixty-hertz drag cannot afford.
	 */
	const fromPointer = useCallback(
		(clientX: number): number | null => {
			const box = origin.current ?? grid?.getBoundingClientRect();
			if (!box) return null;
			return fit(
				side === "start" ? clientX - box.left : box.right - clientX,
			);
		},
		[fit, grid, side],
	);

	// Memoised, and stably, because these are handed straight to the divider: a
	// handler rebuilt on every render would re-bind the pointer capture the
	// divider is holding mid-drag.
	const onPointerDown = useCallback(
		(event: ReactPointerEvent<HTMLDivElement>) => {
			if (event.button !== 0) return;
			// Suppressed for the whole drag: a divider dragged across the panel would
			// otherwise select every row of text it passed over.
			event.preventDefault();
			beginDragSuppressSelect("col");
			dragging.current = true;
			// The line stays lit for the whole drag: the pointer leaves the handle
			// constantly, and a divider that blinks out mid-drag looks broken.
			event.currentTarget.dataset.dragging = "true";
			event.currentTarget.setPointerCapture(event.pointerId);
			handleEl.current = event.currentTarget;
		},
		[],
	);

	const onPointerMove = useCallback(
		(event: ReactPointerEvent<HTMLDivElement>) => {
			if (!dragging.current) return;
			origin.current ??= grid?.getBoundingClientRect() ?? null;
			const next = fromPointer(event.clientX);
			if (next !== null) paint(next);
		},
		[fromPointer, grid, paint],
	);

	const onPointerUp = useCallback(
		(event: ReactPointerEvent<HTMLDivElement>) => {
			if (!dragging.current) return;
			dragging.current = false;
			origin.current = null;
			endDragSuppressSelect("col");
			if (handleEl.current) delete handleEl.current.dataset.dragging;
			if (event.currentTarget.hasPointerCapture(event.pointerId)) {
				event.currentTarget.releasePointerCapture(event.pointerId);
			}
			// Committed once the drag ends, so the handle's accessible value and the
			// remembered width both change when the analyst lets go.
			const next = fromPointer(event.clientX) ?? width;
			setWidth(next);
			paint(next);
			remember(next);
		},
		[fromPointer, paint, remember, width],
	);

	// A drag that ends off the handle — released over the window, or the element
	// unmounted mid-drag — would leave the flag set and the next move would jump.
	useEffect(() => {
		const stop = () => {
			if (!dragging.current) return;
			dragging.current = false;
			origin.current = null;
			// A drag released off the handle leaves the line lit otherwise, and a
			// divider that stays highlighted looks stuck.
			if (handleEl.current) delete handleEl.current.dataset.dragging;
			endDragSuppressSelect("col");
		};
		window.addEventListener("pointerup", stop);
		window.addEventListener("pointercancel", stop);
		return () => {
			window.removeEventListener("pointerup", stop);
			window.removeEventListener("pointercancel", stop);
		};
	}, []);

	const nudge = useCallback(
		(next: number) => {
			const fitted = fit(next);
			paint(fitted);
			setWidth(fitted);
			remember(fitted);
		},
		[fit, paint, remember],
	);

	const onKeyDown = useCallback(
		(event: ReactKeyboardEvent<HTMLDivElement>) => {
			const step = event.shiftKey ? DRAG_STEP_COARSE : DRAG_STEP;
			// A column on the leading edge grows as the arrow moves away from it.
			const wider = side === "start" ? "ArrowRight" : "ArrowLeft";
			const narrower = side === "start" ? "ArrowLeft" : "ArrowRight";
			if (event.key === wider) {
				event.preventDefault();
				nudge(width + step);
			} else if (event.key === narrower) {
				event.preventDefault();
				nudge(width - step);
			} else if (event.key === "Home") {
				event.preventDefault();
				nudge(min);
			} else if (event.key === "End") {
				event.preventDefault();
				nudge(max);
			} else if (event.key === "Enter" || event.key === " ") {
				event.preventDefault();
				nudge(initial(window.innerWidth));
			}
		},
		[initial, max, min, nudge, side, width],
	);

	const onDoubleClick = useCallback(
		() => nudge(initial(window.innerWidth)),
		[initial, nudge],
	);

	return {
		width,
		divider: {
			role: "separator" as const,
			"aria-orientation": "vertical" as const,
			"aria-label": `Resize the ${key}`,
			"aria-valuenow": Math.round(width),
			"aria-valuemin": min,
			"aria-valuemax": max,
			tabIndex: 0,
			title: `Drag to resize the ${key} — double-click to reset`,
			// The grab area is 4px and the line inside it is 1px: see `chrome.css`.
			className: `${chrome.colDivider} w-1 shrink-0 cursor-col-resize`,
			onPointerDown,
			onPointerMove,
			onPointerUp,
			onKeyDown,
			onDoubleClick,
		},
	};
}
