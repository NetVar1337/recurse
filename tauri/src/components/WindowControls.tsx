import { getCurrentWindow } from "@tauri-apps/api/window";
import { useEffect, useState } from "react";

import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";

/**
 * The window's own buttons, because the app draws its own title bar.
 *
 * With the native one gone the window still has to be closable, minimisable and
 * restorable, and the corners of the screen are where a reader expects to find
 * them — so they sit in the top right of the header, in the order and the
 * familiar widths every other window on the platform uses.
 *
 * A drag region fills the space to their left, so the bar is a title bar: click
 * and drag anywhere on it to move the window, and double-click to maximise.
 *
 * @example
 * <WindowControls />
 */
export function WindowControls() {
	const win = getCurrentWindow();
	const [maximised, setMaximised] = useState(false);

	useEffect(() => {
		void win
			.isMaximized()
			.then(setMaximised)
			.catch(() => setMaximised(false));
	}, [win]);

	/**
	 * Maximise, or put the window back the way it was.
	 *
	 * Toggling rather than always maximising: a reader who maximises to read a
	 * wide listing wants to get their own layout back without finding the taskbar.
	 */
	const toggleMaximise = () => {
		void (maximised ? win.unmaximize() : win.maximize())
			.then(() => win.isMaximized())
			.then(setMaximised)
			.catch(() => setMaximised(false));
	};

	return (
		<div className={chrome.windowControls} data-tauri-drag-region>
			<button
				type="button"
				className={chrome.windowButton}
				title="Minimise"
				aria-label="Minimise"
				onClick={() => void win.minimize()}
			>
				<Minimize />
			</button>
			<button
				type="button"
				className={chrome.windowButton}
				title={maximised ? "Restore" : "Maximise"}
				aria-label={maximised ? "Restore" : "Maximise"}
				onClick={toggleMaximise}
			>
				<Maximize restored={maximised} />
			</button>
			<button
				type="button"
				className={cn(chrome.windowButton, chrome.windowClose)}
				title="Close"
				aria-label="Close"
				onClick={() => void win.close()}
			>
				<Close />
			</button>
		</div>
	);
}

/** A minimise glyph: one hairline rule, as wide as the others. */
function Minimize() {
	return (
		<svg
			width="10"
			height="10"
			viewBox="0 0 10 10"
			aria-hidden
			focusable="false"
		>
			<path
				d="M1 5 H9"
				stroke="currentColor"
				strokeWidth="1"
				strokeLinecap="square"
			/>
		</svg>
	);
}

/**
 * A maximise glyph, and a restore glyph when the window is already maximised.
 *
 * The restore is the maximise with a second box behind it, which is what makes it
 * read as "put it back" rather than as a second maximise.
 */
function Maximize({ restored }: { restored: boolean }) {
	return (
		<svg
			width="10"
			height="10"
			viewBox="0 0 10 10"
			aria-hidden
			focusable="false"
		>
			<rect
				x="1.5"
				y={restored ? "3.5" : "1.5"}
				width="7"
				height="5"
				fill="none"
				stroke="currentColor"
				strokeWidth="1"
			/>
			{restored && (
				<path
					d="M3.5 3.5 V1.5 H8.5 V6.5 H6.5"
					fill="none"
					stroke="currentColor"
					strokeWidth="1"
				/>
			)}
		</svg>
	);
}

/** A close glyph: the one mark that means the same thing everywhere. */
function Close() {
	return (
		<svg
			width="10"
			height="10"
			viewBox="0 0 10 10"
			aria-hidden
			focusable="false"
		>
			<path
				d="M2 2 L8 8 M8 2 L2 8"
				stroke="currentColor"
				strokeWidth="1"
				strokeLinecap="square"
			/>
		</svg>
	);
}
