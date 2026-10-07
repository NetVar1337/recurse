import { create } from "zustand";

import { api } from "../api";
import {
	DEFAULT_THEME,
	isLightTheme,
	resolveTheme,
	themeById,
} from "../lib/themes";
import type { Backend } from "../types";
import { useAnalysisStore } from "./analysisStore";
import { useBinaryStore } from "./binaryStore";
import { useUiStore } from "./uiStore";

const KEY = "recurse.zoomLevel";
const BACKEND_KEY = "recurse.backend";
const THEME_KEY = "recurse.theme";
const DEBUG_CONTEXT_KEY = "recurse.debugContext";
const MIN = -5;
const MAX = 8;

/** Fewest instructions of context the CPU view will keep above the cursor. */
export const DEBUG_CONTEXT_MIN = 0;

/** Most the CPU view will keep, bounding both the rows and the scrollback. */
export const DEBUG_CONTEXT_MAX = 20;

/** Instructions of context shown when nothing has been configured. */
export const DEBUG_CONTEXT_DEFAULT = 5;

/**
 * Calculates the zoom scale multiplier for a given integer zoom level.
 *
 * @param level - The integer zoom level.
 * @returns The scale multiplier factor.
 */
function scaleFor(level: number): number {
	return Math.pow(1.2, level);
}

/** The id of the applied theme, e.g. `recurse-dark` or `tokyo-night`. */
export type ThemeId = string;

interface SettingsState {
	zoomLevel: number;
	backend: Backend;
	/** The id of the theme in force; see THEMES in src/lib/themes.ts. */
	theme: ThemeId;
	/**
	 * How many instructions of context the debugger CPU view keeps above the
	 * program counter.
	 *
	 * Those rows are the code leading into the cursor, not a record of what ran:
	 * a debugger only observes the program between stops, and a row at a lower
	 * address is not a row that executed. Where the run really came from is
	 * shown by peeking the branch the cursor is on, which needs no setting.
	 */
	debugContext: number;
	initZoom: () => Promise<void>;
	zoomIn: () => Promise<void>;
	zoomOut: () => Promise<void>;
	resetZoom: () => Promise<void>;
	initBackend: () => Promise<void>;
	setBackend: (backend: Backend) => Promise<void>;
	initTheme: () => void;
	toggleTheme: () => void;
	setTheme: (theme: ThemeId) => void;
	setDebugContext: (n: number) => void;
	nudgeDebugContext: (delta: number) => void;
	resetDebugContext: () => void;
}

/**
 * Reads the initially configured backend from localStorage.
 *
 * @returns The initial Backend identifier ('native', 'r2', or 'ida').
 */
function readInitialBackend(): Backend {
	const v = localStorage.getItem(BACKEND_KEY);
	return v === "r2" || v === "ida" ? v : "native";
}

/**
 * Reads the initial zoom level from localStorage.
 *
 * @returns Clamped integer zoom level between MIN and MAX.
 */
function readInitial(): number {
	const v = Number(localStorage.getItem(KEY));
	if (!Number.isFinite(v)) return 0;
	return Math.min(MAX, Math.max(MIN, Math.round(v)));
}

/**
 * Reads the initial theme from localStorage, or from the system when nothing has
 * been chosen.
 *
 * A stored value of `light` or `dark` is a choice this app made before it had
 * named themes, and it is read as the Recurse theme of that handedness rather
 * than discarded. Reinterpreting it keeps the reader on the side of the light
 * they asked for; writing a fresh default over it would answer a question they
 * had already answered, in the one setting where doing that is least forgivable.
 *
 * @returns The id of the theme to apply.
 */
export function readInitialTheme(): string {
	const v = localStorage.getItem(THEME_KEY);
	// Already a named theme.
	if (themeById(v)) return v as string;
	// The old two-valued setting, migrated to the matching Recurse theme.
	if (v === "light") return "recurse-light";
	if (v === "dark") return "recurse-dark";
	// Nothing stored, or something unreadable: follow the system, so a reader
	// who has never opened the settings still gets a theme they can read.
	if (typeof window !== "undefined" && window.matchMedia) {
		return window.matchMedia("(prefers-color-scheme: light)").matches
			? "recurse-light"
			: DEFAULT_THEME;
	}
	return DEFAULT_THEME;
}

/**
 * Clamp a debugger context depth into the supported range.
 *
 * A non-finite depth is treated as unset and resolves to the default rather than
 * to a bound: a `NaN` or `Infinity` reaching here means a corrupt stored value,
 * and "no usable preference" has a better answer than "pin to an extreme".
 *
 * @param n - Requested number of instructions of context.
 * @returns The depth, rounded and bounded to [DEBUG_CONTEXT_MIN, DEBUG_CONTEXT_MAX],
 * or DEBUG_CONTEXT_DEFAULT when `n` is not finite.
 */
export function clampDebugContext(n: number): number {
	if (!Number.isFinite(n)) return DEBUG_CONTEXT_DEFAULT;
	return Math.min(
		DEBUG_CONTEXT_MAX,
		Math.max(DEBUG_CONTEXT_MIN, Math.round(n)),
	);
}

/**
 * Reads the initial debugger context depth from localStorage.
 *
 * @returns The saved depth, or DEBUG_CONTEXT_DEFAULT when unset or invalid.
 */
function readInitialDebugContext(): number {
	const raw = localStorage.getItem(DEBUG_CONTEXT_KEY);
	// Read as null first: `Number(null)` is 0, and 0 is a depth the user can
	// legitimately choose, so it cannot double as "nothing stored".
	if (raw === null) return DEBUG_CONTEXT_DEFAULT;
	const v = Number(raw);
	return Number.isFinite(v) ? clampDebugContext(v) : DEBUG_CONTEXT_DEFAULT;
}

/**
 * Applies a theme to the document.
 *
 * Two things are written, and they are not redundant. `data-theme` selects the
 * palette, and is the only thing a theme needs. The `dark` class is kept because
 * `dark:invert-0` on the logo and the `@custom-variant dark` both key off it, so
 * a light theme that left it off would draw the logo the wrong way round.
 *
 * An id that is not a shipped theme is refused rather than written: a theme with
 * no palette behind it resolves every token to nothing, and the window comes up
 * with no colours at all instead of with the wrong ones.
 *
 * @param id - The theme to apply. Anything unrecognised falls back to the default.
 */
function applyTheme(id: string) {
	if (typeof document === "undefined") return;
	const theme = resolveTheme(id);
	const root = document.documentElement;
	root.dataset.theme = theme.id;
	root.classList.toggle("dark", !theme.light);
	// The window's own scrollbars and form controls follow this, and it is what
	// `color-scheme` in each theme block would set anyway; assigning it here means
	// a theme that forgot the declaration still gets correct native controls.
	root.style.colorScheme = theme.light ? "light" : "dark";
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
	zoomLevel: readInitial(),
	backend: readInitialBackend(),
	theme: readInitialTheme(),
	debugContext: readInitialDebugContext(),

	initZoom: async () => {
		try {
			await api.setZoom(scaleFor(get().zoomLevel));
		} catch {
			/* non-fatal */
		}
	},

	zoomIn: async () => {
		const z = Math.min(MAX, get().zoomLevel + 1);
		set({ zoomLevel: z });
		localStorage.setItem(KEY, String(z));
		try {
			await api.setZoom(scaleFor(z));
		} catch {
			/* non-fatal */
		}
	},

	zoomOut: async () => {
		const z = Math.max(MIN, get().zoomLevel - 1);
		set({ zoomLevel: z });
		localStorage.setItem(KEY, String(z));
		try {
			await api.setZoom(scaleFor(z));
		} catch {
			/* non-fatal */
		}
	},

	resetZoom: async () => {
		localStorage.removeItem(KEY);
		set({ zoomLevel: 0 });
		try {
			await api.setZoom(1);
		} catch {
			/* non-fatal */
		}
	},

	initBackend: async () => {
		try {
			const { backend } = await api.getBackend();
			set({ backend });
			localStorage.setItem(BACKEND_KEY, backend);
		} catch {
			/* non-fatal: keep the local value */
		}
	},

	setBackend: async (backend: Backend) => {
		const prevBackend = get().backend;
		try {
			await api.setBackend(backend);
			useAnalysisStore.getState().clearDecompiled();
			const currentBinary = useBinaryStore.getState().binary;
			if (currentBinary?.path) {
				const prevSelected = useAnalysisStore.getState().selected;
				const currentTab = useUiStore.getState().tab;
				await useBinaryStore.getState().openBinary(currentBinary.path);
				if (currentTab) {
					useUiStore.getState().setTab(currentTab);
				}
				if (prevSelected) {
					const funcs = useAnalysisStore.getState().funcs;
					const match = funcs.find(
						(f) =>
							f.addr === prevSelected.addr ||
							f.name === prevSelected.name,
					);
					if (match) {
						useAnalysisStore.getState().selectFn(match);
					}
				}
			}
			set({ backend });
			localStorage.setItem(BACKEND_KEY, backend);
		} catch (e) {
			useUiStore.getState().setErr(String(e));
			set({ backend: prevBackend });
			localStorage.setItem(BACKEND_KEY, prevBackend);
			await api.setBackend(prevBackend).catch(() => {});
		}
	},

	initTheme: () => {
		applyTheme(get().theme);
	},

	toggleTheme: () => {
		// Toggle by handedness, not by name: from Tokyo Night this lands on
		// Recurse Light, which is the other side of the same switch. Stepping
		// through the twelve in order would make a two-press shortcut a
		// twelve-press one and a second press land nowhere near the inverse.
		const next = isLightTheme(get().theme)
			? "recurse-dark"
			: "recurse-light";
		set({ theme: next });
		localStorage.setItem(THEME_KEY, next);
		applyTheme(next);
	},

	setTheme: (theme: ThemeId) => {
		const resolved = resolveTheme(theme);
		set({ theme: resolved.id });
		localStorage.setItem(THEME_KEY, resolved.id);
		applyTheme(resolved.id);
	},

	setDebugContext: (n: number) => {
		const depth = clampDebugContext(n);
		set({ debugContext: depth });
		localStorage.setItem(DEBUG_CONTEXT_KEY, String(depth));
	},

	nudgeDebugContext: (delta: number) => {
		get().setDebugContext(get().debugContext + delta);
	},

	resetDebugContext: () => {
		localStorage.removeItem(DEBUG_CONTEXT_KEY);
		set({ debugContext: DEBUG_CONTEXT_DEFAULT });
	},
}));

// Applied at import time (before first paint in practice) rather than only
// from a React effect, so a saved light-mode preference never flashes dark
// first. index.html still hardcodes class="dark" as the no-JS fallback.
applyTheme(readInitialTheme());
