import { create } from "zustand";

import { api } from "../api";
import type { Backend } from "../types";

const KEY = "recurse.zoomLevel";
const BACKEND_KEY = "recurse.backend";
const MIN = -5;
const MAX = 8;

function scaleFor(level: number): number {
	return Math.pow(1.2, level);
}

interface SettingsState {
	zoomLevel: number;
	backend: Backend;
	initZoom: () => Promise<void>;
	zoomIn: () => Promise<void>;
	zoomOut: () => Promise<void>;
	resetZoom: () => Promise<void>;
	initBackend: () => Promise<void>;
	setBackend: (backend: Backend) => Promise<void>;
}

function readInitialBackend(): Backend {
	const v = localStorage.getItem(BACKEND_KEY);
	return v === "native" ? "native" : "r2";
}

function readInitial(): number {
	const v = Number(localStorage.getItem(KEY));
	if (!Number.isFinite(v)) return 0;
	return Math.min(MAX, Math.max(MIN, Math.round(v)));
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
	zoomLevel: readInitial(),
	backend: readInitialBackend(),

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
		set({ backend });
		localStorage.setItem(BACKEND_KEY, backend);
		try {
			await api.setBackend(backend);
		} catch {
			/* non-fatal: takes effect on next launch */
		}
	},
}));
