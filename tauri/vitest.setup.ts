// Node has no localStorage; settingsStore reads it at import time.
const store = new Map<string, string>();
globalThis.localStorage = {
	getItem: (k: string) => store.get(k) ?? null,
	setItem: (k: string, v: string) => void store.set(k, v),
	removeItem: (k: string) => void store.delete(k),
	clear: () => void store.clear(),
} as Storage;

/**
 * Tauri's callback registry, which only exists inside a real window.
 *
 * A `Channel` registers its handler here and the host calls back through it, so
 * a stub is what lets a test both build a channel and deliver a message the way
 * the host would — the only way to check that the event plumbing is wired to
 * something the host can actually answer.
 */
type IpcCallback = (payload: unknown) => void;
const ipcCallbacks = new Map<number, IpcCallback>();
/**
 * How many messages each channel has been sent.
 *
 * A `Channel` drops a message whose index is not the one it expects next, so the
 * host's per-channel counter has to be reproduced here or every message after
 * the first would be silently discarded.
 */
const ipcMessageIndex = new Map<number, number>();
let nextCallbackId = 1;

globalThis.window = {
	__TAURI_INTERNALS__: {
		transformCallback(callback: IpcCallback, once?: boolean) {
			const id = nextCallbackId++;
			if (once) {
				ipcCallbacks.set(id, (payload) => {
					ipcCallbacks.delete(id);
					callback(payload);
				});
			} else {
				ipcCallbacks.set(id, callback);
			}
			return id;
		},
	},
} as unknown as Window & typeof globalThis;

/**
 * Deliver a message to the callback a channel registered, as the host does.
 *
 * @param id - The channel's id.
 * @param message - The message the host would have sent.
 */
export function deliverTauriCallback(id: number, message: unknown): void {
	const index = ipcMessageIndex.get(id) ?? 0;
	ipcMessageIndex.set(id, index + 1);
	ipcCallbacks.get(id)?.({ index, message });
}
