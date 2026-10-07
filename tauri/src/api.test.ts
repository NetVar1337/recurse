import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("@tauri-apps/api/core")>();
	return { ...actual, invoke: vi.fn() };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

import { Channel, invoke } from "@tauri-apps/api/core";
import { api } from "./api";
import type { DebugEvent } from "./types";

/** The arguments of the last call to a command. */
function argsFor(command: string): Record<string, unknown> | undefined {
	const call = vi
		.mocked(invoke)
		.mock.calls.find(([name]) => name === command);
	return call?.[1] as Record<string, unknown> | undefined;
}

describe("debugSubscribe", () => {
	beforeEach(() => {
		vi.mocked(invoke).mockReset();
		vi.mocked(invoke).mockResolvedValue(undefined);
	});

	/**
	 * The host declares this argument as `tauri::ipc::Channel<Envelope>` and the
	 * ipc layer deserializes it as one, so the object the caller built has to
	 * reach the command untouched: wrapped in a closure, or renamed on the way
	 * over, the call rejects and nothing is ever pushed.
	 *
	 * The caller-side half of this contract — building a channel at all rather
	 * than a bare callback — is checked in `debugStore.test.ts`.
	 */
	it("hands the host the channel, under the name the host declares", async () => {
		const channel = new Channel<DebugEvent>();
		channel.onmessage = () => {};

		await api.debugSubscribe(channel);

		const args = argsFor("debug_subscribe");
		expect(args?.onEvent).toBe(channel);
		expect(args?.onEvent).toBeInstanceOf(Channel);
	});
});
