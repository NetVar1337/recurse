import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Node has no localStorage; settingsStore reads it at module init.
const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
	getItem: (k: string) => store.get(k) ?? null,
	setItem: (k: string, v: string) => void store.set(k, v),
	removeItem: (k: string) => void store.delete(k),
});

vi.mock("../api", () => ({
	api: {
		agentChat: vi.fn(),
		agentHistory: vi.fn().mockResolvedValue([]),
		agentReset: vi.fn().mockResolvedValue(undefined),
	},
}));

import { Channel } from "@tauri-apps/api/core";

import { api } from "../api";
import { useAgentStore, type UiBlock, type UiMessage } from "./agentStore";
import { useSessionStore } from "./sessionStore";
import { deliverTauriCallback } from "../../vitest.setup";

const mockedChat = vi.mocked(api.agentChat);

/** The channel a `send` built, so a test can answer it as the host would. */
function lastChannel(): Channel<unknown> {
	const calls = mockedChat.mock.calls;
	const call = calls[calls.length - 1];
	if (!call) throw new Error("no agentChat call was made");
	return call[2] as unknown as Channel<unknown>;
}

/** Deliver a stream event through the channel the store registered. */
function emit(ev: unknown): void {
	deliverTauriCallback(lastChannel().id, ev);
}

/** The assistant message a `send` opened, which is the one being streamed into. */
function streaming(): UiMessage {
	const messages = useAgentStore.getState().messages;
	const last = messages[messages.length - 1];
	if (!last || last.role !== "assistant")
		throw new Error("no assistant turn");
	return last;
}

function lastAssistantText(): string {
	return streaming()
		.blocks.map((b: UiBlock) => (b.kind === "content" ? b.text : ""))
		.join("");
}

function token(run: string, text: string): unknown {
	return { kind: "token", run_id: run, delta: text };
}

function deferred<T>() {
	let resolve!: (v: T) => void;
	const promise = new Promise<T>((r) => (resolve = r));
	return { promise, resolve };
}

describe("agentStore streamed events", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		mockedChat.mockReset();
		mockedChat.mockResolvedValue(undefined);
		useSessionStore.setState({ current: null, sessions: [] });
		useAgentStore.setState({
			messages: [],
			busy: false,
			activeSessionId: null,
			activeRunId: null,
		});
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("holds streamed tokens until a frame passes", async () => {
		void useAgentStore.getState().send("hi");
		await vi.advanceTimersByTimeAsync(0);

		emit(token("r1", "he"));
		emit(token("r1", "llo"));

		// Nothing is committed mid-stream: the whole point is one render per
		// frame rather than one per token.
		expect(lastAssistantText()).toBe("");

		await vi.advanceTimersByTimeAsync(200);
		expect(lastAssistantText()).toBe("hello");
	});

	it("keeps a run's events in the order the host sent them", async () => {
		void useAgentStore.getState().send("hi");
		await vi.advanceTimersByTimeAsync(0);

		emit({ kind: "tool_call", run_id: "r1", id: "c1", name: "disasm" });
		emit({ kind: "tool_result", run_id: "r1", id: "c1", result: "mov a" });
		emit(token("r1", "done"));
		await vi.advanceTimersByTimeAsync(200);

		const blocks = streaming().blocks;
		// A result committed before its call would leave the card permanently
		// "running", so order is the thing being pinned down here.
		expect(blocks.map((b: UiBlock) => b.kind)).toEqual([
			"tool_call",
			"content",
		]);
		const call = blocks[0];
		expect(call.kind === "tool_call" && call.call.result).toBe("mov a");
	});

	it("commits a terminal event even with no frame left to come", async () => {
		// The host's call resolves only once it has finished sending, which is
		// the real ordering: stream first, resolve second.
		const call = deferred<void>();
		mockedChat.mockReturnValue(call.promise as never);
		void useAgentStore.getState().send("hi");
		await vi.advanceTimersByTimeAsync(0);

		emit(token("r1", "hi"));
		emit({ kind: "done", run_id: "r1", content: "hi" });
		call.resolve();
		await vi.advanceTimersByTimeAsync(0);

		expect(useAgentStore.getState().busy).toBe(false);
		expect(useAgentStore.getState().activeRunId).toBeNull();
		expect(lastAssistantText()).toBe("hi");
	});

	it("does not resurrect a run the analyst has left", async () => {
		const call = deferred<void>();
		mockedChat.mockReturnValue(call.promise as never);
		void useAgentStore.getState().send("hi", undefined, "s1");
		await vi.advanceTimersByTimeAsync(0);

		emit(token("r1", "a"));
		await vi.advanceTimersByTimeAsync(200);
		expect(lastAssistantText()).toBe("a");

		// The analyst moves to another session; the run keeps streaming, but into
		// a transcript nobody is reading.
		useAgentStore.setState({ activeSessionId: "s2" });
		emit(token("r1", "b"));
		await vi.advanceTimersByTimeAsync(200);
		expect(lastAssistantText()).toBe("a");
		call.resolve();
		await vi.advanceTimersByTimeAsync(0);
	});

	it("reports a failed request without leaving the transcript pending", async () => {
		mockedChat.mockRejectedValue(new Error("host gone"));
		await useAgentStore.getState().send("hi");

		const last = streaming();
		expect(last.pending).toBe(false);
		expect(last.error).toContain("host gone");
		expect(useAgentStore.getState().busy).toBe(false);
	});

	it("commits a burst of tokens as one change, not one per token", async () => {
		void useAgentStore.getState().send("hi");
		await vi.advanceTimersByTimeAsync(0);

		const seen: unknown[] = [];
		const unsub = useAgentStore.subscribe((s) => seen.push(s.messages));
		for (const word of ["one ", "two ", "three ", "four ", "five"]) {
			emit(token("r1", word));
		}
		await vi.advanceTimersByTimeAsync(200);
		unsub();

		// Five tokens, one new array. One per token is a re-render of the whole
		// transcript each time, which is what makes a stream stutter.
		expect(seen).toHaveLength(1);
		expect(lastAssistantText()).toBe("one two three four five");
	});
});
