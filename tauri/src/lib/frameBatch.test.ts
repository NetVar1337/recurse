import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFrameBatch } from "./frameBatch";

describe("createFrameBatch", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("commits nothing until a frame passes", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		expect(apply).not.toHaveBeenCalled();
	});

	it("commits everything queued in one go, in push order", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		batch.push("b");
		batch.push("c");
		vi.runAllTimers();
		expect(apply).toHaveBeenCalledTimes(1);
		expect(apply).toHaveBeenCalledWith(["a", "b", "c"]);
	});

	it("commits once per frame, not once per push", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		vi.runAllTimers();
		batch.push("b");
		batch.push("c");
		vi.runAllTimers();
		expect(apply).toHaveBeenCalledTimes(2);
		expect(apply).toHaveBeenNthCalledWith(1, ["a"]);
		expect(apply).toHaveBeenNthCalledWith(2, ["b", "c"]);
	});

	it("commits on flush without waiting for the frame", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		batch.push("b");
		batch.flush();
		expect(apply).toHaveBeenCalledTimes(1);
		expect(apply).toHaveBeenCalledWith(["a", "b"]);
	});

	it("does not commit twice when a frame lands after a flush", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		batch.flush();
		vi.runAllTimers();
		expect(apply).toHaveBeenCalledTimes(1);
	});

	it("flushing an empty batch calls nothing", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.flush();
		expect(apply).not.toHaveBeenCalled();
	});

	it("reports what is waiting", () => {
		const batch = createFrameBatch<string>(vi.fn());
		expect(batch.size).toBe(0);
		batch.push("a");
		batch.push("b");
		expect(batch.size).toBe(2);
		batch.flush();
		expect(batch.size).toBe(0);
	});

	it("discards a dropped batch rather than committing it late", () => {
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		batch.drop();
		vi.runAllTimers();
		expect(apply).not.toHaveBeenCalled();
		expect(batch.size).toBe(0);
	});

	it("gives a re-pushing apply its own buffer, not the one being read", () => {
		const seen: string[][] = [];
		const batch = createFrameBatch<string>((items) => {
			seen.push([...items]);
			// An apply that pushes again must not append into the array it was
			// handed, or the next commit would replay what it already saw.
			if (items[0] === "a") batch.push("b");
		});
		batch.push("a");
		batch.flush();
		expect(seen).toEqual([["a"]]);
		batch.flush();
		expect(seen).toEqual([["a"], ["b"]]);
	});

	it("commits on a frame when the host provides one", () => {
		// An occluded window still gets no frames, which is why the timer is a
		// floor; but when a frame does arrive it is the one that should commit.
		const callbacks: FrameRequestCallback[] = [];
		vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
			callbacks.push(cb);
			return callbacks.length;
		});
		vi.stubGlobal("cancelAnimationFrame", vi.fn());
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		batch.push("b");
		expect(apply).not.toHaveBeenCalled();
		for (const cb of callbacks) cb(0);
		expect(apply).toHaveBeenCalledExactlyOnceWith(["a", "b"]);
		vi.unstubAllGlobals();
	});

	it("still commits when frames never come", () => {
		// A hidden window stops being given frames entirely. The timer is what
		// keeps a stream from stalling behind one.
		vi.stubGlobal("requestAnimationFrame", vi.fn());
		const apply = vi.fn();
		const batch = createFrameBatch<string>(apply);
		batch.push("a");
		vi.runAllTimers();
		expect(apply).toHaveBeenCalledExactlyOnceWith(["a"]);
		vi.unstubAllGlobals();
	});
});
