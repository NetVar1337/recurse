import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { chrome } from "./chrome";
import { THEMES } from "./themes";

const css = readFileSync(new URL("../chrome.css", import.meta.url), "utf8");

describe("chrome tokens", () => {
	it("exports class names that exist in chrome.css", () => {
		for (const name of Object.values(chrome)) {
			expect(css).toContain(`.${name}`);
		}
	});

	it("defines the shared control tokens", () => {
		for (const token of [
			"--selection",
			"--past-foreground",
			"--taken",
			"--fall",
			"--control-h",
			"--chrome-h",
			"--radius-control",
			"--space-1",
			"--space-2",
			"--space-3",
			"--kbd",
			"--warning",
		]) {
			expect(css).toContain(token);
		}
	});

	it("defines the debugger's branch and context colours for every theme", () => {
		// These live in themes.css now, one block per palette, so this reads them
		// from there. The check that matters is that each theme defines each one:
		// a palette that omitted `--taken` would silently fall back to the default
		// theme's green, which is the kind of wrong answer nothing else reports.
		const themes = readFileSync(
			new URL("../themes.css", import.meta.url),
			"utf8",
		);
		const blocks = [
			...themes.matchAll(/\[data-theme="[^"]+"\]\s*\{([^}]*)\}/g),
		];
		expect(blocks).toHaveLength(THEMES.length);
		for (const [, body] of blocks) {
			for (const token of ["--past-foreground:", "--taken:", "--fall:"]) {
				expect(body).toContain(token);
			}
		}
	});
});
