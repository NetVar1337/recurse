import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
	DEFAULT_THEME,
	isLightTheme,
	resolveTheme,
	TEN,
	themeById,
	THEMES,
	themesOf,
} from "./themes";

const css = readFileSync(new URL("../themes.css", import.meta.url), "utf8");

/** The `[data-theme="…"]` blocks in themes.css, keyed by id. */
function blocks(): Map<string, string> {
	const out = new Map<string, string>();
	const re = /\[data-theme="([^"]+)"\]\s*\{([^}]*)\}/g;
	for (let m = re.exec(css); m; m = re.exec(css)) out.set(m[1], m[2]);
	return out;
}

/**
 * The selectors of every rule block that names this theme.
 *
 * Matched across newlines on purpose: the default's selector is written as a
 * `:root,` line and its `[data-theme]` line, because a grouped selector that
 * fitted on one line would be 90 characters of it.
 */
function blocksNaming(id: string): string[] {
	const re = new RegExp(
		`((?:[^\\n{]|\\n)*?\\[data-theme="${id}"\\](?:[^\\n{]|\\n)*?)\\s*\\{`,
		"g",
	);
	const out: string[] = [];
	for (let m = re.exec(css); m; m = re.exec(css)) {
		out.push(m[1].replace(/\s+/g, " ").trim());
	}
	return out;
}

describe("themes", () => {
	it("ships ten themes, and they are ten distinct ids", () => {
		expect(THEMES).toHaveLength(TEN);
		expect(new Set(THEMES.map((t) => t.id)).size).toBe(TEN);
	});

	it("names every theme for the menu and gives each a label", () => {
		for (const theme of THEMES) {
			expect(theme.id).toMatch(/^[a-z][a-z0-9-]*$/);
			expect(theme.label.length).toBeGreaterThan(0);
		}
	});

	it("gives every theme three swatches that are real colours", () => {
		for (const theme of THEMES) {
			expect(theme.swatches).toHaveLength(3);
			for (const s of theme.swatches) {
				expect(s).toMatch(/^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i);
			}
		}
	});

	it("says of each theme whether it is a light one, and lists them accordingly", () => {
		const light = THEMES.filter((t) => t.light).map((t) => t.id);
		expect(light.length).toBeGreaterThan(0);
		expect(light.length).toBeLessThan(THEMES.length);
		expect(themesOf(true).map((t) => t.id)).toEqual(light);
		expect(themesOf(false).map((t) => t.id)).toEqual(
			THEMES.filter((t) => !t.light).map((t) => t.id),
		);
		// Both sides of the switch have to exist, or the toggle has nowhere to go.
		expect(themeById(light[0])).toBeDefined();
		expect(themeById(THEMES.find((t) => !t.light)!.id)).toBeDefined();
	});

	it("resolves a known id to that theme and an unknown one to the default", () => {
		expect(resolveTheme("dracula").id).toBe("dracula");
		expect(resolveTheme("nope").id).toBe(DEFAULT_THEME);
		expect(resolveTheme(undefined).id).toBe(DEFAULT_THEME);
		expect(resolveTheme(null).id).toBe(DEFAULT_THEME);
		// An unknown id is not a reason to leave the reader without a palette.
		expect(themeById("nope")).toBeUndefined();
	});

	it("reports an unknown theme as dark, so the logo inverts rather than vanishing", () => {
		expect(isLightTheme("solarized-light")).toBe(true);
		expect(isLightTheme("recurse-dark")).toBe(false);
		expect(isLightTheme("nope")).toBe(false);
	});

	describe("the stylesheet and the registry agree", () => {
		// The colours live in CSS and the names in TypeScript, so nothing but a
		// test stops the two from drifting: a theme listed in one and absent from
		// the other is a row in the menu that paints nothing.
		it("has a CSS block for every theme in the registry", () => {
			const b = blocks();
			for (const theme of THEMES) {
				expect(
					b.has(theme.id),
					`no [data-theme] block for ${theme.id}`,
				).toBe(true);
			}
		});

		it("has no CSS block for a theme the registry does not list", () => {
			const known = new Set(THEMES.map((t) => t.id));
			for (const id of blocks().keys()) {
				expect(known.has(id), `${id} is styled but not listed`).toBe(
					true,
				);
			}
		});

		it("defines every token in every theme, so none inherits another by accident", () => {
			const required = [
				"--background",
				"--foreground",
				"--card",
				"--popover",
				"--primary",
				"--secondary",
				"--muted",
				"--accent",
				"--destructive",
				"--border",
				"--input",
				"--ring",
				"--selection",
				"--selection-foreground",
				"--past-foreground",
				"--changed",
				"--taken",
				"--fall",
				"--peek-foreground",
				"--warning",
				"--warning-foreground",
				"--kbd",
				"--brand",
				"--activity-bg",
				"--asm-addr",
				"--asm-bytes",
				"--asm-mnemonic",
				"--asm-register",
				"--asm-number",
				"--asm-string",
				"--asm-symbol",
				"--asm-jump",
				"--graph-edge",
				"--graph-taken",
				"--graph-fall",
				"--minimap-bg",
				"--minimap-mask",
				"--minimap-mask-stroke",
				"--minimap-node",
				"--minimap-node-stroke",
			];
			const b = blocks();
			for (const theme of THEMES) {
				const body = b.get(theme.id)!;
				for (const token of required) {
					expect(body, `${theme.id} is missing ${token}`).toContain(
						`${token}:`,
					);
				}
			}
		});

		it("declares colour-scheme in every theme, so native controls match it", () => {
			// Scrollbars, form controls and the caret are the window's own, not
			// the page's: a dark theme with `color-scheme: light` gets light ones.
			const b = blocks();
			for (const theme of THEMES) {
				expect(
					b.get(theme.id)!,
					`${theme.id} has no color-scheme`,
				).toContain("color-scheme:");
			}
		});

		it("agrees with each theme's declared handedness", () => {
			const b = blocks();
			for (const theme of THEMES) {
				const body = b.get(theme.id)!;
				if (theme.light) {
					expect(body).toContain("color-scheme: light");
					// A "light" theme on a dark ground is a theme nobody asked for.
					expect(
						body,
						`${theme.id} says light but paints dark`,
					).not.toContain("color-scheme: dark");
				} else {
					expect(body).toContain("color-scheme: dark");
				}
			}
		});

		it("has the default theme as the block that also serves a bare :root", () => {
			// :root carries the default so a document with no data-theme at all
			// still has a palette — the no-JS case in index.html.
			const selectors = blocksNaming(DEFAULT_THEME);
			expect(selectors.length).toBeGreaterThan(0);
			expect(selectors.some((s) => s.includes(":root"))).toBe(true);
		});

		it("gives the default theme's block every other theme's tokens too", () => {
			// Only the default is also :root, so it is the floor every other
			// palette falls back to for anything it does not declare.
			const body = blocks().get(DEFAULT_THEME)!;
			const bodyTokens = new Set(
				[...body.matchAll(/(--[a-z0-9-]+):/g)].map((m) => m[1]),
			);
			for (const theme of THEMES) {
				for (const m of blocks()
					.get(theme.id)!
					.matchAll(/(--[a-z0-9-]+):/g)) {
					expect(
						bodyTokens.has(m[1]),
						`${theme.id} sets ${m[1]}, which the default does not`,
					).toBe(true);
				}
			}
		});

		it("keeps chrome.css free of colours, so a theme change needs no second edit", () => {
			// If geometry ever grows a colour literal, every theme but the default
			// misses it, which is the failure this split exists to prevent.
			const chrome = readFileSync(
				new URL("../chrome.css", import.meta.url),
				"utf8",
			);
			const geometry = chrome.slice(0, chrome.indexOf("@theme inline"));
			expect(geometry).not.toMatch(/#[0-9a-f]{3,8}\b/i);
			expect(geometry).not.toMatch(/rgba?\(/i);
		});
	});
});
