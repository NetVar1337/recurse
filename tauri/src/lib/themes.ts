/**
 * The themes the app ships, named and ordered once.
 *
 * The colour values themselves live in `src/themes.css`, as CSS custom
 * properties on a `[data-theme]` attribute. Keeping them there rather than here
 * is deliberate: a token is read by stylesheets that Tailwind generates, by
 * `color-mix()` expressions, and by the graph panels, so a palette that lived in
 * TypeScript would have to be serialised back into CSS to be used at all. What
 * lives here is only what TypeScript actually needs to know — which themes
 * exist, what they are called, which way round they are, and whether one is a
 * light one.
 *
 * A theme that is not listed here is not applied: `applyTheme` refuses ids it
 * cannot find rather than writing them to the document, so a hand-edited
 * localStorage cannot leave the app with no colours at all.
 */

/** One of the app's themes. */
export interface Theme {
	/**
	 * Stable identifier, written to localStorage and to the document as
	 * `data-theme`. Never change one: a renamed id silently resets the reader's
	 * choice, because the old value simply stops being a theme they have.
	 */
	id: string;
	/** The name shown in the menu and the palette. */
	label: string;
	/** Whether this theme is built on a light background. */
	light: boolean;
	/**
	 * Two or three swatches shown beside the name, so a list of themes can be
	 * chosen from by eye rather than by reading ten names. They are the theme's
	 * real `--background`, `--foreground` and `--brand`, repeated here as
	 * literals only because a menu row cannot resolve a custom property from a
	 * theme that is not the one currently applied.
	 */
	swatches: [string, string, string];
}

/** How many themes the app ships. Named, so the test says what it means. */
export const TEN = 10;

/**
 * The shipped themes, in menu order: the two Recurse defaults first, then the
 * well-known ones an editor user is likely to already have in muscle memory.
 *
 * Recurse is dark by default because the work is reading a dark terminal's
 * worth of hex all day, but "Recurse Light" sits beside it rather than at the
 * end, because the reader who wants light usually wants it immediately and
 * should not have to scroll to find the one they came for.
 *
 * Ten is a deliberate count rather than a round one that got rounded: these are
 * the themes with an install base, and a twelfth would be one more name to read
 * past rather than one more place to find something. Adding one is a block in
 * themes.css and an entry here; the tests check they agree.
 */
export const THEMES: readonly Theme[] = [
	{
		id: "recurse-dark",
		label: "Recurse Dark",
		light: false,
		swatches: ["#06070a", "#e9edf3", "#7ec8ff"],
	},
	{
		id: "recurse-light",
		label: "Recurse Light",
		light: true,
		swatches: ["#fbfcfe", "#0b0d12", "#1f7fd0"],
	},
	{
		id: "dark-plus",
		label: "Dark+ (default dark)",
		light: false,
		swatches: ["#1e1e1e", "#cccccc", "#3794ff"],
	},
	{
		id: "light-plus",
		label: "Light+ (default light)",
		light: true,
		swatches: ["#ffffff", "#333333", "#005fb8"],
	},
	{
		id: "tokyo-night",
		label: "Tokyo Night",
		light: false,
		swatches: ["#1a1b26", "#c0caf5", "#7aa2f7"],
	},
	{
		id: "solarized-dark",
		label: "Solarized Dark",
		light: false,
		swatches: ["#002b36", "#93a1a1", "#268bd2"],
	},
	{
		id: "solarized-light",
		label: "Solarized Light",
		light: true,
		swatches: ["#fdf6e3", "#586e75", "#268bd2"],
	},
	{
		id: "monokai",
		label: "Monokai",
		light: false,
		swatches: ["#272822", "#f8f8f2", "#a6e22e"],
	},
	{
		id: "one-dark",
		label: "One Dark",
		light: false,
		swatches: ["#282c34", "#abb2bf", "#61afef"],
	},
	{
		id: "dracula",
		label: "Dracula",
		light: false,
		swatches: ["#282a36", "#f8f8f2", "#bd93f9"],
	},
];

/** The theme applied when nothing has been chosen, or the choice is unusable. */
export const DEFAULT_THEME = "recurse-dark";

/**
 * The shipped theme with this id, or undefined when there is none.
 *
 * @param id - Candidate theme identifier, from storage or from a caller.
 * @returns The theme, or undefined if the id is not one of the shipped themes.
 *
 * @example
 * themeById("tokyo-night")?.label // => "Tokyo Night"
 * themeById("nope") // => undefined
 */
export function themeById(id: string | null | undefined): Theme | undefined {
	return THEMES.find((t) => t.id === id);
}

/**
 * The shipped theme with this id, or the default theme.
 *
 * This is the reading a caller wants in almost every case: an id that is not a
 * theme is not a reason to leave the reader without a palette, so it resolves to
 * the default instead of to nothing.
 *
 * @param id - Candidate theme identifier, from storage or from a caller.
 * @returns The named theme, or the default when the id is not a shipped theme.
 *
 * @example
 * resolveTheme("dracula").id // => "dracula"
 * resolveTheme("corrupt").id // => "recurse-dark"
 * resolveTheme(undefined).id // => "recurse-dark"
 */
export function resolveTheme(id: string | null | undefined): Theme {
	return themeById(id) ?? themeById(DEFAULT_THEME)!;
}

/**
 * Whether this theme is built on a light background.
 *
 * A reader who has said "keep the app light" is making a claim about glare and
 * contrast that a dark theme breaks, so the answer is consulted whenever the app
 * has to pick a form control or scrollbar treatment of its own accord.
 *
 * @param id - Candidate theme identifier.
 * @returns True for a light theme, false for a dark one or an unknown id.
 *
 * @example
 * isLightTheme("solarized-light") // => true
 * isLightTheme("recurse-dark") // => false
 */
export function isLightTheme(id: string | null | undefined): boolean {
	return resolveTheme(id).light;
}

/**
 * The themes of one handedness, in menu order.
 *
 * @param light - True for the light themes, false for the dark ones.
 * @returns Those themes, in the order `THEMES` lists them.
 *
 * @example
 * THEMES.filter((t) => !t.light).map((t) => t.id).length // => 10
 */
export function themesOf(light: boolean): readonly Theme[] {
	return THEMES.filter((t) => t.light === light);
}
