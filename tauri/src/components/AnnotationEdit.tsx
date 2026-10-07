import { useRef, useState } from "react";

import { cn } from "@/lib/utils";

/**
 * One inline-editable annotation: what it shows, what is being typed, and how
 * the edit ends.
 *
 * Shared by every annotation a view can change — a variable's name, a datum's
 * type — because the hard parts of editing a field in place are the same for
 * all of them and are the parts that go wrong: Escape must not save, a rename
 * from another view must reach a field that is open but not being typed in, and
 * a write that fails must hand back what was there rather than leave a value
 * that silently did not stick.
 */
export interface AnnotationEdit {
	/** The text to show when not editing: the analyst's, else the derived one. */
	shown: string;
	/** The value actually recorded, or undefined when there is none. */
	value: string | undefined;
	/** Whether the field is open. */
	editing: boolean;
	/** What is in the field while it is open. */
	draft: string;
	/** Record a keystroke. */
	setDraft: (text: string) => void;
	/** Open the field. */
	begin: () => void;
	/** Save and close. */
	commit: () => void;
	/** Abandon and close. */
	cancel: () => void;
}

/**
 * Editing one annotation in place.
 *
 * The write is the caller's: this owns the field and nothing else, so a view
 * decides what "saved" means — a name goes to `rename_variable`, a type to
 * `set_variable_type` — without the field's behaviour being reimplemented.
 *
 * @param options.shown - The value to show and to seed the draft with.
 * @param options.value - The recorded value, or undefined when there is none.
 *   Read on every render, so a change made elsewhere reaches an open field.
 * @param options.persist - Called with the trimmed draft on save, and with
 *   `undefined` when the field is saved empty (which clears it). Not called for
 *   a draft equal to what is already recorded.
 * @returns The state and handlers for one annotation.
 *
 * @example
 * const edit = useAnnotationEdit({ shown: "var_18", value: undefined, persist: save });
 * edit.begin();
 * edit.setDraft("buf");
 * edit.commit(); // calls save("buf")
 */
export function useAnnotationEdit({
	shown,
	value,
	persist,
}: {
	shown: string;
	value: string | undefined;
	persist: (next: string | undefined) => void;
}): AnnotationEdit {
	const [editing, setEditing] = useState(false);
	const [draft, setDraft] = useState(shown);
	// Escape closes the field by unmounting it, and a browser may still deliver
	// the blur on its way out — which would save the value that was just backed
	// out of. One flag, set by the cancel and spent by the commit that follows.
	const abandoned = useRef(false);
	// An annotation changed from elsewhere, or by this field's own blur, has to
	// reach the field — but not one the analyst is halfway through typing.
	// Adjusting the draft while rendering is the documented way to derive state
	// from a prop; doing it in an effect would lag a keystroke behind.
	const [shownWhen, setShownWhen] = useState(shown);
	if (shownWhen !== shown) {
		setShownWhen(shown);
		if (!editing) setDraft(shown);
	}

	const close = () => {
		abandoned.current = false;
		setEditing(false);
	};

	return {
		shown,
		value,
		editing,
		draft,
		setDraft,
		begin: () => {
			// Seeded, not empty. A field that opens blank gives the analyst
			// nothing to edit: Enter and click-away both mean "keep what I see",
			// and on a blank field both quietly do nothing at all.
			abandoned.current = false;
			setDraft(shown);
			setEditing(true);
		},
		commit: () => {
			if (abandoned.current) {
				// The blur that follows an Escape, not a save.
				close();
				return;
			}
			close();
			const next = draft.trim();
			if (next === (value ?? "")) return;
			persist(next || undefined);
		},
		cancel: () => {
			abandoned.current = true;
			setEditing(false);
			setDraft(value ?? shown);
		},
	};
}

/**
 * The open field for an annotation.
 *
 * @param props.edit - The state and handlers for this annotation.
 * @param props.className - Classes for the field, so a view can size it.
 * @returns The text input.
 */
export function AnnotationField({
	edit,
	className,
}: {
	edit: AnnotationEdit;
	className?: string;
}) {
	return (
		<input
			autoFocus
			value={edit.draft}
			onChange={(e) => edit.setDraft(e.target.value)}
			// Selected, so typing overwrites the value being replaced instead of
			// appending to it — the field is open to change what is already there.
			onFocus={(e) => e.currentTarget.select()}
			onBlur={edit.commit}
			onKeyDown={(e) => {
				if (e.key === "Enter") e.currentTarget.blur();
				if (e.key === "Escape") {
					// The blur that follows would otherwise save the value the
					// analyst just backed out of.
					e.preventDefault();
					edit.cancel();
				}
			}}
			className={cn(
				"bg-background text-foreground mx-1 border px-1 py-0 font-mono text-xs",
				className,
			)}
		/>
	);
}

/**
 * An annotation as it reads when the field is closed: a button that opens it.
 *
 * Muted when nothing is recorded, because a derived `undefined8` or `var_18` is
 * not a fact about the program — it is this tool's own placeholder — and the
 * analyst should be able to tell at a glance which cells they have filled in.
 *
 * @param props.edit - The state and handlers for this annotation.
 * @param props.className - Classes for the button, so a view can size it.
 * @param props.title - The hover hint. Defaults to the derived/annotated wording.
 * @returns The button.
 */
export function AnnotationButton({
	edit,
	className,
	title,
}: {
	edit: AnnotationEdit;
	className?: string;
	title?: string;
}) {
	return (
		<button
			type="button"
			className={cn(
				"hover:bg-accent/50 hover:text-foreground mx-1 rounded px-0.5 font-mono text-xs",
				edit.value
					? "text-asm-symbol italic"
					: "text-muted-foreground/70",
				className,
			)}
			title={
				title ??
				(edit.value
					? "Click to change this"
					: "Derived — click to set it")
			}
			onClick={() => edit.begin()}
		>
			{edit.shown}
		</button>
	);
}
