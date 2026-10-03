import { api } from "@/api";
import {
	AnnotationButton,
	AnnotationField,
	useAnnotationEdit,
} from "@/components/AnnotationEdit";
import { annotationKey, typeFor } from "@/lib/listingFormat";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useUiStore } from "@/store/uiStore";

/**
 * Editing one datum's type, the counterpart of `useVarRename`.
 *
 * Free text rather than a choice from a fixed list, because the useful
 * annotation is often not on one: `char[8]`, `struct config *`, `char *`. A list
 * would only be a faster way to reach the entries it did have, and a faster way
 * to say something untrue about the rest.
 *
 * The write is optimistic and reversible, for the reason `useVarRename` gives.
 *
 * @param options.func - The function's static address.
 * @param options.datum - The datum: a frame offset, a register, or `RETURN_KEY`.
 * @param options.width - The datum's derived width in bytes, shown until the
 *   analyst gives it a type.
 * @param options.types - Every recorded type, keyed by {@link annotationKey}.
 * @returns The state and handlers for one type.
 */
export function useTypeAnnotate({
	func,
	datum,
	width,
	types,
}: {
	func: number | null;
	datum: string | number | null;
	width: number;
	types: Record<string, string>;
}) {
	const value =
		func === null || datum === null
			? undefined
			: types[annotationKey(func, datum)];
	return useAnnotationEdit({
		shown:
			func === null || datum === null
				? ""
				: typeFor(types, func, datum, width),
		value,
		persist: (next) => {
			if (func === null || datum === null) return;
			// Shown first, so the cell updates on the keystroke; given back if the
			// write fails, and said out loud — a type that reverts with no
			// explanation is indistinguishable from one that was never editable.
			const previous = value ?? "";
			useAnalysisStore
				.getState()
				.setVariableType(func, datum, next ?? "");
			void api
				.setVariableType(func, String(datum), next ?? "")
				.catch((e) => {
					useAnalysisStore
						.getState()
						.setVariableType(func, datum, previous);
					useUiStore
						.getState()
						.setErr(
							`could not save "${next}" for ${datum}: ${
								e instanceof Error ? e.message : String(e)
							}`,
						);
				});
		},
	});
}

/**
 * A datum's type, editable in place.
 *
 * Sized for the listing's own type scale, which is a step below the panels': a
 * header cell is one line of an 11px monospace listing, and an input sized for
 * a 12px panel would reflow the row it sits in.
 *
 * @param props.func - The function's static address.
 * @param props.datum - The datum: a frame offset, a register, or `RETURN_KEY`.
 * @param props.width - The datum's derived width in bytes.
 * @param props.className - Classes for the cell.
 * @returns The type, as a field when open and a button when not.
 */
export function TypeCell({
	func,
	datum,
	width,
	className,
}: {
	func: number;
	datum: string | number;
	width: number;
	className?: string;
}) {
	const types = useAnalysisStore((s) => s.variableTypes);
	const edit = useTypeAnnotate({ func, datum, width, types });
	if (edit.editing) {
		// Sized for the listing's own type scale, and for the column it opens in:
		// a field wider than the 12-character type column would reflow the row
		// around it, pushing the storage column sideways on the keystroke that
		// opened it.
		return (
			<AnnotationField
				edit={edit}
				className={cn("mx-0 w-[10ch] text-[11px]", className)}
			/>
		);
	}
	return <AnnotationButton edit={edit} className={className} />;
}
