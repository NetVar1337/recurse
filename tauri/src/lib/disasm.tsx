import type { ReactNode } from "react";

/**
 * Split a disassembly line into its instruction and its `; comment` suffix.
 *
 * Both backends append annotations to `disasm` as `"<instr> ; <comment>"`
 * (the comment is a string literal, a symbol, or a GOT/PLT name), so the UI
 * splits on that separator to colour the two parts independently.
 *
 * ```
 * splitComment('mov edi, 0x4007d4 ; "Hello ! "')
 * // => { instr: "mov edi, 0x4007d4", comment: '"Hello ! "' }
 * ```
 */
export function splitComment(text: string): {
	instr: string;
	comment: string;
} {
	const i = text.indexOf(" ; ");
	if (i < 0) return { instr: text, comment: "" };
	return { instr: text.slice(0, i), comment: text.slice(i + 3) };
}

/**
 * Render the `; comment` suffix of a disassembly line. Quoted string literals
 * get the string accent; symbol / GOT / PLT comments are muted italic, so a
 * `; "Give me your flag"` reads clearly as a string rather than more assembly.
 */
export function DisasmComment({ comment }: { comment: string }): ReactNode {
	if (!comment) return null;
	const isString = comment.startsWith('"');
	return (
		<span
			className={
				isString
					? "text-orange-500 dark:text-orange-400"
					: "text-muted-foreground italic"
			}
		>
			{" ; "}
			{comment}
		</span>
	);
}
