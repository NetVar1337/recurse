import logoMark from "@/assets/logo-mark.png";
import logoFull from "@/assets/logo.png";
import { cn } from "@/lib/utils";

/**
 * Compact brand mark (the control-flow graph) for tight spaces such as the
 * header and list rows. Rendered from a high-resolution source, so it stays
 * sharp at any size.
 *
 * The source is white-on-transparent, so it inverts to dark in a light theme.
 *
 * @param props.className - Tailwind sizing classes (e.g. `h-9 w-auto`)
 */
export function LogoMark({ className }: { className?: string }) {
	return (
		<img
			src={logoMark}
			alt="Recurse"
			draggable={false}
			className={cn("invert dark:invert-0", className)}
		/>
	);
}

/**
 * Full brand logo (a disassembly listing beside its control-flow graph) for
 * hero and dialog placements, where it is large enough to read.
 *
 * @param props.className - Tailwind sizing classes (e.g. `h-32 w-auto`)
 */
export function Logo({ className }: { className?: string }) {
	return (
		<img
			src={logoFull}
			alt="Recurse"
			draggable={false}
			className={cn("invert dark:invert-0", className)}
		/>
	);
}
