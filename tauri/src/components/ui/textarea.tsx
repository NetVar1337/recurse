import * as React from "react";

import { cn } from "@/lib/utils";

// Memoized so a growing transcript above the composer does not re-render the
// one field the analyst is typing into — which would fight the keystroke.
const Textarea = React.memo(
	React.forwardRef<HTMLTextAreaElement, React.ComponentProps<"textarea">>(
		({ className, ...props }, ref) => {
			return (
				<textarea
					ref={ref}
					className={cn(
						"border-input bg-background placeholder:text-muted-foreground focus-visible:ring-ring flex w-full rounded-[var(--radius-control)] border px-2 py-1 text-xs shadow-none focus-visible:ring-1 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50",
						className,
					)}
					{...props}
				/>
			);
		},
	),
);
Textarea.displayName = "Textarea";

export { Textarea };
