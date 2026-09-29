import * as React from "react";

import { cn } from "@/lib/utils";

// Memoized, because a panel full of inputs — a hex view is four thousand of
// them — should not re-render every field because one of them changed.
const Input = React.memo(
	React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
		({ className, type, ...props }, ref) => {
			return (
				<input
					type={type}
					ref={ref}
					className={cn(
						"border-input bg-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-[var(--control-h)] w-full rounded-[var(--radius-control)] border px-2 py-1 text-xs shadow-none transition-colors focus-visible:ring-1 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50",
						className,
					)}
					{...props}
				/>
			);
		},
	),
);
Input.displayName = "Input";

export { Input };
