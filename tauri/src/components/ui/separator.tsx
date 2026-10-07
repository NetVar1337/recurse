import * as React from "react";
import * as SeparatorPrimitive from "@radix-ui/react-separator";

import { cn } from "@/lib/utils";

// Memoized for the same reason as the rest: a rule between two panes is static,
// and there is one of them in every row of every register grid.
const Separator = React.memo(
	React.forwardRef<
		React.ElementRef<typeof SeparatorPrimitive.Root>,
		React.ComponentPropsWithoutRef<typeof SeparatorPrimitive.Root>
	>(
		(
			{
				className,
				orientation = "horizontal",
				decorative = true,
				...props
			},
			ref,
		) => (
			<SeparatorPrimitive.Root
				ref={ref}
				decorative={decorative}
				orientation={orientation}
				className={cn(
					"bg-border shrink-0",
					orientation === "horizontal"
						? "h-[1px] w-full"
						: "h-full w-[1px]",
					className,
				)}
				{...props}
			/>
		),
	),
);
Separator.displayName = SeparatorPrimitive.Root.displayName;

export { Separator };
