import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuLabel,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { useSessionStore } from "@/store/sessionStore";

export function SessionMenu() {
	const current = useSessionStore((s) => s.current);
	const sessions = useSessionStore((s) => s.sessions);
	const select = useSessionStore((s) => s.select);
	const remove = useSessionStore((s) => s.remove);
	const refresh = useSessionStore((s) => s.refresh);
	const [open, setOpen] = useState(false);

	return (
		<DropdownMenu
			open={open}
			onOpenChange={(o) => {
				setOpen(o);
				if (o) refresh();
			}}
		>
			<DropdownMenuTrigger asChild>
				<Button
					variant="ghost"
					size="sm"
					className="max-w-[170px] truncate"
					title="Select session"
				>
					<span className="truncate">
						{current?.name ?? "Session"}
					</span>
				</Button>
			</DropdownMenuTrigger>

			<DropdownMenuContent align="start" className="w-72">
				<DropdownMenuLabel>Recent sessions</DropdownMenuLabel>

				{sessions.length === 0 && (
					<div className="text-muted-foreground px-2 py-1 text-xs">
						No sessions yet
					</div>
				)}

				{sessions.map((s) => (
					<div
						key={s.id}
						className={cn(
							"flex items-center gap-1.5 rounded-sm px-2 py-1 text-xs",
							current?.id === s.id
								? "ui-selected"
								: "hover:bg-accent",
						)}
					>
						<button
							type="button"
							className="min-w-0 flex-1 truncate text-left"
							onClick={() => {
								select(s.id);
								setOpen(false);
							}}
						>
							{s.name}
						</button>
						<button
							type="button"
							className="text-2xs shrink-0 opacity-60 hover:opacity-100"
							onClick={(e) => {
								e.stopPropagation();
								remove(s.id);
							}}
						>
							Delete
						</button>
					</div>
				))}
			</DropdownMenuContent>
		</DropdownMenu>
	);
}
