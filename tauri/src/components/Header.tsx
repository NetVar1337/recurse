import { useEffect } from "react";
import { MessageSquare, Moon, Settings, Sun, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { LogoMark } from "@/components/Logo";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useBinaryStore } from "@/store/binaryStore";
import { useProjectStore } from "@/store/projectStore";
import { useUiStore } from "@/store/uiStore";
import { useSettingsStore } from "@/store/settingsStore";
export function Header() {
	const binary = useBinaryStore((s) => s.binary);
	const busy = useBinaryStore((s) => s.busy);
	const project = useProjectStore((s) => s.current);
	const close = useProjectStore((s) => s.close);
	const chatOpen = useUiStore((s) => s.chatOpen);
	const toggleChat = useUiStore((s) => s.toggleChat);
	const zoomLevel = useSettingsStore((s) => s.zoomLevel);
	const zoomIn = useSettingsStore((s) => s.zoomIn);
	const zoomOut = useSettingsStore((s) => s.zoomOut);
	const resetZoom = useSettingsStore((s) => s.resetZoom);
	const backend = useSettingsStore((s) => s.backend);
	const setBackend = useSettingsStore((s) => s.setBackend);
	const initBackend = useSettingsStore((s) => s.initBackend);
	const theme = useSettingsStore((s) => s.theme);
	const toggleTheme = useSettingsStore((s) => s.toggleTheme);

	useEffect(() => {
		void initBackend();
	}, [initBackend]);

	const zoomPct = Math.round(Math.pow(1.2, zoomLevel) * 100);

	return (
		<header className="border-border bg-card flex items-center gap-3 border-b px-3 py-2">
			<div className="flex items-center gap-2">
				<LogoMark className="h-9 w-auto" />
				<span className="text-sm font-bold tracking-wide">Recurse</span>
				<span className="text-muted-foreground text-[11px]">
					agentic reverse engineering
				</span>
			</div>

			{binary && project && (
				<div className="flex flex-1 items-center gap-1.5 overflow-hidden">
					<Badge variant="outline" className="text-primary font-mono">
						{project.name}
					</Badge>
				</div>
			)}

			<div className="ml-auto flex items-center gap-2">
				{binary && (
					<Button
						variant={chatOpen ? "secondary" : "ghost"}
						size="sm"
						onClick={toggleChat}
						title="Toggle agent chat (Ctrl+L)"
					>
						<MessageSquare /> Chat
					</Button>
				)}
				{binary && (
					<Button
						variant="outline"
						size="sm"
						onClick={close}
						disabled={busy}
					>
						<X /> Close
					</Button>
				)}
				<Button
					variant="ghost"
					size="icon"
					onClick={toggleTheme}
					title={
						theme === "dark"
							? "Switch to light theme"
							: "Switch to dark theme"
					}
				>
					{theme === "dark" ? <Sun /> : <Moon />}
				</Button>
				<DropdownMenu>
					<DropdownMenuTrigger asChild>
						<Button variant="ghost" size="icon" title="Settings">
							<Settings />
						</Button>
					</DropdownMenuTrigger>
					<DropdownMenuContent align="end">
						<DropdownMenuLabel>Zoom · {zoomPct}%</DropdownMenuLabel>
						<DropdownMenuItem onClick={zoomIn}>
							Zoom in (Ctrl +)
						</DropdownMenuItem>
						<DropdownMenuItem onClick={zoomOut}>
							Zoom out (Ctrl −)
						</DropdownMenuItem>
						<DropdownMenuSeparator />
						<DropdownMenuLabel>
							Analysis engine · {backend}
						</DropdownMenuLabel>
						<DropdownMenuItem
							onClick={() => void setBackend("native")}
						>
							{backend === "native" ? "● " : "○ "}Native — pure
							Rust (default)
						</DropdownMenuItem>
						<DropdownMenuItem onClick={() => void setBackend("r2")}>
							{backend === "r2" ? "● " : "○ "}r2 — radare2
							(opt-in)
						</DropdownMenuItem>
						<DropdownMenuSeparator />
						<DropdownMenuLabel>Theme · {theme}</DropdownMenuLabel>
						<DropdownMenuItem onClick={toggleTheme}>
							Toggle light / dark
						</DropdownMenuItem>
						<DropdownMenuSeparator />
						<DropdownMenuItem onClick={resetZoom}>
							Reset zoom (Ctrl 0)
						</DropdownMenuItem>
					</DropdownMenuContent>
				</DropdownMenu>
			</div>
		</header>
	);
}
