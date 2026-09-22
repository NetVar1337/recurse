import { useEffect } from "react";
import { MessageSquare, RefreshCw, Settings, X } from "lucide-react";

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
import { useUpdateStore } from "@/store/updateStore";
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
	const updateStatus = useUpdateStore((s) => s.status);
	const availableVersion = useUpdateStore((s) => s.availableVersion);
	const updateProgress = useUpdateStore((s) => s.progress);
	const checkForUpdates = useUpdateStore((s) => s.checkForUpdates);
	const installAndRestart = useUpdateStore((s) => s.installAndRestart);

	useEffect(() => {
		void initBackend();
	}, [initBackend]);

	const zoomPct = Math.round(Math.pow(1.2, zoomLevel) * 100);
	const updateAvailable = updateStatus === "available";

	function updateLabel(): string {
		switch (updateStatus) {
			case "checking":
				return "Checking for updates…";
			case "available":
				return `Update to v${availableVersion} — restart to install`;
			case "downloading":
				return updateProgress != null
					? `Downloading update… ${updateProgress}%`
					: "Downloading update…";
			case "restarting":
				return "Restarting…";
			case "up-to-date":
				return "You're up to date";
			case "error":
				return "Update check failed — retry";
			default:
				return "Check for updates";
		}
	}

	function onUpdateClick() {
		if (updateAvailable) void installAndRestart();
		else void checkForUpdates();
	}

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
				<DropdownMenu>
					<DropdownMenuTrigger asChild>
						<Button
							variant="ghost"
							size="icon"
							title={
								updateAvailable
									? `Update available: v${availableVersion}`
									: "Settings"
							}
							className="relative"
						>
							<Settings />
							{updateAvailable && (
								<span className="bg-primary absolute top-1 right-1 h-2 w-2 rounded-full" />
							)}
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
						<DropdownMenuItem onClick={resetZoom}>
							Reset zoom (Ctrl 0)
						</DropdownMenuItem>
						<DropdownMenuSeparator />
						<DropdownMenuItem
							onClick={onUpdateClick}
							disabled={
								updateStatus === "checking" ||
								updateStatus === "downloading" ||
								updateStatus === "restarting"
							}
						>
							<RefreshCw
								className={
									updateStatus === "checking" ||
									updateStatus === "downloading"
										? "animate-spin"
										: undefined
								}
							/>
							{updateLabel()}
						</DropdownMenuItem>
					</DropdownMenuContent>
				</DropdownMenu>
			</div>
		</header>
	);
}
