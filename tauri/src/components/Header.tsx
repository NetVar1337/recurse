import { useEffect } from "react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DebuggerSettingsDialog } from "@/components/DebuggerSettingsDialog";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
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
	const initBackend = useSettingsStore((s) => s.initBackend);
	const debuggerSettingsOpen = useUiStore((s) => s.debuggerSettingsOpen);
	const setDebuggerSettingsOpen = useUiStore(
		(s) => s.setDebuggerSettingsOpen,
	);

	useEffect(() => {
		void initBackend();
	}, [initBackend]);

	if (!binary) return null;
	return (
		<header className="border-border bg-card ui-bar border-b px-3">
			{project && (
				<div className="flex min-w-0 flex-1 items-center overflow-hidden px-3">
					<Badge variant="outline" className="font-mono">
						{project.name}
					</Badge>
				</div>
			)}

			{/* Its own element, empty: a drag region on the header itself would
			    make every button in the header a place to drag the window from. */}
			<div
				data-tauri-drag-region
				className="min-w-4 flex-1 self-stretch"
			/>

			{binary && (
				<div className={cn("ml-auto", chrome.headerActions)}>
					<Button
						variant="toolbar"
						size="sm"
						className={cn("rounded-[2px]", chrome.press)}
						aria-pressed={chatOpen}
						onClick={toggleChat}
						title="Toggle agent chat (Ctrl+L)"
					>
						Chat
					</Button>
					<Button
						variant="toolbar"
						size="sm"
						className="rounded-[2px]"
						onClick={close}
						disabled={busy}
					>
						Close
					</Button>
				</div>
			)}

			<DebuggerSettingsDialog
				open={debuggerSettingsOpen}
				onOpenChange={setDebuggerSettingsOpen}
			/>
		</header>
	);
}
