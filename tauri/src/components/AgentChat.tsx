import { useEffect, useRef, useState, type RefObject } from "react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { api } from "@/api";
import { Markdown } from "@/components/Markdown";
import { ModelPicker } from "@/components/ModelPicker";
import { useLlmStore } from "@/store/llmStore";
import {
	useAgentStore,
	type ToolCallUi,
	type UiBlock,
} from "@/store/agentStore";
import { useContextStore } from "@/store/contextStore";
import { useSessionStore } from "@/store/sessionStore";

function fmtDate(secs: number): string {
	const d = new Date(secs * 1000);
	return Number.isNaN(d.getTime())
		? ""
		: d.toLocaleDateString(undefined, {
				month: "short",
				day: "numeric",
			});
}

interface Props {
	inputRef?: RefObject<HTMLTextAreaElement | null>;
}

function ToolCallChip({ call }: { call: ToolCallUi }) {
	const [open, setOpen] = useState(false);
	const running = call.result === undefined;
	return (
		<div className="border-border/60 bg-muted/30 text-muted-foreground rounded border px-2 py-1 text-[11px]">
			<button
				className="flex w-full min-w-0 items-center gap-1.5 text-left"
				onClick={() => setOpen((o) => !o)}
			>
				<span className="shrink-0 font-mono font-semibold">
					{call.name}
				</span>
				{call.arguments && (
					<span className="text-muted-foreground/70 min-w-0 flex-1 truncate font-mono">
						{call.arguments.slice(0, 40)}
					</span>
				)}
				<span className="shrink-0">
					{running ? (
						<span className="text-primary animate-pulse">…</span>
					) : open ? (
						"Hide"
					) : (
						"Show"
					)}
				</span>
			</button>
			{open && call.result !== undefined && (
				<pre className="text-muted-foreground mt-1 max-h-40 overflow-auto pt-1 font-mono text-[10px] break-words whitespace-pre-wrap">
					{call.result}
				</pre>
			)}
		</div>
	);
}

export function AgentChat({ inputRef }: Props) {
	const messages = useAgentStore((s) => s.messages);
	const busy = useAgentStore((s) => s.busy);
	const send = useAgentStore((s) => s.send);
	const prevBusy = useRef(false);

	const items = useContextStore((s) => s.items);
	const removeItem = useContextStore((s) => s.remove);
	const sessions = useSessionStore((s) => s.sessions);
	const current = useSessionStore((s) => s.current);
	const sessionsLoading = useSessionStore((s) => s.loading);
	const sessionsError = useSessionStore((s) => s.error);
	const createSession = useSessionStore((s) => s.create);
	const refreshSessions = useSessionStore((s) => s.refresh);

	const [input, setInput] = useState("");
	const [showSessions, setShowSessions] = useState(
		() => !useSessionStore.getState().current,
	);
	const scrollRef = useRef<HTMLDivElement>(null);

	const provider = useLlmStore((s) => s.provider);
	const configured = useLlmStore((s) => s.configured);

	// Refresh after completion so the generated session name appears on home.
	useEffect(() => {
		if (prevBusy.current && !busy) {
			void refreshSessions();
		}
		prevBusy.current = busy;
	}, [busy, refreshSessions]);

	useEffect(() => {
		scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
	}, [messages, busy]);

	const openSessions = () => {
		setShowSessions(true);
		void refreshSessions();
	};

	const startNewChat = async () => {
		if (busy) return;
		await createSession();
		setShowSessions(false);
	};

	const selectSession = async (id: string) => {
		if (busy) return;
		await useSessionStore.getState().select(id);
		setShowSessions(false);
	};

	const doSend = async () => {
		const text = input.trim();
		if (!text || busy) return;
		setInput("");
		setShowSessions(false);
		const ctxs = useContextStore.getState().items;
		const sessionId = useSessionStore.getState().current?.id ?? "";
		await send(text, ctxs, sessionId);
	};

	return (
		<div className="flex min-h-0 flex-1 flex-col">
			<div className="border-border ui-bar border-b px-2">
				{showSessions ? (
					<span className="ui-panel-title">Sessions</span>
				) : (
					<Button
						variant="toolbar"
						size="sm"
						onClick={openSessions}
						title="Sessions"
					>
						Sessions
					</Button>
				)}
				{!showSessions && (
					<span className="ui-panel-title text-muted-foreground">
						{current?.name ?? "Chat"}
					</span>
				)}
				<Button
					variant="toolbar"
					size="sm"
					className="ml-auto"
					onClick={() => void startNewChat()}
					title="New chat"
				>
					New
				</Button>
			</div>

			{!configured && (
				<div className="border-border text-warning-foreground bg-warning/10 border-b px-3 py-1.5 text-[11px]">
					Set your{" "}
					<code className="font-mono">
						{provider.toUpperCase().replace(/_/g, " ")} API key
					</code>{" "}
					via the model menu.
				</div>
			)}

			<div
				ref={scrollRef}
				className="scroll-host flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto p-4"
			>
				{showSessions && (
					<div className="flex flex-col gap-3">
						{sessionsError && (
							<div className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-[11px]">
								{sessionsError}
							</div>
						)}
						{sessionsLoading ? (
							<div className="text-muted-foreground px-2 py-3 text-xs">
								Loading sessions…
							</div>
						) : sessions.length > 0 ? (
							<ul className="border-border overflow-hidden rounded-[var(--radius-control)] border">
								{sessions.map((s) => {
									const active = current?.id === s.id;
									return (
										<li key={s.id} className="min-w-0">
											<button
												type="button"
												onClick={() =>
													void selectSession(s.id)
												}
												className={cn(
													"hover:bg-accent focus-visible:ring-ring flex w-full min-w-0 flex-col px-3 py-2 text-left focus-visible:ring-1",
													active && "ui-selected",
												)}
											>
												<span className="block max-w-full truncate text-xs font-medium">
													{s.name}
												</span>
												<span className="mt-0.5 block truncate text-[10px] opacity-70">
													{fmtDate(s.updated_at)}
												</span>
											</button>
										</li>
									);
								})}
							</ul>
						) : (
							<div className="text-muted-foreground border-border rounded-[var(--radius-control)] border px-3 py-8 text-center text-xs">
								No chats yet. Start one with New.
							</div>
						)}
					</div>
				)}
				{!showSessions &&
					messages.map((m) => (
						<div key={m.id}>
							{m.role === "user" ? (
								<div className="flex justify-end">
									<div className="bg-primary text-primary-foreground max-w-[92%] rounded-lg px-2.5 py-2 text-xs leading-relaxed break-words whitespace-pre-wrap">
										{m.blocks
											.filter((b) => b.kind === "content")
											.map((b) =>
												b.kind === "content"
													? b.text
													: "",
											)
											.join("")}
										{m.contextRefs &&
											m.contextRefs.length > 0 && (
												<div className="mt-1.5 flex flex-wrap gap-1">
													{m.contextRefs.map(
														(ref, i) => (
															<span
																key={i}
																className="bg-primary-foreground/15 rounded px-1 py-px font-mono text-[10px]"
															>
																{ref}
															</span>
														),
													)}
												</div>
											)}
									</div>
								</div>
							) : (
								<AssistantMessage
									blocks={m.blocks}
									pending={m.pending}
									error={m.error}
								/>
							)}
						</div>
					))}
			</div>

			<div className="border-border border-t px-3 py-2">
				<div className="flex w-full flex-col gap-1">
					<div className="ui-composer">
						{items.length > 0 && (
							<div className="flex flex-wrap gap-1 px-1">
								{items.map((it) => (
									<Badge
										key={it.id}
										variant="secondary"
										className="font-mono text-[10px]"
									>
										<span className="max-w-[180px] truncate">
											{it.label}
										</span>
										<button
											className="hover:text-destructive ml-1"
											onClick={() => removeItem(it.id)}
											title="Remove from context"
											aria-label="Remove from context"
										>
											×
										</button>
									</Badge>
								))}
							</div>
						)}
						<div className="flex items-end gap-1">
							<Textarea
								ref={inputRef}
								placeholder="e.g. what does sym.main do? disassemble it"
								rows={1}
								className="min-h-[var(--control-h)] flex-1 resize-none border-0 bg-transparent px-1.5 py-1.5 shadow-none focus-visible:ring-0"
								value={input}
								onChange={(e) => setInput(e.target.value)}
								onKeyDown={(e) => {
									if (e.key === "Enter" && !e.shiftKey) {
										e.preventDefault();
										doSend();
									}
								}}
							/>
							{busy ? (
								<Button
									variant="toolbar"
									size="sm"
									onClick={() => void api.agentCancel()}
									title="Stop the agent (lands between tool steps)"
								>
									Stop
								</Button>
							) : (
								<Button
									variant="toolbar"
									size="sm"
									onClick={doSend}
									disabled={!input.trim()}
									title="Send"
								>
									Send
								</Button>
							)}
						</div>
					</div>
					<ModelPicker />
				</div>
			</div>
		</div>
	);
}

function ReasoningBlock({ text }: { text: string }) {
	const [show, setShow] = useState(true);
	return (
		<div className="border-primary/50 text-muted-foreground mb-1.5 border-l-2 pl-2">
			<button
				className="flex items-center gap-1 text-[10px] tracking-wider uppercase"
				onClick={() => setShow((s) => !s)}
			>
				{show ? "Hide" : "Show"} thinking
			</button>
			{show && (
				<div className="text-muted-foreground/80 mt-1 break-words whitespace-pre-wrap">
					{text}
				</div>
			)}
		</div>
	);
}

function AssistantMessage({
	blocks,
	pending,
	error,
}: {
	blocks: UiBlock[];
	pending: boolean;
	error?: string;
}) {
	const hasAny = blocks.some(
		(b) => b.kind !== "content" || b.text.length > 0,
	);
	return (
		<div className="max-w-full min-w-0 text-xs leading-relaxed">
			{blocks.map((b, i) => {
				switch (b.kind) {
					case "reasoning":
						return <ReasoningBlock key={i} text={b.text} />;
					case "tool_call":
						return (
							<div key={i} className="mb-1.5">
								<ToolCallChip call={b.call} />
							</div>
						);
					case "content":
						return b.text.length > 0 ? (
							<div key={i} className="mb-1.5">
								<Markdown>{b.text}</Markdown>
							</div>
						) : null;
					default:
						return null;
				}
			})}
			{pending && !hasAny && (
				<span className="text-muted-foreground animate-pulse">…</span>
			)}
			{error && (
				<div className="text-destructive mt-1.5 text-[11px]">
					{error}
				</div>
			)}
		</div>
	);
}
