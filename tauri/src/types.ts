export interface BinaryInfo {
	path: string;
	backend?: Backend;
	capabilities?: {
		decompile: boolean;
		raw: boolean;
		graph: boolean;
		xrefs_from: boolean;
	};
	info: {
		bin?: {
			arch?: string;
			bits?: number;
			type?: string | null;
			/** Entry-point address, when the backend reports one. */
			entry?: number;
			[k: string]: unknown;
		};
		[k: string]: unknown;
	};
	function_count: number;
	string_count: number;
}

/** Hardening report (checksec-style) for the recon page. */
export interface ReconChecksec {
	relro?: string;
	canary?: string;
	nx?: string;
	pie?: string;
	rpath?: string;
	runpath?: string;
	fortify?: string;
	fortified?: number;
	fortifiable?: number;
}

/** File hashes for the recon page. */
export interface ReconHashes {
	md5: string;
	sha1: string;
	sha256: string;
	crc32: string;
}

/** Analysis counts for the recon page. */
export interface ReconAnalysis {
	functions?: number;
	xrefs?: number;
	calls?: number;
	strings?: number;
	symbols?: number;
	imports?: number;
	coverage?: number;
}

/** Reconnaissance summary rendered by the recon page. */
export interface Recon {
	info: Record<string, unknown>;
	checksec: ReconChecksec;
	libraries: string[];
	analysis: ReconAnalysis;
	hashes: ReconHashes;
	entropy: number;
	temperature: number;
}

export interface Function {
	addr: number;
	name?: string;
	realname?: string;
	size?: number;
	signature?: string;
	[k: string]: unknown;
}

export interface AsmInsn {
	addr: number;
	text?: string;
	disasm?: string;
	bytes?: string | null;
	esil?: string | null;
	jump?: number | null;
	ptr?: number | null;
	[k: string]: unknown;
}

export interface AsmResult {
	name?: string;
	addr?: number;
	size?: number;
	ops?: AsmInsn[];
	[k: string]: unknown;
}

export interface R2String {
	vaddr: number;
	string: string;
	type?: string;
	[k: string]: unknown;
}

export interface Import {
	name?: string;
	[k: string]: unknown;
}

export interface Xref {
	from: number;
	type?: string;
	fcn_name?: string;
	opcode?: string;
	[k: string]: unknown;
}

export interface DecompileAnnotation {
	start: number;
	end: number;
	type?: string;
	name?: string;
	offset?: number;
	syntax_highlight?: string;
	[k: string]: unknown;
}

export interface DecompileResult {
	code?: string;
	annotations?: DecompileAnnotation[];
	[k: string]: unknown;
}

export type CenterTab =
	"recon" | "disasm" | "strings" | "imports" | "console" | "debug";

export interface ModelInfo {
	id: string;
	name: string;
	context_length: number;
	prompt_price: string;
	free: boolean;
}

export interface LlmStatus {
	provider: string;
	configured: boolean;
	model: string;
	/** Normalized completions URL the agent calls. */
	endpoint: string;
	/** True for a custom/local OpenAI-compatible endpoint (no key required). */
	custom: boolean;
}

/** Analysis backend implementations selectable at runtime. */
export type Backend = "r2" | "native";

export interface Project {
	name: string;
	binary_path: string;
	created_at: number;
	updated_at: number;
}

export interface ToolCallFn {
	name: string;
	arguments: string;
}

export interface ToolCall {
	id: string;
	type: string;
	function: ToolCallFn;
}

export interface ChatMessage {
	role: string;
	content: string | null;
	tool_calls?: ToolCall[] | null;
	tool_call_id?: string | null;
	reasoning?: string | null;
}

export type AgentEventKind =
	"reasoning" | "token" | "tool_call" | "tool_result" | "done" | "error";

export interface AgentEvent {
	kind: AgentEventKind;
	run_id: string;
	delta?: string;
	content?: string;
	message?: string;
	id?: string;
	name?: string;
	arguments?: string;
	result?: string;
}

export interface ContextItem {
	id: string;
	source: "disasm" | "decompile" | "string" | "function";
	label: string;
	text: string;
}

export interface PendingSelection {
	label: string;
	text: string;
	source: ContextItem["source"];
}

export interface GraphOp {
	addr: number;
	disasm?: string;
	bytes?: string | null;
	type?: string;
	jump?: number | null;
	fail?: number | null;
	[k: string]: unknown;
}

export interface GraphBlock {
	addr: number;
	ninstr?: number;
	size?: number;
	jump?: number | null;
	fail?: number | null;
	/** Extra successors of a computed jump (jump-table / switch cases). */
	targets?: number[];
	ops?: GraphOp[];
	[k: string]: unknown;
}

/**
 * Canonical control-flow graph. Both engines produce exactly this shape — r2's
 * output is transformed into it host-side — so the graph UI is
 * backend-agnostic.
 */
export interface FunctionGraph {
	addr: number;
	name?: string;
	blocks?: GraphBlock[];
	[k: string]: unknown;
}

export interface DebugRegisters {
	pc: number;
	sp: number;
	fp: number;
	values: Record<string, number>;
}

/** A tagged stop reason (`{reason: "breakpoint", addr, id}`, …). */
export interface DebugStopReason {
	reason: string;
	addr?: number;
	id?: number;
	signal?: number;
	name?: string;
	code?: number;
}

export interface DebugStop {
	pid: number;
	thread: number;
	reason: DebugStopReason;
	registers: DebugRegisters;
}

export interface DebugBreakpoint {
	id: number;
	addr: number;
	enabled: boolean;
}

export interface DebugFrame {
	addr: number;
	name?: string;
}

export interface DebugStatus {
	pid?: number | null;
	state: string;
	stop?: DebugStopReason;
	breakpoints: DebugBreakpoint[];
}

/** Live session snapshot, published by the debugger for follow-along. */
export interface DebugSnapshot {
	pid?: number | null;
	state: string;
	stop?: DebugStop | null;
	breakpoints: DebugBreakpoint[];
	frames: DebugFrame[];
	/** `runtime - static` address (ASLR/PIE load bias). */
	bias: number;
}

/** One instruction decoded from the debuggee's live memory. */
export interface DebugInsn {
	addr: number;
	bytes: string;
	text: string;
}

/** A rendered memory read. */
export interface DebugMemory {
	addr: number;
	len?: number;
	hex?: string;
	ascii?: string;
	words?: number[];
}

export interface Session {
	id: string;
	name: string;
	model: string;
	created_at: number;
	updated_at: number;
}
