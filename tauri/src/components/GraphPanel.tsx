import { useEffect, useMemo, useState } from "react";
import {
	Controls,
	Handle,
	MarkerType,
	Position,
	ReactFlow,
	ReactFlowProvider,
	type Edge,
	type Node,
	type NodeProps,
	useEdgesState,
	useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { api } from "@/api";
import { layoutInline, layoutInWorker } from "@/lib/dagreLayout";
import { cn } from "@/lib/utils";
import { callTarget } from "@/lib/calls";
import { VarNameChip } from "@/components/VarNameChip";
import {
	DisasmComment,
	DisasmInstr,
	formatInstructionBytes,
	splitComment,
} from "@/lib/disasm";
import { useAnalysisStore } from "@/store/analysisStore";
import type { Function, FunctionGraph, GraphOp } from "@/types";

const BLOCK_W = 380;
const LINE_H = 17;
const HEADER_H = 24;
const COL_H = 15;

function fmtAddr(a?: number | null) {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

type BlockOp = GraphOp & { target?: Function | null };
type BlockData = {
	addr: string;
	ops: BlockOp[];
	/**
	 * The function this block belongs to, for its variable names: a block has an
	 * address of its own, and `[rbp - 0x18]` is only a slot once you know which
	 * frame it is in.
	 */
	func: number;
	/**
	 * The function's instructions, flattened out of the blocks. Needed because
	 * how a function addresses its frame — `rbp` or `rsp`, and how deep — is a
	 * property of the whole body, not of the one block a node shows.
	 */
	insns: { text?: string; disasm?: string }[];
};
type BlockNode = Node<BlockData, "cfgnode">;

// Columns are sized per node from its own content (see `blockColumns`) so
// both the addr and bytes columns are exactly as wide as their widest value
// and the instruction column holds the longest line in full — a hardcoded
// character width (the previous approach for the addr column) clips as soon
// as an address is longer than assumed (e.g. `0x14000105f` on a driver
// loaded above 4 GiB is 11 chars, not the 9 a 32-bit-shaped estimate
// allows), and since grid tracks don't reflow their neighbors when content
// overflows them, the clipped text visually bleeds into the next column
// instead of wrapping or truncating. The graph is pan/zoomable, so a node
// may be as wide as its content needs — nothing is trimmed.
const MIN_ADDR_CH = 9;
const MIN_BYTES_CH = 16;
// px per character for the 10.5px monospace used in block nodes. Slightly
// above the true advance (~0.6em) so the estimate errs wide and never clips.
const CHAR_W = 6.7;
// Non-column chrome: two `gap-x-2` gaps (8px) plus `px-1.5` padding (6px/side).
const NODE_CHROME_W = 2 * 8 + 2 * 6;
// Slack so a rounding error can never clip the last glyph.
const WIDTH_SLACK = 10;

/** Widest addr column for a block, in characters (never below the header). */
function addrColumns(ops: BlockOp[]): number {
	let addr = MIN_ADDR_CH;
	for (const op of ops) addr = Math.max(addr, fmtAddr(op.addr).length);
	return addr;
}

/** Widest byte column for a block, in characters (never below the header). */
function bytesColumns(ops: BlockOp[]): number {
	let bytes = MIN_BYTES_CH;
	for (const op of ops) {
		bytes = Math.max(bytes, formatInstructionBytes(op.bytes).length);
	}
	return bytes;
}

/** CSS grid template shared by the header row and every instruction row. */
function blockColumns(ops: BlockOp[]): string {
	return `${addrColumns(ops)}ch ${bytesColumns(ops)}ch max-content`;
}

/** Node width that fits the longest instruction line without trimming. */
function blockWidth(ops: BlockOp[]): number {
	let instr = "Instruction".length;
	for (const op of ops) {
		instr = Math.max(instr, (op.disasm ?? "").length);
	}
	const contentCh = addrColumns(ops) + bytesColumns(ops) + instr;
	return Math.max(
		BLOCK_W,
		Math.ceil(contentCh * CHAR_W + NODE_CHROME_W + WIDTH_SLACK),
	);
}

function BlockNodeComponent({ data }: NodeProps<BlockNode>) {
	const frameOps = useMemo(
		() =>
			data.insns.map((i) => ({
				addr: 0,
				bytes: "",
				text: i.text ?? i.disasm ?? "",
			})),
		[data.insns],
	);
	const cols = blockColumns(data.ops);
	return (
		<div className="border-border bg-card text-2xs rounded border font-mono shadow-lg">
			<Handle
				type="target"
				position={Position.Top}
				className="!opacity-0"
			/>
			<div className="text-muted-foreground border-border bg-secondary/30 text-2xs flex items-center gap-2 border-b px-1.5 py-0.5">
				<span className="text-primary font-semibold">{data.addr}</span>
				<span className="ml-auto">{data.ops.length} insn</span>
			</div>
			<div
				className="text-muted-foreground border-border text-2xs grid gap-x-2 border-b px-1.5 py-0.5 font-semibold tracking-wider uppercase"
				style={{ gridTemplateColumns: cols }}
			>
				<span className="text-asm-addr">Addr</span>
				<span className="text-asm-bytes">Bytes</span>
				<span>Instruction</span>
			</div>
			<div className="py-0.5">
				{data.ops.map((op, i) => {
					const clickable = !!op.target;
					const { instr, comment } = splitComment(op.disasm ?? "");
					return (
						<div
							key={i}
							className={cn(
								"grid gap-x-2 px-1.5 leading-[17px]",
								clickable &&
									"hover:bg-accent/70 cursor-pointer",
							)}
							style={{ gridTemplateColumns: cols }}
							onClick={
								clickable && op.target
									? () =>
											useAnalysisStore
												.getState()
												.selectFn(op.target as Function)
									: undefined
							}
							title={
								clickable && op.target
									? `Go to ${op.target.name ?? fmtAddr(op.target.addr)}`
									: undefined
							}
						>
							<span
								className="nums text-asm-addr overflow-hidden"
								title="Virtual address"
							>
								{fmtAddr(op.addr)}
							</span>
							<span
								className="text-asm-bytes overflow-hidden whitespace-pre"
								title="Machine code bytes (hex)"
							>
								{formatInstructionBytes(op.bytes)}
							</span>
							<span
								className={cn(
									"text-foreground",
									clickable &&
										"text-primary underline decoration-dotted underline-offset-2",
								)}
								title="Disassembly (mnemonic + operands)"
							>
								{instr && <DisasmInstr text={instr} />}
								<DisasmComment comment={comment} />
								<VarNameChip
									func={data.func}
									insns={frameOps}
									text={instr}
								/>
							</span>
						</div>
					);
				})}
			</div>
			<Handle
				type="source"
				position={Position.Bottom}
				className="!opacity-0"
			/>
		</div>
	);
}

const nodeTypes = { cfgnode: BlockNodeComponent };

function makeEdge(src: string, dst: number, label: string | undefined): Edge {
	const taken = label === "T";
	const failed = label === "F";
	const color = taken ? "#8fd694" : failed ? "#ff7a5c" : "#69727f";
	return {
		id: `${src}->${dst}`,
		source: src,
		target: String(dst),
		type: "smoothstep",
		label,
		style: { stroke: color, strokeWidth: taken || failed ? 1.6 : 1.2 },
		labelStyle: label
			? { fill: color, fontSize: 11, fontWeight: 700 }
			: undefined,
		markerEnd: { type: MarkerType.ArrowClosed, color },
	};
}

function toGraph(
	graph: FunctionGraph,
	byAddr: Map<number, Function>,
): { nodes: BlockNode[]; edges: Edge[] } {
	const blocks = graph.blocks ?? [];
	// Every node carries the function's whole instruction list, because a block
	// only shows its own and the shared list is what names a variable in it.
	// Flattened once here: doing it per node rebuilt the whole function's
	// instructions once per basic block.
	const allOps = blocks.flatMap((blk) => blk.ops ?? []);
	const nodes: BlockNode[] = blocks.map((b) => {
		const ops: BlockOp[] = (b.ops ?? []).map((op) => ({
			...op,
			target: callTarget(op, byAddr),
		}));
		return {
			id: String(b.addr),
			type: "cfgnode",
			data: {
				addr: fmtAddr(b.addr),
				ops,
				func: graph.addr,
				insns: allOps,
			},
			position: { x: 0, y: 0 },
			width: blockWidth(ops),
			height: HEADER_H + COL_H + ops.length * LINE_H + 6,
		};
	});

	const edges: Edge[] = [];
	// Only emit edges between blocks that exist: a jump target that was not
	// decoded as a block would otherwise leave a dangling edge ReactFlow chokes
	// on (common with the native backend's partial CFG).
	const ids = new Set(nodes.map((n) => n.id));
	for (const b of blocks) {
		const src = String(b.addr);
		const conditional = b.jump != null && b.fail != null;
		if (b.jump != null && ids.has(String(b.jump))) {
			edges.push(makeEdge(src, b.jump, conditional ? "T" : undefined));
		}
		if (b.fail != null && ids.has(String(b.fail))) {
			edges.push(makeEdge(src, b.fail, conditional ? "F" : undefined));
		}
		// Computed jump (jump-table / switch): one edge per recovered case.
		for (const target of b.targets ?? []) {
			if (ids.has(String(target))) {
				edges.push(makeEdge(src, target, "case"));
			}
		}
	}
	return { nodes, edges };
}

/**
 * Place every block, in a worker where one is available.
 *
 * A large function's graph is hundreds of blocks, and dagre's pass over all of
 * them blocks the thread it runs on — which is the thread that also has to
 * answer the next click. The worker keeps the window alive while it works; the
 * inline pass is the fallback for an environment without one.
 *
 * @param nodes - The blocks to place.
 * @param edges - The jumps between them.
 * @returns The blocks with positions filled in.
 */
async function layout(nodes: BlockNode[], edges: Edge[]): Promise<BlockNode[]> {
	const request = {
		nodes: nodes.map((n) => ({
			id: n.id,
			width: n.width ?? BLOCK_W,
			height: n.height ?? 80,
		})),
		edges: edges.map((e) => ({ source: e.source, target: e.target })),
	};
	let positions;
	try {
		positions = await layoutInWorker(request);
	} catch {
		positions = layoutInline(request);
	}
	return nodes.map((n, i) => ({ ...n, position: positions[i] }));
}

function GraphCanvas({ addr }: { addr: number }) {
	const [nodes, setNodes, onNodesChange] = useNodesState<BlockNode>([]);
	const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
	const [loading, setLoading] = useState(true);
	const [err, setErr] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		// Read at fetch time rather than subscribing: the address is what decides
		// which graph to show, and taking the function list as a dependency meant
		// every background indexing tick re-fetched the graph over IPC and laid it
		// out again — once a second and a half, while the analyst typed.
		const byAddr = new Map<number, Function>();
		for (const f of useAnalysisStore.getState().funcs) {
			if (typeof f.addr === "number") byAddr.set(f.addr, f);
		}
		api.functionGraph(addr)
			.then(async (g) => {
				if (cancelled) return;
				if (!g || !g.blocks || g.blocks.length === 0) {
					setErr("no graph for this address");
					setLoading(false);
					return;
				}
				const { nodes: ns, edges: es } = toGraph(g, byAddr);
				const placed = await layout(ns, es);
				// A graph that took a moment to lay out can be overtaken by the
				// analyst moving to the next function; the old one must not land.
				if (cancelled) return;
				setNodes(placed);
				setEdges(es);
				setLoading(false);
			})
			.catch((e) => {
				if (!cancelled) {
					setErr(String(e));
					setLoading(false);
				}
			});
		return () => {
			cancelled = true;
		};
	}, [addr, setNodes, setEdges]);

	return (
		<div className="h-full w-full">
			{loading ? (
				<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
					building graph…
				</div>
			) : err ? (
				<div className="border-destructive bg-destructive/10 text-destructive m-3 rounded-md border p-2.5 text-xs">
					{err}
				</div>
			) : nodes.length === 0 ? (
				<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
					No graph.
				</div>
			) : (
				<ReactFlow
					key={addr}
					nodes={nodes}
					edges={edges}
					nodeTypes={nodeTypes}
					onNodesChange={onNodesChange}
					onEdgesChange={onEdgesChange}
					// Each node renders its block's instructions. With every node
					// mounted, a large function's graph meant every instruction of
					// the whole function in the DOM at once, off-screen included.
					onlyRenderVisibleElements
					fitView
					fitViewOptions={{ padding: 0.15 }}
					nodesDraggable={false}
					nodesConnectable={false}
					elementsSelectable
					panOnScroll
					zoomOnScroll={false}
					zoomOnPinch
					zoomOnDoubleClick={false}
					minZoom={0.05}
					proOptions={{ hideAttribution: true }}
					className="bg-background"
				>
					<Controls showInteractive={false} />
				</ReactFlow>
			)}
		</div>
	);
}

export function GraphPanel({ addr }: { addr: number }) {
	// Keying by address remounts the canvas per function so state (loading,
	// nodes) resets cleanly and fitView re-runs.
	return (
		<div className="min-h-0 min-w-0 flex-1">
			<ReactFlowProvider>
				<GraphCanvas key={addr} addr={addr} />
			</ReactFlowProvider>
		</div>
	);
}
