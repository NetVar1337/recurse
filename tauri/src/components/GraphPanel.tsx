import {
	createContext,
	memo,
	useContext,
	useEffect,
	useMemo,
	useState,
} from "react";
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
	useViewport,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { api } from "@/api";
import { layoutInline, layoutInWorker } from "@/lib/dagreLayout";
import { cn } from "@/lib/utils";
import { callTarget } from "@/lib/calls";
import {
	AsmTokens,
	DisasmComment,
	formatInstructionBytes,
	splitComment,
	tokenizeAsm,
	type Token,
} from "@/lib/disasm";
import { useVarRename, VarNameField } from "@/components/VarNameChip";
import { frameOf, slotIn, type Frame } from "@/lib/debugVars";
import { useAnalysisStore } from "@/store/analysisStore";
import type { Function, FunctionGraph } from "@/types";

const BLOCK_W = 380;
const LINE_H = 17;
const HEADER_H = 24;
const COL_H = 15;

/**
 * How many instructions a graph may carry before only the visible part of it is
 * kept in the DOM.
 *
 * A node is mounted every time it crosses into view, so below this the whole
 * graph is mounted once and never touched again — a smaller graph spends
 * nothing to be held, and paying a mount on every pan to save memory it did not
 * need would be the more expensive mistake. Above it, the DOM would be large
 * enough that keeping all of it costs more than the churn.
 */
const WINDOW_THRESHOLD = 1_200;

/**
 * The zoom at which variable names appear in the graph.
 *
 * A name is a 10px label beside an operand. Below this it is not read, it is
 * only clutter — and clutter in a node is a cost paid on every node in view,
 * which is the cost that decides whether a pan holds its rate. Past it, a name
 * is worth the room and the analyst is looking closely enough to want it.
 */
const NAME_ZOOM = 0.85;

function fmtAddr(a?: number | null) {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}
/**
 * One instruction row, with everything the node needs already worked out.
 *
 * Tokenizing an instruction and formatting its bytes are per-character and
 * per-regex passes, and a node mounted them again for every one of its rows.
 * A block's rows are prepared once, when the graph is built, so mounting a node
 * is reconciliation and nothing else — which is the whole cost of a node
 * crossing into view while the analyst is panning.
 */
type BlockRow = {
	/** The address, formatted. */
	addr: string;
	/** The machine code, spaced hex. */
	bytes: string;
	/** The instruction, split into coloured tokens. */
	tokens: Token[];
	/** The instruction as written, without its comment — what a name is read from. */
	instr: string;
	/** The `; …` suffix, or empty. */
	comment: string;
	/** The function this instruction calls, if it calls one. */
	target: Function | null;
};

type BlockData = {
	addr: string;
	/** How many instructions the block holds, for its header. */
	count: number;
	rows: BlockRow[];
	/** The CSS grid template the header and every row share. */
	cols: string;
	/**
	 * How the function addresses its frame, worked out once for the whole body.
	 *
	 * A frame belongs to a function, not to a block: whether `[rbp - 0x18]` is a
	 * slot at all, and which one, depends on every instruction in the body. So it
	 * is read once when the graph is built rather than once per node, and handed
	 * to each node ready to use.
	 */
	frame: Frame;
	/** The function's address, which is what a name is keyed by. */
	func: number;
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
function addrColumns(rows: BlockRow[]): number {
	let addr = MIN_ADDR_CH;
	for (const row of rows) addr = Math.max(addr, row.addr.length);
	return addr;
}

/** Widest byte column for a block, in characters (never below the header). */
function bytesColumns(rows: BlockRow[]): number {
	let bytes = MIN_BYTES_CH;
	for (const row of rows) {
		bytes = Math.max(bytes, row.bytes.length);
	}
	return bytes;
}

/** CSS grid template shared by the header row and every instruction row. */
function blockColumns(rows: BlockRow[]): string {
	return `${addrColumns(rows)}ch ${bytesColumns(rows)}ch max-content`;
}

/** Node width that fits the longest instruction line without trimming. */
function blockWidth(rows: BlockRow[]): number {
	let instr = "Instruction".length;
	for (const row of rows) {
		let width = 0;
		for (const token of row.tokens) width += token.text.length;
		instr = Math.max(instr, width + row.comment.length + 3);
	}
	const contentCh = addrColumns(rows) + bytesColumns(rows) + instr;
	return Math.max(
		BLOCK_W,
		Math.ceil(contentCh * CHAR_W + NODE_CHROME_W + WIDTH_SLACK),
	);
}

/**
 * What the graph's nodes need to know that is not their own.
 *
 * Held in one context rather than read per node: a node that subscribed to the
 * variable-name map on its own would re-render every chip in the graph on every
 * rename, and a node that subscribed to the viewport would re-render on every
 * frame of a pan. The name map changes when a variable is named, and the zoom
 * flag changes when the analyst crosses the threshold — neither is a per-frame
 * event, so neither belongs in a frame's work.
 */
const GraphDetail = createContext<{
	/** Variable names, keyed by `${function}:${slot}`. */
	names: Record<string, string>;
	/** Whether the graph is zoomed in far enough for names to be legible. */
	namesVisible: boolean;
}>({ names: {}, namesVisible: false });

/**
 * A variable's name, beside the operand that touches it, inside a graph node.
 *
 * The same name, the same key and the same write as the listing — a rename here
 * is a rename there and in the debugger — but shown only once the graph is zoomed
 * in far enough for a 10px label to be read.
 *
 * @param props.frame - How the function addresses its frame, worked out once for
 *   the whole function rather than per row.
 * @param props.func - The function's address, which names are keyed by.
 * @param props.text - The instruction this sits beside.
 * @returns The name, which opens a field when clicked.
 */
function GraphVarName({
	frame,
	func,
	text,
}: {
	frame: Frame;
	func: number;
	text: string;
}) {
	const { names } = useContext(GraphDetail);
	const rename = useVarRename({ func, slot: slotIn(text, frame), names });
	if (!rename.present) return null;
	if (rename.editing) {
		// Sized for the graph's own type scale, which is a step below the
		// listing's.
		return <VarNameField rename={rename} className="text-2xs w-[10ch]" />;
	}
	return (
		<span
			className={cn(
				"text-2xs mx-1 font-mono",
				rename.named
					? "text-asm-symbol italic"
					: "text-muted-foreground/70",
				"hover:bg-accent/50 hover:text-foreground rounded px-0.5",
			)}
			title={
				rename.named
					? "Click to rename this variable"
					: "Derived from the slot's offset — click to name it"
			}
			onClick={(e) => {
				// A graph is panned by dragging it, so a click that opens a field
				// must not also be read as the start of a pan.
				e.stopPropagation();
				rename.begin();
			}}
		>
			{rename.shown}
		</span>
	);
}

/**
 * One basic block: its address, and its instructions.
 *
 * Memoized, and given rows that are already prepared, so a node does no work of
 * its own to appear. A node entering the viewport while the analyst pans pays
 * only for being put in the DOM, which is the smallest cost React can be asked
 * for — the alternative is re-tokenizing every instruction of the block each
 * time it crosses the edge of the screen.
 */
const BlockNodeComponent = memo(function BlockNodeComponent({
	data,
}: NodeProps<BlockNode>) {
	const { namesVisible } = useContext(GraphDetail);
	return (
		<div className="border-border bg-card text-2xs rounded border font-mono shadow-lg">
			<Handle
				type="target"
				position={Position.Top}
				className="!opacity-0"
			/>
			<div className="text-muted-foreground border-border bg-secondary/30 text-2xs flex items-center gap-2 border-b px-1.5 py-0.5">
				<span className="text-primary font-semibold">{data.addr}</span>
				<span className="ml-auto">{data.count} insn</span>
			</div>
			<div
				className="text-muted-foreground border-border text-2xs grid gap-x-2 border-b px-1.5 py-0.5 font-semibold tracking-wider uppercase"
				style={{ gridTemplateColumns: data.cols }}
			>
				<span className="text-asm-addr">Addr</span>
				<span className="text-asm-bytes">Bytes</span>
				<span>Instruction</span>
			</div>
			<div className="py-0.5">
				{data.rows.map((row, i) => (
					<div
						key={i}
						className={cn(
							"grid gap-x-2 px-1.5 leading-[17px]",
							row.target && "hover:bg-accent/70 cursor-pointer",
						)}
						style={{ gridTemplateColumns: data.cols }}
						onClick={
							row.target
								? () =>
										useAnalysisStore
											.getState()
											.selectFn(row.target as Function)
								: undefined
						}
						title={
							row.target
								? `Go to ${row.target.name ?? fmtAddr(row.target.addr)}`
								: undefined
						}
					>
						<span
							className="nums text-asm-addr overflow-hidden"
							title="Virtual address"
						>
							{row.addr}
						</span>
						<span
							className="text-asm-bytes overflow-hidden whitespace-pre"
							title="Machine code bytes (hex)"
						>
							{row.bytes}
						</span>
						<span
							className={cn(
								"text-foreground",
								row.target &&
									"text-primary underline decoration-dotted underline-offset-2",
							)}
							title="Disassembly (mnemonic + operands)"
						>
							<AsmTokens tokens={row.tokens} />
							<DisasmComment comment={row.comment} />
							{namesVisible && (
								<GraphVarName
									frame={data.frame}
									func={data.func}
									text={row.instr}
								/>
							)}
						</span>
					</div>
				))}
			</div>
			<Handle
				type="source"
				position={Position.Bottom}
				className="!opacity-0"
			/>
		</div>
	);
});

const nodeTypes = { cfgnode: BlockNodeComponent };

/**
 * One jump, as an edge between two blocks.
 *
 * Which way a conditional went is carried by colour alone. A `T`/`F`/`case` text
 * label said the same thing twice, and every label is a text element and a
 * background rectangle in the SVG layer — the most expensive thing per edge in
 * the view, for information the colour was already giving.
 *
 * @param src - The block the jump leaves.
 * @param dst - The block it arrives at.
 * @param label - `T` for the taken arm, `F` for the one not taken, `case` for a
 *   jump-table entry, or undefined for an unconditional jump.
 * @returns The edge.
 */
function makeEdge(src: string, dst: number, label: string | undefined): Edge {
	const taken = label === "T";
	const failed = label === "F";
	const color = taken ? "#8fd694" : failed ? "#ff7a5c" : "#69727f";
	return {
		id: `${src}->${dst}`,
		source: src,
		target: String(dst),
		type: "smoothstep",
		style: { stroke: color, strokeWidth: taken || failed ? 1.6 : 1.2 },
		markerEnd: { type: MarkerType.ArrowClosed, color },
	};
}

function toGraph(
	graph: FunctionGraph,
	byAddr: Map<number, Function>,
): { nodes: BlockNode[]; edges: Edge[] } {
	const blocks = graph.blocks ?? [];
	// The frame is a property of the whole function, so it is read once here
	// rather than by each node: every node needs it, and reading it per node meant
	// walking every instruction of the body once per block. Normalized on the way,
	// because a graph reports its disassembly under `disasm` and frame analysis
	// reads `text`.
	const frame = frameOf(
		blocks.flatMap((b) =>
			(b.ops ?? []).map((op) => ({
				addr: op.addr,
				bytes: op.bytes ?? "",
				text: op.disasm ?? "",
			})),
		),
	);
	const nodes: BlockNode[] = blocks.map((b) => {
		// Prepared here rather than in the node, so that the work happens once
		// per instruction instead of once per instruction per mount. A node is
		// mounted every time it crosses into view, and a pan is nothing but
		// nodes crossing into view.
		const rows: BlockRow[] = (b.ops ?? []).map((op) => {
			const { instr, comment } = splitComment(op.disasm ?? "");
			return {
				addr: fmtAddr(op.addr),
				bytes: formatInstructionBytes(op.bytes),
				tokens: tokenizeAsm(instr),
				instr,
				comment,
				target: callTarget(op, byAddr),
			};
		});
		const cols = blockColumns(rows);
		return {
			id: String(b.addr),
			type: "cfgnode",
			data: {
				addr: fmtAddr(b.addr),
				count: rows.length,
				rows,
				cols,
				frame,
				func: graph.addr,
			},
			position: { x: 0, y: 0 },
			width: blockWidth(rows),
			height: HEADER_H + COL_H + rows.length * LINE_H + 6,
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

	// A graph this size is held in the DOM whole; past it, only what is on
	// screen is. The threshold is about mount cost during a pan, so it counts
	// the instructions a graph carries rather than its blocks: a graph of a few
	// hundred very large blocks costs more to keep mounted than one of a few
	// hundred small ones.
	const windowed = useMemo(
		() =>
			nodes.reduce((sum, n) => sum + n.data.count, 0) > WINDOW_THRESHOLD,
		[nodes],
	);

	// Variable names, but only once they are big enough to read. The zoom itself
	// comes from a subscription, so a pan re-renders this panel — but the flag it
	// produces only changes when the analyst crosses the threshold, and it is the
	// flag the nodes read, so a pan that stays on one side of it re-renders no
	// node at all.
	const { zoom } = useViewport();
	const namesVisible = zoom >= NAME_ZOOM;
	const names = useAnalysisStore((s) => s.variableNames);
	const detail = useMemo(
		() => ({ names, namesVisible }),
		[names, namesVisible],
	);

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
				<GraphDetail.Provider value={detail}>
					<ReactFlow
						key={addr}
						nodes={nodes}
						edges={edges}
						nodeTypes={nodeTypes}
						onNodesChange={onNodesChange}
						onEdgesChange={onEdgesChange}
						// Only for a graph too big to hold at once. Below the threshold the
						// whole graph is mounted once and then left alone, because
						// otherwise every node crossing the edge of the screen while the
						// analyst pans is mounted and unmounted again — work bought with
						// the smoothness of the gesture itself.
						onlyRenderVisibleElements={windowed}
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
				</GraphDetail.Provider>
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
