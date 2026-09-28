/**
 * x86 branch verdicts from an instruction's text and the live flags.
 *
 * A conditional branch is the one instruction whose meaning is decided by state
 * that is not in the instruction, so the view has to read the flags to say
 * which way it goes. That verdict is what makes a loop readable: standing on
 * the back edge, `taken` plus the branch's own condition is the whole story,
 * and the target is spelled out in the operand.
 *
 * Text, not bytes: the debuggee's instruction arrives as a rendered line
 * (`je 0x7f1980a095e8`), and a direct target is the last operand when it is a
 * bare address. Anything indirect — `call qword ptr [rip+0x...]` — has no
 * target to show, which is reported as `null` rather than guessed at.
 */

/** x86 RFLAGS bit positions, as `[name, bit]`, for the flags readout. */
export const X86_FLAG_BITS: readonly (readonly [string, number])[] = [
	["CF", 0],
	["PF", 2],
	["AF", 4],
	["ZF", 6],
	["SF", 7],
	["TF", 8],
	["IF", 9],
	["DF", 10],
	["OF", 11],
];

/** The flag bits a conditional branch can read, unpacked. */
export interface X86Flags {
	readonly cf: boolean;
	readonly pf: boolean;
	readonly zf: boolean;
	readonly sf: boolean;
	readonly of: boolean;
	readonly df: boolean;
}

/**
 * Unpack a raw flags register into the bits the branches test.
 *
 * A missing or nonsensical value reads as all-clear, which claims nothing: the
 * condition still evaluates, and the verdict is shown as one of two outcomes
 * either way.
 *
 * ```
 * x86Flags(0x246).zf  // => true   (bit 6, ZF)
 * x86Flags(0x246).cf  // => false
 * x86Flags(null).df   // => false
 * ```
 *
 * @param eflags - The raw flags register, if the target reported one.
 * @returns The flag bits.
 */
export function x86Flags(eflags: number | null | undefined): X86Flags {
	const v =
		typeof eflags === "number" && Number.isFinite(eflags) ? eflags : 0;
	const bit = (name: string): boolean => {
		const row = X86_FLAG_BITS.find(([n]) => n === name);
		return row ? (v & (1 << row[1])) !== 0 : false;
	};
	return {
		cf: bit("CF"),
		pf: bit("PF"),
		zf: bit("ZF"),
		sf: bit("SF"),
		of: bit("OF"),
		df: bit("DF"),
	};
}

/**
 * A flag condition, written the way a C expression would say it.
 *
 * The string *is* the condition, so the verdict text and the test cannot drift
 * apart: the same expression is evaluated and shown.
 */
export type X86Condition =
	| "C"
	| "!C"
	| "Z"
	| "!Z"
	| "C || Z"
	| "!C && !Z"
	| "S"
	| "!S"
	| "O"
	| "!O"
	| "P"
	| "!P"
	| "S==O"
	| "S!=O"
	| "!Z && S==O"
	| "Z || S!=O"
	| "!$CX"
	| "$CX"
	| "$CX && Z"
	| "$CX && !Z";

/** Every conditional jump mnemonic, mapped to the condition it tests. */
const CONDITIONS: Readonly<Record<string, X86Condition>> = {
	ja: "!C && !Z",
	jnbe: "!C && !Z",
	jae: "!C",
	jnb: "!C",
	jnc: "!C",
	jb: "C",
	jc: "C",
	jnae: "C",
	jbe: "C || Z",
	jna: "C || Z",
	je: "Z",
	jz: "Z",
	jne: "!Z",
	jnz: "!Z",
	jg: "!Z && S==O",
	jnle: "!Z && S==O",
	jge: "S==O",
	jnl: "S==O",
	jl: "S!=O",
	jnge: "S!=O",
	jle: "Z || S!=O",
	jng: "Z || S!=O",
	jo: "O",
	jno: "!O",
	jp: "P",
	jpe: "P",
	jnp: "!P",
	jpo: "!P",
	js: "S",
	jns: "!S",
	jcxz: "!$CX",
	jecxz: "!$CX",
	jrcxz: "!$CX",
	// `loop` counts down rather than comparing flags: taken while the counter
	// is left, and its address arithmetic is the direction flag's business, not
	// the branch condition's.
	loop: "$CX",
	loope: "$CX && Z",
	loopz: "$CX && Z",
	loopne: "$CX && !Z",
	loopnz: "$CX && !Z",
};

/** Mnemonics that transfer control without a condition worth reading. */
const CALLS = new Set(["call", "callq", "bl", "blx", "jal"]);

/**
 * Whether a condition holds, given the flags and the loop counter.
 *
 * ```
 * testCondition("Z", x86Flags(1 << 6), 0)   // => true
 * testCondition("!C", x86Flags(0), 0)       // => true
 * testCondition("$CX", x86Flags(0), 0)      // => false
 * ```
 *
 * @param cond - The condition to test.
 * @param flags - The flag bits.
 * @param cx - The counter register, for the `loop` family.
 * @returns True when the branch would be taken.
 */
export function testCondition(
	cond: X86Condition,
	flags: X86Flags,
	cx: number,
): boolean {
	switch (cond) {
		case "C":
			return flags.cf;
		case "!C":
			return !flags.cf;
		case "Z":
			return flags.zf;
		case "!Z":
			return !flags.zf;
		case "C || Z":
			return flags.cf || flags.zf;
		case "!C && !Z":
			return !flags.cf && !flags.zf;
		case "S":
			return flags.sf;
		case "!S":
			return !flags.sf;
		case "O":
			return flags.of;
		case "!O":
			return !flags.of;
		case "P":
			return flags.pf;
		case "!P":
			return !flags.pf;
		case "S==O":
			return flags.sf === flags.of;
		case "S!=O":
			return flags.sf !== flags.of;
		case "!Z && S==O":
			return !flags.zf && flags.sf === flags.of;
		case "Z || S!=O":
			return flags.zf || flags.sf !== flags.of;
		case "!$CX":
			return cx === 0;
		case "$CX":
			return cx !== 0;
		case "$CX && Z":
			return cx !== 0 && flags.zf;
		case "$CX && !Z":
			return cx !== 0 && !flags.zf;
	}
}

/** What kind of control transfer an instruction is. */
export type BranchKind = "conditional" | "call" | "jump" | "ret";

/** An instruction that transfers control, and where it can be read off. */
export interface Branch {
	readonly kind: BranchKind;
	readonly mnemonic: string;
	/** The condition a conditional branch tests, else null. */
	readonly condition: X86Condition | null;
	/** A direct destination address, or null when the transfer is indirect. */
	readonly target: number | null;
}

/**
 * Read a branch out of a disassembled line, or null if it is not one.
 *
 * The mnemonic decides the kind, the last operand is the destination when it is
 * a bare address, and anything after `;` is a comment rather than an operand.
 *
 * ```
 * classifyInsn("je 0x7f1980a095e8").condition   // => "Z"
 * classifyInsn("jbe 0x7a8ab0a3f586").target    // => 0x7a8ab0a3f586
 * classifyInsn("call 0x710").kind               // => "call"
 * classifyInsn("mov rax, rdx")                  // => null
 * classifyInsn("call qword ptr [rip+0x3fb6]").target // => null, indirect
 * ```
 *
 * @param text - One disassembled line, comment included.
 * @returns The branch, or null when the line does not transfer control.
 */
export function classifyInsn(text: string): Branch | null {
	const body = text.split(";")[0].trim();
	if (body === "") return null;
	const parts = body.split(/\s+/);
	const mnemonic = parts[0].toLowerCase();
	const condition = CONDITIONS[mnemonic] ?? null;
	const isCall = CALLS.has(mnemonic);
	if (
		condition === null &&
		!isCall &&
		mnemonic !== "jmp" &&
		mnemonic !== "ret"
	) {
		return null;
	}
	const kind: BranchKind = condition
		? "conditional"
		: isCall
			? "call"
			: mnemonic === "jmp"
				? "jump"
				: "ret";
	return { kind, mnemonic, condition, target: directTarget(parts.slice(1)) };
}

/**
 * The address a jump goes to, when the instruction names one.
 *
 * ```
 * directTarget(["0x7a8ab0a3f586"])            // => 0x7a8ab0a3f586
 * directTarget(["4102", "; loop"])            // => 4102
 * directTarget(["qword", "ptr", "[rip+0x3f]"]) // => null
 * ```
 *
 * @param operands - The instruction's operands, already split on whitespace.
 * @returns The address, or null when it is indirect or absent.
 */
function directTarget(operands: readonly string[]): number | null {
	for (let i = operands.length - 1; i >= 0; i--) {
		// An address may be bracketed (`[0x... ]`) or trailing-punctuated, so the
		// wrappers come off before the token is asked whether it is one.
		const tok = operands[i].replace(/[,[\]()]/g, "");
		if (!/^(0x[0-9a-f]+|\d+)$/i.test(tok)) continue;
		const addr = Number(tok);
		return Number.isFinite(addr) ? addr : null;
	}
	return null;
}

/** Which way a branch goes, and the condition that says so. */
export interface BranchVerdict {
	readonly taken: boolean;
	/** The condition as a C expression — what makes the verdict checkable. */
	readonly reason: string;
}

/**
 * Evaluate a branch against the live state.
 *
 * A conditional branch gets a verdict from the flags; a call, jump or return
 * has no condition to read, so it gets none — there is nothing to guess.
 *
 * ```
 * const b = classifyInsn("jbe 0x7a8ab0a3f586")!;
 * branchVerdict(b, x86Flags(1 << 6), 0).taken   // => true, ZF set
 * branchVerdict(b, x86Flags(0), 0).taken        // => false
 * branchVerdict(classifyInsn("jmp 0x1")!, x86Flags(0), 0) // => null
 * ```
 *
 * @param branch - The instruction, as read by {@link classifyInsn}.
 * @param flags - The flag bits at the cursor.
 * @param cx - The counter register, for the `loop` family.
 * @returns The verdict, or null when the instruction is unconditional.
 */
export function branchVerdict(
	branch: Branch | null,
	flags: X86Flags,
	cx: number,
): BranchVerdict | null {
	if (branch?.condition == null) return null;
	const taken = testCondition(branch.condition, flags, cx);
	return { taken, reason: branch.condition };
}

/**
 * The verdict as one line of text, negating the condition when it did not hold
 * so both outcomes read the same way.
 *
 * ```
 * verdictText({ taken: true, reason: "C || Z" })
 * // => "taken [C || Z]"
 * verdictText({ taken: false, reason: "C || Z" })
 * // => "not taken [!(C || Z)]"
 * ```
 *
 * @param verdict - The verdict to phrase.
 * @returns The label for the instruction row.
 */
export function verdictText(verdict: BranchVerdict): string {
	return verdict.taken
		? `taken [${verdict.reason}]`
		: `not taken [!(${verdict.reason})]`;
}

/**
 * The address whose code is worth showing under this branch: where a taken
 * conditional branch is about to land, or the callee of a direct call.
 *
 * An untaken branch, a plain `jmp` and a `ret` have nothing to show, so they
 * peek at nothing and the view keeps its straight-line lookahead instead.
 *
 * ```
 * peekTarget(classifyInsn("je 0x1")!, { taken: true, reason: "Z" })  // => 1
 * peekTarget(classifyInsn("je 0x1")!, { taken: false, reason: "Z" }) // => null
 * peekTarget(classifyInsn("call 0x710")!, null)                    // => 0x710
 * ```
 *
 * @param branch - The instruction, as read by {@link classifyInsn}.
 * @param verdict - Its verdict, or null when unconditional.
 * @returns The address to show, or null.
 */
export function peekTarget(
	branch: Branch | null,
	verdict: BranchVerdict | null,
): number | null {
	if (branch?.target == null) return null;
	if (branch.kind === "conditional")
		return verdict?.taken ? branch.target : null;
	return branch.kind === "call" ? branch.target : null;
}
