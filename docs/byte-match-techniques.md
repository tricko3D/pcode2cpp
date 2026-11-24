# General techniques for byte-exact matching decompilation

This is a **toolchain-agnostic diagnostic catalog** for source-to-binary matching.
It contains no target function, game, address, historical compiler pin, proof verdict or experiment result.
Examples that depend on a compiler phase, ISA, source language or ABI are **conditional hypotheses**, not guaranteed transformations.

## Universal diagnostic axes (12 questions)

1. What are the exact compiler, frontend, backend, optimization flags and translation-unit context?
2. Is the matching target object code, relocation-aware function code, linked executable bytes, or behavioral equivalence?
3. Are instruction differences genuine, rather than relocations, symbol names, padding or alignment?
4. Is the first differing instruction created by lowering, optimization, allocation, scheduling, or linking?
5. Do the inputs have identical ABI, calling convention, type widths, alignment and object layouts?
6. Does memory aliasing create or remove legal load/store dependencies?
7. Has value numbering, common-subexpression elimination or copy propagation changed the intermediate representation?
8. Are live ranges, interference, register preferences and spill decisions different?
9. Are the mismatched instructions in the same scheduler region, with comparable dependency graphs?
10. Could a control-flow, statement-order or expression-form difference alter an earlier compiler phase?
11. What is the smallest experiment or compiler trace that could discriminate the leading causes?
12. Does the proposed transformation preserve behavior under the verification model, not merely improve a similarity score?

## Complete cross-toolchain catalog

Each numbered entry is an investigation axis or **possible** source-level transformation. Not every entry applies to every compiler. Prefer evidence from the relevant compiler's actual behavior over general folklore.

### Toolchain provenance and reproducibility

1. [BUILD] Identify the exact compiler family, release, patch level, and executable hashes, as small backend changes may alter instructions.
2. [BUILD] Determine the actual code-generation flags rather than assuming default optimization settings.
3. [BUILD] Match the target architecture, ABI variant, target CPU, endianness, and floating-point ABI.
4. [BUILD] Account for debug/release mode, profile-guided optimization, link-time optimization, and whole-program compilation.
5. [BUILD] Distinguish C, C++, Objective-C, Rust, and other source frontends that lower similar constructs differently.
6. [BUILD] Check language dialect, extension switches, implementation-defined behavior, and compiler-specific pragmas.
7. [BUILD] Recreate relevant headers, macros, type definitions, and inline function bodies from the build.
8. [BUILD] Match the complete translation-unit compilation context, not merely the isolated function body.
9. [BUILD] Check structure packing, alignment switches, enum width, bitfield layout and calling-convention defaults.
10. [BUILD] Identify security instrumentation, stack probes, sanitizer hooks, exception-handling mode and runtime model.
11. [BUILD] Check compiler behavior under optimization-for-size versus optimization-for-speed profiles.
12. [BUILD] Separate code differences caused at compile time from those introduced during assembly or linking.

### Object files, linkers and binary layout

13. [LINK] Distinguish source-to-object code matching from whole-binary or final-executable matching.
14. [LINK] Match assembler syntax, instruction relaxation policy, and target instruction encoding modes.
15. [LINK] Account for relocation records and symbolic references instead of comparing unresolved addresses literally.
16. [LINK] Ensure calls, global references and jump tables target the same entities, not just the same relocation kinds.
17. [LINK] Separate symbol name decoration and linkage visibility from executed machine instructions.
18. [LINK] Account for position-independent code, GOT/PLT indirection, TLS, import thunks and interworking stubs.
19. [LINK] Reproduce function-section granularity, COMDAT folding, identical-code folding and section ordering.
20. [LINK] Check linker-generated veneers, trampolines, thunks and long-branch relaxation.
21. [LINK] Account for alignment directives, padding bytes, function hot/cold splitting and padding between sections.
22. [LINK] Check constant-pool, string-pool, literal-pool and jump-table placement.
23. [LINK] Distinguish compiler-generated function bytes from linker-inserted stubs or metadata.
24. [LINK] Verify build reproducibility and normalize timestamps or nonsemantic binary metadata only when the matching goal permits.

### Frontend representations and type information

25. [FRONTEND] Compare pointer arithmetic in elements with equivalent byte-based address calculations.
26. [FRONTEND] Compare array subscripts, dereference expressions, and named structure-field accesses when their types permit.
27. [FRONTEND] Investigate whether explicit casts affect operand widths, sign extension, alias sets or conversion placement.
28. [FRONTEND] Test integral signedness and size assumptions, including enumeration and integer-promotion rules.
29. [FRONTEND] Check whether a source-level temporary survives frontend simplification or becomes a pure expression.
30. [FRONTEND] Distinguish a declaration with initialization from a later assignment, especially for nontrivial objects.
31. [FRONTEND] Compare nested arithmetic expressions, reassociation and grouped operations without changing overflow behavior.
32. [FRONTEND] Consider syntactically different but provably equivalent boolean expressions and conditional operators.
33. [FRONTEND] Check how sequence points and evaluation order influence observable loads, stores and calls.
34. [FRONTEND] Examine member-function versus free-function lowering, implicit object parameters and virtual dispatch.
35. [FRONTEND] Check template instantiation, inline helpers, macro expansion and overload resolution in languages that support them.
36. [FRONTEND] Identify aggregate initialization, copies, constructors, destructors, and implicit return-object handling.
37. [FRONTEND] Inspect compiler-generated temporaries for references, iterators, proxy objects and expression templates.
38. [FRONTEND] Check whether implicit conversions, constness, restrict-like qualifiers and atomic semantics alter optimization assumptions.

### Dataflow, memory and alias analysis

39. [DATA] Map each value's definitions and uses across basic blocks before changing source expressions.
40. [DATA] Distinguish must-alias, may-alias, and proven-disjoint memory accesses, including unusual pointer overlaps.
41. [DATA] Analyze load/store movement constraints using read-after-write, write-after-read and write-after-write dependencies.
42. [DATA] Check whether an address is recomputed, reused as a local, or read back from previously stored memory.
43. [DATA] Inspect whether a named pointer copy or reference alias changes alias analysis and value numbering.
44. [DATA] Check whether intervening calls, pointer stores or unknown effects invalidate a previously loaded value.
45. [DATA] Identify common-subexpression elimination that merges expressions or loads from the same value number.
46. [DATA] Look for expression reassociation that prevents or creates common subexpressions.
47. [DATA] Distinguish direct memory operands from register-cached values and reloaded values.
48. [DATA] Check whether rematerialization is cheaper than keeping an address, constant or simple expression live.
49. [DATA] Examine dead-store elimination, dead-code elimination and partial redundancy elimination.
50. [DATA] Analyze copy propagation, constant propagation and folding before register allocation.
51. [DATA] Distinguish scalar replacement of aggregates and promotion of memory-backed variables to registers.
52. [DATA] Check how volatile, atomics, barriers and concurrency rules constrain reordering and load coalescing.
53. [DATA] Check whether read-modify-write folding requires a memory leaf rather than a common-subexpression temporary.
54. [DATA] Compare source expressions that share an address but receive different alias classes in the compiler's intermediate representation.

### Integer, floating-point and vector semantics

55. [ARITH] Check arithmetic width, wraparound, trapping behavior and undefined signed overflow before transformations.
56. [ARITH] Investigate multiply/divide-by-constant strength reduction and power-of-two optimization.
57. [ARITH] Compare shift and rotate formulations, accounting for operand width and out-of-range shift behavior.
58. [ARITH] Check bitfield extraction, sign extension, zero extension, masks and partial-register operations.
59. [ARITH] Distinguish compare-and-branch from subtract/test or fused compare forms.
60. [ARITH] Inspect compiler choices between arithmetic flags and explicit boolean materialization.
61. [ARITH] Check the treatment of zero constants, all-ones values, narrow immediates and materialized literal registers.
62. [ARITH] Account for floating-point precision modes, excess precision, rounding, contraction and reassociation flags.
63. [ARITH] Distinguish fused multiply-add from multiply-plus-add, and account for contraction settings.
64. [ARITH] Check signed zero, NaNs, infinities and exceptional floating-point behavior when changing expression order.
65. [ARITH] Inspect vectorization, scalarization, widening and packed-versus-scalar instruction choices.
66. [ARITH] Account for alignment assumptions and unaligned-memory instruction sequences.
67. [ARITH] Check division and remainder semantics for signed operands, especially around negative values.
68. [ARITH] Distinguish implementation-specific library calls from inline arithmetic expansions.

### Register allocation and value lifetimes

69. [REG] Identify which values are assigned physical registers and which are spilled.
70. [REG] Map live ranges, especially values that must remain available across calls.
71. [REG] Check register classes and architectural register constraints before attributing a mismatch to allocation.
72. [REG] Inspect interference between simultaneously live values and their legal register sets.
73. [REG] Investigate reference counts, use frequency and loop/block weights that affect allocation priority.
74. [REG] Compare move/coalescing opportunities and register preferences caused by copies or call arguments.
75. [REG] Identify live-range splitting, reloads and spill placement instead of treating a register rename as a local issue.
76. [REG] Check whether introducing or removing a real use changes lifetime endpoints.
77. [REG] Analyze first-use and last-use positions, including definitions moved across basic-block boundaries.
78. [REG] Compare named locals, short-lived temporaries and aliases as distinct allocator candidates.
79. [REG] Inspect operand constraints, tied operands, fixed-register instructions and calling-convention registers.
80. [REG] Consider register allocator tie-breaks based on definition order, block order or internal numbering.
81. [REG] Check callee-saved register pressure and preservation sequences across calls.
82. [REG] Examine scratch-register allocation separately from long-lived register allocation.
83. [REG] Check whether low-level copies survive late optimization or get coalesced away.
84. [REG] Measure allocator effects with compiler traces or minimal probes where the compiler exposes such evidence.

### Control flow and code layout

85. [CFG] Compare equivalent if/else shapes, branch inversion and fallthrough preference.
86. [CFG] Inspect loop idioms such as while, do-while, for and explicit backedge branches.
87. [CFG] Check early returns versus shared epilogues and tail-merged blocks.
88. [CFG] Identify tail-call eligibility and compare call-plus-return against jump-based tail calls.
89. [CFG] Inspect switch lowering to chains, jump tables, binary-search trees or bit tests.
90. [CFG] Consider branch prediction metadata and profile-directed basic-block placement.
91. [CFG] Check cross-jumping, tail merging, head merging and identical-branch elimination.
92. [CFG] Distinguish control-flow changes visible before register allocation from those simplified afterward.
93. [CFG] Analyze fallthrough labels, block alignment and branch displacement relaxation.
94. [CFG] Verify that reordered independent statements do not cross observable side effects.
95. [CFG] Check whether artificial branches survive long enough to influence earlier compiler phases.
96. [CFG] Investigate exception and cleanup edges that alter the control-flow graph despite similar source.

### Instruction selection and peepholes

97. [ISEL] Identify where the compiler chooses an instruction opcode rather than merely its destination register.
98. [ISEL] Compare address-generation instructions with arithmetic sequences that compute the same pointer.
99. [ISEL] Check load-plus-operation fusion, folded memory operands and explicit register loads.
100. [ISEL] Inspect store width, operand size, immediate width and encoding alternatives for the same value.
101. [ISEL] Consider zeroing idioms and their impact on flags and dependency tracking.
102. [ISEL] Compare compare/test alternatives, conditional moves, setcc, and branch-based boolean sequences.
103. [ISEL] Inspect commutative operand order and destructive destination selection.
104. [ISEL] Look for compiler-specific peepholes that remove redundant compares, moves or extensions.
105. [ISEL] Check whether an instruction is generated before or after a particular optimization phase.
106. [ISEL] Consider specialized target instructions, intrinsics and library-call lowering.
107. [ISEL] Distinguish instruction selection differences from later scheduling and register allocation differences.
108. [ISEL] Inspect whether multiple instructions become a single read-modify-write instruction or the reverse.

### Instruction scheduling

109. [SCHED] Determine whether the differing instructions are inside the same schedulable region.
110. [SCHED] Identify hard scheduling boundaries such as calls, barriers, labels, returns or compiler-inserted prologue/epilogue markers.
111. [SCHED] Build the dependency graph using true, anti, output and memory dependencies.
112. [SCHED] Inspect memory-alias edges that force a load or store to remain ordered.
113. [SCHED] Check critical-path height and successor counts when the scheduler uses priority-based selection.
114. [SCHED] Compare source order and intermediate-representation order as potential tie-break inputs.
115. [SCHED] Consider latency tables, issue resources and target CPU scheduling model.
116. [SCHED] Distinguish independent instruction reordering from changes caused by register allocation.
117. [SCHED] Inspect whether the scheduler can legally cross a call or move a parameter load across a stack change.
118. [SCHED] Use a pre-/post-scheduling intermediate-representation trace when available.
119. [SCHED] Check if instruction order changed through earlier optimization rather than the scheduler itself.
120. [SCHED] Test a minimal compiler probe that varies one dependency while preserving observable semantics.

### Stack frames, ABI and function boundaries

121. [ABI] Reconstruct calling convention, hidden parameters and stack-cleanup responsibility.
122. [ABI] Identify argument placement, register-passed versus stack-passed parameters and varargs behavior.
123. [ABI] Analyze prologue generation, callee-saved spills and epilogue restoration separately from body scheduling.
124. [ABI] Account for stack-frame pointer omission, red zones, home areas and shadow space where applicable.
125. [ABI] Check stack alignment requirements and dynamic realignment when local objects demand it.
126. [ABI] Inspect stack protector cookies, probing, canaries and exception-registration records.
127. [ABI] Check whether address-taken locals force stack slots that otherwise disappear.
128. [ABI] Analyze spill-slot reuse, lifetime overlap and stack-slot packing.
129. [ABI] Examine tail-call constraints created by ABI, stack arguments or cleanup code.
130. [ABI] Account for return conventions for aggregates, floating-point values and multiple-register returns.
131. [ABI] Inspect compiler-generated destructors, unwind metadata and function personality routines.
132. [ABI] Separate stack-offset changes caused by prologue size from changes to actual memory-access semantics.

### Architecture-specific effects

133. [ARCH] Classify which hypotheses require a particular instruction set, target ABI or architecture revision.
134. [ARCH] Consider delay slots and instruction bundling only on architectures where they exist.
135. [ARCH] Account for register windows, condition-code registers and predicate registers where supported.
136. [ARCH] Check load/store addressing modes, scaled indexes and update-form addressing that vary by ISA.
137. [ARCH] Examine literal pools, PC-relative ranges and branch island insertion on relevant targets.
138. [ARCH] Consider compressed instruction encodings and alignment restrictions.
139. [ARCH] Account for big-endian versus little-endian field access and struct layout.
140. [ARCH] Inspect weak memory ordering, instruction barriers and atomic instruction sequences.
141. [ARCH] Distinguish fixed-width and variable-length instruction encodings when comparing raw byte distances.
142. [ARCH] Check platform-specific veneers or ABI thunks inserted between compiled functions.

### Verification, scoring and search discipline

143. [VERIFY] Confirm whether the objective is exact object bytes, relocation-aware function identity, assembly shape or executable identity.
144. [VERIFY] Compare the first meaningful mismatch rather than relying exclusively on a global similarity percentage.
145. [VERIFY] Normalize only deliberately irrelevant relocations and metadata, not real callee or global mismatches.
146. [VERIFY] Record compiler stdout, command line, source hashes and complete diff evidence for every variant.
147. [VERIFY] Deduplicate candidates by compiled machine code as well as source text.
148. [VERIFY] Maintain a known-good verified candidate separately from unproven lower-distance variants.
149. [VERIFY] Use differential execution to reject behavioral mistakes, while recognizing limits of sampled inputs.
150. [VERIFY] Use symbolic or formal equivalence checks under explicit assumptions when available.
151. [VERIFY] Treat a proof of behavioral equivalence as different from an exact machine-code match.
152. [VERIFY] Check undefined behavior, aliasing, integer overflow and floating-point differences before calling a mutation semantics-preserving.
153. [VERIFY] Use metamorphic or synthetic micro-probes to isolate uncertain compiler behavior.
154. [VERIFY] Preserve the exact target compiler and flags during local matching experiments.
155. [VERIFY] Compare search strategies under equal compile budgets, not simply by number of source edits.
156. [VERIFY] Track source-to-machine novelty and stop when a mutation family repeatedly compiles to the same code.
157. [VERIFY] Keep architecture and compiler-specific heuristics tagged as conditional, not universal facts.
158. [VERIFY] Distinguish original source recovery, functional source reconstruction, and compiler-output reproduction.

## Research foundations and tool examples

- [decomp-permuter](https://github.com/simonlindholm/decomp-permuter), randomized and user-controlled source permutations, recompilation and assembly scoring. Original tool mainly targets MIPS, PowerPC and ARM32.
- [C2Scope](https://github.com/NoahBPeterson/c2scope), compiler tracing, rewrite search, register and scheduling analysis. Its measured rules are specific to supported historical MSVC backends and are not universal.
- [decomp.me FAQ](https://www.decomp.me/faq), matching-decompilation workflows and scoring.
- [LLVM CodeGen documentation](https://llvm.org/docs/CodeGenerator.html), compiler backend phases and target-specific instruction selection and allocation.
- [decomp-permuter scoring sources](https://github.com/simonlindholm/decomp-permuter/tree/main/src), measuring compiler output differences.

**Usage:** This document provides general mechanisms. Pass actual source, compiler flags, original/compiled assembly, verification assumptions, and prior experiments separately as per-task evidence. An AI model should select relevant entries dynamically and justify them from the supplied evidence. It should not presume any one technique applies.
