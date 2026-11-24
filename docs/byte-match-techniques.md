# Byte-matching decompilation: compiler diagnosis catalog

**Scope:** These are hypotheses, not guaranteed source transformations or claims about any particular function. The Spore pilot uses pinned VC9 15.00.30729.1, x86, /O2 /MD /Gy /EHsc /TP. Findings from another compiler version should be treated as general guidance until measured here.

## Highest-priority shortlist for the current 0x00672CF0 near-match

1. [SCHED] **Prologue boundary**: Is push edi / initial argument load in the compiler's prologue rather than a schedulable body region? C2Scope documents Schedule starting after OPPROLOGEND.
2. [ALIAS] **Stack/load vs field/store aliasing**: Can the this-derived write alias the incoming pointer's stack slot? A memory edge may block hoisting.
3. [REG] **Callee-saved lifetime**: Why was edi chosen for the second argument and saved at this point rather than earlier?
4. [REG] **Parameter early use**: Does a real earlier use create allocation pressure or move entry initialization? Dead reads often vanish.
5. [ALIAS] **Reference aliasing**: Does a reference or pointer alias change points-at sets, CSE, or the load/store dependency graph?
6. [DATA] **Field dependency**: Reuse a previously stored pointer field rather than recomputing its address, as already improved this function.
7. [REG] **Allocator priority**: Changes to reference counts, overlap, first use, block pressure, and tie breaks can move register setup.
8. [REG] **Live-range shape**: Copies, named locals, scopes, and call-crossing values may influence preserved register choice.
9. [SCHED] **Scheduling DAG**: Inspect region, dependencies, height, successors, memory-read priority, and issue order before blaming scheduler.
10. [SCHED] **Source statement order**: Independent statements may change defOrd or tie breaks, but can compile identically or alter alias semantics.
11. [DATA] **Value numbering/CSE**: Similar expressions can share or fail to share a value because memory points-at classes differ.
12. [VERIFY] **Relocation masking**: A synthetic call target displayed as a different displacement is not necessarily a byte difference.

## Full catalog

### Build configuration and ABI

13. [BUILD] Exact compiler binary and service-pack identity, including c2.dll revision.
14. [BUILD] Full flag fidelity, optimization, runtime, security, EH, function sections, and machine target.
15. [BUILD] C versus C++ frontend and /TP effects on name decoration and lowered IR.
16. [ABI] Calling convention, thiscall ECX, argument order, stack cleanup, and return register.
17. [ABI] External callee declaration, type qualifiers, inlining eligibility, symbol pairing, and clobbers.
18. [BUILD] Translation-unit and header/inlining context can matter even with identical function bodies.
19. [VERIFY] Relocation-aware fingerprint and normalized call/jump encodings.
20. [VERIFY] Formal behavioral equivalence versus empirical differential testing versus exact byte match.

### Frontend expression and source forms

21. [FRONTEND] Typed pointer arithmetic versus byte displacement arithmetic.
22. [FRONTEND] p[i] versus *(p+i), struct-field spelling, casts, and base+offset address forms.
23. [FRONTEND] Signedness and width affecting sign/zero-extension and operand size.
24. [FRONTEND] Immediate constant sharing, narrow stores and signed encodings.
25. [FRONTEND] Grouping/reassociation and explicit temporaries, guarding against overflow differences.
26. [FRONTEND] Commuting associative integer operations may alter register preferences.
27. [FRONTEND] Declaration with initializer versus declaration then assignment.
28. [FRONTEND] Direct return versus named local return and copy propagation.
29. [FRONTEND] Inlined helpers, member access, and templated forwarding can change intermediate IR.
30. [FRONTEND] Compound assignment, increments, comma/conditional operators, and side-effect sequencing.

### Memory aliasing, loads, stores and dataflow

31. [ALIAS] Pointer copy, pointer-to-reference, and aliases used repeatedly affect points-at sets.
32. [ALIAS] Named reference to member field can change load reuse and CSE classes.
33. [ALIAS] Loaded pointer used repeatedly versus local copy of that pointer.
34. [ALIAS] Call and may-alias stores kill prior memory values.
35. [ALIAS] Store-before-load versus load-before-store when addresses may overlap.
36. [ALIAS] A pointer field and a stack argument may alias in the formal machine-state model.
37. [DATA] Field-dependent expression reading an earlier stored pointer.
38. [DATA] Value numbering and common subexpression elimination across blocks.
39. [DATA] Re-read memory versus retain a register copy; check optimizer kills and alias class.
40. [DATA] Single-definition temporary eliminated by copy propagation before register allocation.
41. [DATA] Read-modify-write formation versus load/op/store when old memory value is reused.
42. [ALIAS] Volatile/restrict/noalias attributes change semantics or assumptions, not safe matching shortcuts.

### Registers, calls and frame layout

43. [REG] Values live across calls tend toward callee-saved ESI/EDI/EBX/EBP or stack spills.
44. [REG] Callee-saved push/pop sequence depends on actual register assignment and prologue insertion.
45. [REG] Real use/reference count and block pressure can change allocation priority.
46. [REG] First/last use and live-range splitting change entry-load and reload points.
47. [REG] Register interference when distinct webs overlap changes available registers.
48. [REG] Move/copy and call argument preferences affect coloring.
49. [REG] Equal-priority definition ordering can alter register tie breaks.
50. [REG] C2Scope measured scratch register rotation eax -> ecx -> edx under /O2.
51. [REG] Rematerializing a cheap constant/address versus retaining it in a register.
52. [REG] Frame key order, address-taken locals and spill-slot packing can change offsets.
53. [REG] Late-merged equal-arm branches can affect Color yet disappear from final code.

### Instruction scheduling and compiler phase attribution

54. [SCHED] Detect Schedule region starts, OPPROLOGEND boundaries and epilogue barriers.
55. [SCHED] True read-after-write dependency (RAW) prevents early consumption.
56. [SCHED] Anti-dependency write-after-read (WAR) preserves prior read.
57. [SCHED] Output dependency write-after-write (WAW) preserves overlapping stores.
58. [SCHED] May-alias memory DAG edges can constrain load/store order.
59. [SCHED] Critical-path height, successor counts and C2-specific scheduling priorities.
60. [SCHED] Source/IL lexical order can decide ties for independent ready instructions.
61. [SCHED] Calls, labels and control-flow barriers constrain motion.
62. [SCHED] Prologue save/parameter setup can lie outside body scheduler's domain.
63. [SCHED] Head/tail merge and duplicated control flow affect register allocation before late simplification.
64. [SCHED] Alias spelling can create or remove memory DAG edges without changing values.
65. [SCHED] Trace IL immediately before/after register allocation, prologue insertion, and scheduling.

### Instruction selection, control flow and verification

66. [ISEL] lea versus add/sub or explicit pointer recomputation.
67. [ISEL] Immediate width, sign extension, displacement encodings and register constants.
68. [ISEL] xor reg,reg versus mov reg,0, including flag semantics.
69. [ISEL] push [memory] versus mov reg,[memory]; push reg, or folded memory operands.
70. [ISEL] movsx/movzx and partial-register/narrow field operations.
71. [ISEL] Operand order, commutation and destination register form.
72. [ISEL] test versus cmp, condition-code/branch patterns and flag lifetimes.
73. [ISEL] If/else inversion, return/goto/loop shape, tail merge, fallthrough and block order.
74. [ISEL] Inlining changes call barriers, registers, and scheduling.
75. [ISEL] EH/security/frame-pointer settings influence entry/exit code.
76. [VERIFY] First differing instruction and its compiler phase, not only global rdiff/bdiff.
77. [VERIFY] Machine-code deduplication: different source often yields identical bytes.
78. [VERIFY] VC9 micro-probe isolates an uncertain optimization behavior.
79. [VERIFY] Unicorn PASS is empirical; angr EQUIVALENT is scoped; only relocation-aware fingerprint PASS is byte match.

## What is known for Spore 0x00672CF0

The best established source compiles to 57 bytes / 24 instructions, scores rdiff 1 / bdiff 4, and is formally EQUIVALENT under the configured angr L1 model, NOT fingerprint MATCH. Retail initializes EDI (push edi; mov edi,[esp+0xc]) before writing [esi+8], while the candidate emits that one store before initializing EDI. Synthetic external call relocations display differently and are not the relevant remaining mismatch. A field-dependency spelling eliminated an extra EBX save, and reference aliasing improved the ordering. The controlling VC9 optimization pass has **not** been identified.

## Research and implementation sources

- C2Scope first-party measured compiler research: https://github.com/NoahBPeterson/c2scope (docs/c2/sched.md, regalloc.md, loadcse.md, realize.md, opt.md, isel.md; tools/schedwant.py, rwsweep.py). Some rules originated with VC8; check measured cross-version notes.
- Historical Visual C++ compiler optimization overview: https://www.cs.cmu.edu/~rbd/doc/optcode.htm
- Microsoft C++ compiler pipeline discussion: https://devblogs.microsoft.com/cppblog/optimizing-c-code-overview/
- Source permutation and matching by recompilation: https://github.com/simonlindholm/decomp-permuter
- Matching decompilation terminology: https://www.decomp.me/faq
- Machine scheduler dependency classes, general concepts, not VC9 facts: https://llvm.org/doxygen/ScheduleDAG_8h_source.html
- Echo, compiler-feedback-driven matching decompilation: https://arxiv.org/abs/2609.18706

For small models, pass the 12-item shortlist by default. Larger models may receive the entire catalog, but it remains a reference, not an instruction to try all techniques.
