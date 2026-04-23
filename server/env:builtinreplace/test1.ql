/**
 * @name Optimization-sensitive guarded asm or builtin-replace loop
 * @description Detects source patterns where compiler optimization may reorder guarded asm
 *              or rewrite assignment loops into builtin calls (memset/memcpy), which can
 *              violate runtime-environment assumptions.
 * @kind problem
 * @problem.severity warning
 * @id c/optimization-environment-sensitive-rewrite
 */

import cpp

/** Inline asm contains 'cc' clobber but not 'memory'. */
predicate hasCcWithoutMemoryClobber(AsmStmt asmStmt) {
    // Match clobber keywords from textual asm form for broader library compatibility.
    asmStmt.toString().regexpMatch("(?i).*\\bcc\\b.*") and
    not asmStmt.toString().regexpMatch("(?i).*\\bmemory\\b.*")
}

/** Inline asm appears in the then-branch of an if statement whose condition mentions 'is_smp'. */
predicate asmInsideIsSmpThenBranch(AsmStmt asmStmt, IfStmt ifs) {
    // Condition contains a call to is_smp().
    exists(FunctionCall call |
        call.getTarget().hasName("is_smp") and
        ifs.getCondition().getAChild*() = call
    ) and
    ifs.getThen().getAChild*() = asmStmt
}

/**
 * Assignment loop pattern that compilers often lower to memset/memcpy-like builtins.
 * Detects a loop whose body contains an assignment to a global array element with a constant.
 */
predicate isBuiltinReplaceCandidate(Stmt loop, AssignExpr assign) {
    // The assignment must occur inside the loop body
    (loop instanceof ForStmt or loop instanceof WhileStmt or loop instanceof DoStmt) and
    assign.getEnclosingStmt().getParent*() = loop and
    exists(ArrayExpr lhs, VariableAccess base, Literal lit |
        assign.getLValue() = lhs and
        lhs.getArrayBase() = base and
        base.getTarget() instanceof GlobalVariable and
        assign.getRValue() = lit
    )
}

from Element n, string msg
where
    // ARM case: missing memory clobber guarded by is_smp()
    exists(AsmStmt asmStmt, IfStmt ifs |
        hasCcWithoutMemoryClobber(asmStmt) and
        asmInsideIsSmpThenBranch(asmStmt, ifs) and
        n = asmStmt and
        msg =
            "Inline asm with 'cc' but no 'memory' clobber is guarded by is_smp(). " +
            "Compiler reordering may move operations across the intended guard on some targets."
    )
    or
    // Builtin replace case: loop filling global array with constant
    exists(Stmt loop, AssignExpr assign |
        isBuiltinReplaceCandidate(loop, assign) and
        n = assign and
        msg =
            "Global array fill loop is a builtin-replace candidate. " +
            "At -O1+ in non-freestanding builds, the compiler may emit memset/memcpy calls, " +
            "which can break environment-dependent assumptions."
    )
select n, msg