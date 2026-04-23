/**
 * @name Non-volatile or non-barrier repeated state observations
 * @description Detects repeated reads of state (inline cpuid or function calls) that may be optimized away
 *              due to missing volatile, memory barrier, or pure-function assumptions.
 * @kind problem
 * @problem.severity warning
 * @id c/non-volatile-repeated-observation
 */

import cpp

// ---------- 1. Inline asm with cpuid ----------
predicate isCpuidInlineAsm(AsmStmt asmStmt) {
    asmStmt.toString().regexpMatch("(?s).*\\bcpuid\\b.*")
}

predicate lacksVolatileQualifier(AsmStmt asmStmt) {
    isCpuidInlineAsm(asmStmt) and
    not asmStmt.toString().regexpMatch("(?s).*\\bvolatile\\b.*")
}

predicate isNearbyRepeatedCpuid(AsmStmt first, AsmStmt second) {
    first != second and
    first.getEnclosingFunction() = second.getEnclosingFunction() and
    first.getLocation().getStartLine() < second.getLocation().getStartLine() and
    second.getLocation().getStartLine() - first.getLocation().getStartLine() <= 12 and
    first.toString() = second.toString()
}

predicate hasNearbyOutputComparison(AsmStmt second) {
    exists(BinaryOperation cmp |
        cmp.getEnclosingFunction() = second.getEnclosingFunction() and
        (cmp.getOperator() = "!=" or cmp.getOperator() = "==") and
        cmp.getLocation().getStartLine() >= second.getLocation().getStartLine() - 8 and
        cmp.getLocation().getStartLine() <= second.getLocation().getStartLine() + 20 and
        cmp.toString().regexpMatch("(?s).*(eax|ebx|ecx|edx|a|b|c|d).*")
    )
}

// ---------- 2. Ordinary function calls that may be wrongly optimized ----------
/**
 * Function accesses a global variable that is not volatile and may be modified asynchronously.
 * This is a heuristic: the function reads or writes any global/static variable.
 */
predicate accessesAsyncMemory(Function f) {
    exists(VariableAccess va |
        va.getEnclosingFunction() = f and
        va.getTarget() instanceof GlobalVariable and
        not va.getTarget().isVolatile()
    )
}

/**
 * Two function calls with identical arguments, in the same function,
 * and the called function accesses non-volatile global state.
 */
predicate isRepeatedPureLikeCall(FunctionCall call1, FunctionCall call2) {
    call1 != call2 and
    call1.getEnclosingFunction() = call2.getEnclosingFunction() and
    call1.getTarget() = call2.getTarget() and
    call1.getNumberOfArguments() = call2.getNumberOfArguments() and
    // all arguments equal (by AST)
    forall(int i | i in [0 .. call1.getNumberOfArguments()-1] |
        call1.getArgument(i).getValueText() = call2.getArgument(i).getValueText()
    ) and
    // the called function reads/writes non-volatile global variables
    accessesAsyncMemory(call1.getTarget()) and
    // there is no explicit memory barrier or volatile access between them (simplified: no asm volatile with "memory")
    not exists(AsmStmt asm |
        asm = call1.getASuccessor*() and
        asm = call2.getAPredecessor*() and
        asm.toString().regexpMatch("(?s).*\\bvolatile\\b.*") and
        asm.toString().regexpMatch("(?s).*memory.*")
    )
}

// ---------- Main query ----------
from Element n, string msg
where
    (
        exists(AsmStmt first, AsmStmt second |
            lacksVolatileQualifier(first) and
            lacksVolatileQualifier(second) and
            isNearbyRepeatedCpuid(first, second) and
            hasNearbyOutputComparison(second) and
            n = second and
            msg =
                "Potential vulnerability pattern: repeated inline cpuid without 'volatile'. Compiler optimizations may remove/fold one read,"
                + " but surrounding logic appears to rely on output differences between calls."
        )
        or
        exists(FunctionCall call1, FunctionCall call2 |
            isRepeatedPureLikeCall(call1, call2) and
            n = call2 and
            msg =
                "Repeated call to function '" + call2.getTarget().getName() + "' with identical arguments. "
                + "The function accesses non-volatile global state; compiler may treat it as pure and eliminate the second call. "
                + "Consider using volatile, atomic, or memory barriers."
        )
    )
select n, msg
