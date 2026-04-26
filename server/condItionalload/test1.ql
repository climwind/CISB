/**
 * @name Speculative store before condition check
 * @description A global/static write guarded by a condition with one branch
 *              that avoids the write (e.g., early return) may be hoisted
 *              before the condition by the compiler, causing unintended
 *              side effects (e.g., writing to read‑only memory).
 * @kind problem
 * @problem.severity warning
 * @id cpp/speculative-store-before-condition
 */

import cpp
import semmle.code.cpp.controlflow.Dominance

/** Access to a global or static‑storage variable, including arrays. */
predicate isGlobalVarAccess(Expr e) {
  exists(Variable v |
    (e.(VariableAccess).getTarget() = v or
     e.(ArrayExpr).getArrayBase().(VariableAccess).getTarget() = v) and
    (v instanceof GlobalVariable or v instanceof StaticStorageDurationVariable)
  )
}

/** A write to a global/static variable: assignments and increment/decrement. */
class GlobalWrite extends Expr {
  GlobalWrite() {
    this instanceof Assignment and isGlobalVarAccess(this.(Assignment).getLValue())
    or
    this instanceof CrementOperation and isGlobalVarAccess(this.(CrementOperation).getOperand())
  }
}

/** Terminators that bypass following writes in the same block/function path. */
predicate isEarlyExitStmt(Stmt s) {
  s instanceof ReturnStmt or
  s instanceof BreakStmt or
  s instanceof ContinueStmt or
  s instanceof GotoStmt
}

/** True if the condition contains a call that looks like a lock/synchronization. */
predicate isSynchronizationCondition(Expr cond) {
  exists(FunctionCall fc |
    fc = cond.getAChild*() |
    fc.getTarget().getName().regexpMatch(".*(lock|trylock|mutex_lock|spin_lock|acquire).*")
  )
}

from GlobalWrite write, IfStmt condStmt, Expr cond, ControlFlowNode writeNode
where
  // Use statement-level node for stability across expression CFG variations.
  writeNode = write.getEnclosingStmt() and
  cond = condStmt.getCondition() and
  dominates(cond, writeNode) and
  // Write is outside the if branches and appears later in source order.
  write.getLocation().getStartLine() > condStmt.getLocation().getEndLine() and
  not condStmt.getThen().getAChild*() = write and
  (
    not exists(condStmt.getElse()) or
    not condStmt.getElse().getAChild*() = write
  ) and
  // One branch bypasses following code due to an early-exit statement.
  (
    exists(Stmt s | s = condStmt.getThen().getAChild*() and isEarlyExitStmt(s))
    or
    exists(Stmt e, Stmt s |
      e = condStmt.getElse() and
      s = e.getAChild*() and
      isEarlyExitStmt(s)
    )
  ) and
  // Exclude intentional locking guards
  not isSynchronizationCondition(cond)
select write,
  "$@ follows a condition with an early-exit branch; optimization may hoist the write before the check.",
  write, "global write"