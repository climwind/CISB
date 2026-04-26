/**
 * @name Unsynchronized shared writes can be reordered
 * @description Detects two unsynchronized writes to shared globals (one zero/null write and one non-zero write),
 *              which may be observed in inconsistent order by other threads.
 * @kind problem
 * @problem.severity warning
 * @id c/ub-reorder-breaks-unsynchronized-shared-writes
 */

import cpp

predicate isMutexLikeCall(FunctionCall c) {
	exists(Function f |
		c.getTarget() = f and
		(
			f.hasName("pthread_mutex_lock") or
			f.hasName("pthread_mutex_unlock") or
			f.hasName("spin_lock") or
			f.hasName("spin_unlock") or
			f.hasName("mutex_lock") or
			f.hasName("mutex_unlock")
		)
	)
}

predicate isBarrierLikeCall(FunctionCall c) {
	exists(Function f |
		c.getTarget() = f and
		(
			f.hasName("barrier") or
			f.hasName("smp_mb") or
			f.hasName("rmb") or
			f.hasName("wmb") or
			f.hasName("atomic_thread_fence")
		)
	)
}

predicate isSharedGlobalWrite(AssignExpr a, GlobalVariable v) {
	exists(VariableAccess lhs |
		lhs = a.getLValue() and
		lhs.getTarget() = v
	)
}

predicate isZeroOrNullExpr(Expr e) {
	e.toString().regexpMatch("(?i)^\\s*(0([uUlL]*)|NULL)\\s*$")
}

predicate isNonZeroExpr(Expr e) {
	not isZeroOrNullExpr(e)
}

from
	AssignExpr w1, AssignExpr w2,
	GlobalVariable v1, GlobalVariable v2,
	Function fn
where
	fn = w1.getEnclosingFunction() and
	fn = w2.getEnclosingFunction() and
	w1 != w2 and
	isSharedGlobalWrite(w1, v1) and
	isSharedGlobalWrite(w2, v2) and
	v1 != v2 and
	w1.getLocation().getStartLine() < w2.getLocation().getStartLine() and
	(
		(isNonZeroExpr(w1.getRValue()) and isZeroOrNullExpr(w2.getRValue())) or
		(isZeroOrNullExpr(w1.getRValue()) and isNonZeroExpr(w2.getRValue()))
	) and
	// No explicit synchronization in the function: heuristic for missing lock protection.
	not exists(FunctionCall lockOrBarrier |
		lockOrBarrier.getEnclosingFunction() = fn and
		(isMutexLikeCall(lockOrBarrier) or isBarrierLikeCall(lockOrBarrier))
	)
select w2,
	"Potential write-reordering risk: function '" + fn.getName() +
	"' writes shared globals '" + v1.getName() + "' and '" + v2.getName() +
	"' without lock/barrier synchronization."
