/**
 * @name Non-atomic tagged-pointer field store may tear under concurrent reads
 * @description Detects plain assignments that store tagged pointer values into struct fields
 *              (pointer combined with mask/flag bits) without WRITE_ONCE/atomic wrappers,
 *              while another function reads the same field name.
 * @kind problem
 * @problem.severity warning
 * @id c/ubrace-tagged-pointer-store-tearing
 */

import cpp

predicate isAtomicOrWriteOnceCall(FunctionCall c) {
	exists(Function f |
		c.getTarget() = f and
		(
			f.hasName("WRITE_ONCE") or
			f.hasName("atomic_store") or
			f.hasName("atomic_store_explicit") or
			f.hasName("__atomic_store_n") or
			f.hasName("InterlockedExchangePointer")
		)
	)
}

predicate hasTagLikePointerExpression(Expr e) {
	exists(BinaryOperation bo |
		bo = e.getAChild*() and
		(bo.getOperator() = "|" or bo.getOperator() = "+") and
		(
			bo.getType() instanceof PointerType or
			bo.toString().regexpMatch("(?i).*(uintptr_t|unsigned\\s+long|size_t|u64|ulong|flag|mask|anon).*")
		)
	)
}

predicate exprComesFromEarlierTaggedAssign(Expr e) {
	exists(VariableAccess useVa, AssignExpr prevAssign, VariableAccess defVa |
		useVa = e and
		defVa = prevAssign.getLValue() and
		useVa.getTarget() = defVa.getTarget() and
		prevAssign.getLocation().getStartLine() < useVa.getLocation().getStartLine() and
		hasTagLikePointerExpression(prevAssign.getRValue())
	)
}

predicate isLikelyTaggedVariableExpr(Expr e) {
	exists(VariableAccess va |
		va = e and
		va.getTarget().getName().regexpMatch("(?i).*(flag|mask|tag|anon|encoded|bits).*")
	)
}

predicate isTaggedStoreRhs(Expr rhs) {
	hasTagLikePointerExpression(rhs)
	or
	exprComesFromEarlierTaggedAssign(rhs)
	or
	isLikelyTaggedVariableExpr(rhs)
}

predicate hasSameNamedFieldReadInOtherFunction(FieldAccess writeFa, Function writeFn) {
	exists(FieldAccess readFa, Function readFn |
		readFa.getTarget().hasName(writeFa.getTarget().getName()) and
		readFa.getEnclosingFunction() = readFn and
		readFn != writeFn and
		// 读场景排除明显写左值，保留无锁读启发式
		not exists(AssignExpr a | a.getLValue() = readFa)
	)
}

from AssignExpr store, FieldAccess fa, Function fn
where
	fa = store.getLValue() and
	fn = store.getEnclosingFunction() and
	fa.getTarget().getType() instanceof PointerType and
	isTaggedStoreRhs(store.getRValue()) and
	not store.toString().regexpMatch("(?i).*WRITE_ONCE\\s*\\(.*") and
	not exists(FunctionCall call |
		call.getEnclosingFunction() = fn and
		isAtomicOrWriteOnceCall(call)
	) and
	hasSameNamedFieldReadInOtherFunction(fa, fn)
select store,
	"Tagged-pointer field store to '" + fa.getTarget().getName() +
	"' is performed via plain assignment while similarly named field is read in another function; " +
	"without WRITE_ONCE/atomic store this can expose torn or reordered intermediate state."
