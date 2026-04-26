/**
 * @name Size-dispatch switch fallthrough causes wider memory read
 * @description Detects switch-based size dispatch that performs multiple pointer-dereference loads into the same destination without protective break statements.
 * @kind problem
 * @problem.severity warning
 * @id cpp/size-dispatch-switch-fallthrough-wide-read
 */
import cpp

predicate isInSwitchRange(Stmt s, SwitchStmt sw) {
	s.getFile() = sw.getFile() and
	s.getLocation().getStartLine() >= sw.getLocation().getStartLine() and
	s.getLocation().getEndLine() <= sw.getLocation().getEndLine()
}

from SwitchStmt sw,
		 AssignExpr a1, AssignExpr a2,
		 PointerDereferenceExpr d1, PointerDereferenceExpr d2
where
	a1 != a2 and
	d1 != d2 and
	a1.getRValue() = d1 and
	a2.getRValue() = d2 and
	a1.getLValue().toString() = a2.getLValue().toString() and
	isInSwitchRange(a1.getEnclosingStmt(), sw) and
	isInSwitchRange(a2.getEnclosingStmt(), sw) and
	sw.getEnclosingFunction() = a1.getEnclosingFunction() and
	sw.getEnclosingFunction() = a2.getEnclosingFunction() and
	not exists(BreakStmt b |
		isInSwitchRange(b, sw)
	)
select sw,
	"Switch size-dispatch performs multiple pointer loads into the same destination but has no break; fallthrough can force unintended wider read and semantic mismatch."
