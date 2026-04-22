/**
 * @name Non-volatile inline cpuid used as changing hardware-state read
 * @description Detects repeated inline cpuid reads without volatile qualifier. The compiler may remove or fold one call,
 *              while code logic still assumes the two reads can produce different results.
 * @kind problem
 * @problem.severity warning
 * @id c/nonvolatile-inline-cpuid-double-read
 */

import cpp

/** Heuristic: inline assembly contains cpuid instruction text. */
predicate isCpuidInlineAsm(AsmStmt asmStmt) {
	asmStmt.toString().regexpMatch("(?s).*\\bcpuid\\b.*")
}

/** Missing volatile on inline asm can allow optimizer to remove/reorder/fold reads. */
predicate lacksVolatileQualifier(AsmStmt asmStmt) {
	isCpuidInlineAsm(asmStmt) and
	not asmStmt.toString().regexpMatch("(?s).*\\bvolatile\\b.*")
}

/** Two cpuid asm statements are close and ordered in the same function. */
predicate isNearbyRepeatedCpuid(AsmStmt first, AsmStmt second) {
	first != second and
	first.getEnclosingFunction() = second.getEnclosingFunction() and
	first.getLocation().getStartLine() < second.getLocation().getStartLine() and
	second.getLocation().getStartLine() - first.getLocation().getStartLine() <= 12 and
	first.toString() = second.toString()
}

/**
 * Heuristic for "expecting different outputs":
 * near the second cpuid, there is a comparison often used to branch on changed register values.
 */
predicate hasNearbyOutputComparison(AsmStmt second) {
	exists(BinaryOperation cmp |
		cmp.getEnclosingFunction() = second.getEnclosingFunction() and
		(cmp.getOperator() = "!=" or cmp.getOperator() = "==") and
		cmp.getLocation().getStartLine() >= second.getLocation().getStartLine() - 8 and
		cmp.getLocation().getStartLine() <= second.getLocation().getStartLine() + 20 and
		cmp.toString().regexpMatch("(?s).*(eax|ebx|ecx|edx|a|b|c|d).*")
	)
}

from AsmStmt first, AsmStmt second
where
	lacksVolatileQualifier(first) and
	lacksVolatileQualifier(second) and
	isNearbyRepeatedCpuid(first, second) and
	hasNearbyOutputComparison(second)
select second,
	"Potential vulnerability pattern: repeated inline cpuid without 'volatile'. Compiler optimizations may remove/fold one read,"
	+ " but surrounding logic appears to rely on output differences between calls."
