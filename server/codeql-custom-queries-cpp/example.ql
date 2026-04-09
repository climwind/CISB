/**
 * This is an automatically generated file
 * @name Hello world
 * @kind problem
 * @problem.severity warning
 * @id cpp/example/hello-world
 */

/**
 * @name Potential Dead Code Elimination Vulnerability
 * @description Detects security-critical operations that may be optimized away by dead code elimination
 * @kind problem
 * @problem.severity warning
 * @id cpp/potential-dce-vulnerability
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards

class DeadCodeEliminationVulnerability extends DataFlow::Configuration {
  DeadCodeEliminationVulnerability() { this = "DeadCodeEliminationVulnerability" }

  override predicate isSource(DataFlow::Node source) {
    // Match function calls that could be security-critical but might be optimized away
    source.asExpr() instanceof FunctionCall and (
      source.(FunctionCall).getTarget().getName() = "memset" or
      source.(FunctionCall).getTarget().hasQualifiedName("std.memset") or
      source.(FunctionCall).getTarget().hasQualifiedName("__builtin_memset")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // No explicit sinks - we're looking for operations without subsequent use
    none()
  }
}

/**
 * A class representing potentially vulnerable memory operations
 */
class VulnerableMemoryOperation extends FunctionCall {
  VulnerableMemoryOperation() {
    // Match memset and similar security-critical operations
    this.getTarget().getName() = "memset" or
    this.getTarget().hasQualifiedName("std.memset") or
    this.getTarget().hasQualifiedName("__builtin_memset") or
    // Could extend to other security-critical functions like memcpy, bzero, etc.
    this.getTarget().getName() = "memcpy" or
    this.getTarget().getName() = "bzero"
  }

  /**
   * Gets the destination argument (first parameter of memset)
   */
  Expr getDestinationArg() {
    this.getArgument(0)
  }

  /**
   * Gets the value argument (second parameter of memset)
   */
  Expr getValueArg() {
    this.getArgument(1)
  }

  /**
   * Gets the size argument (third parameter of memset)
   */
  Expr getSizeArg() {
    this.getArgument(2)
  }

  /**
   * Checks if the destination is a static variable or local variable that has no subsequent reads
   */
  predicate hasNoSubsequentReads() {
    not exists(Expr read |
      read.getLocation().getFile() = this.getLocation().getFile() and
      read.getLocation().getStartLine() > this.getLocation().getStartLine() and
      // Check for data flow from the destination to a read expression
      DataFlow::localFlow(this.getArgument(0), read) and
      // Ensure the read happens after the function call
      read.getLocation().getStartLine() > this.getLocation().getStartLine()
    )
  }

  /**
   * Checks if the function call lacks compiler barriers
   */
  predicate lacksCompilerBarriers() {
    not exists(Variable v |
      v.getAnAssignment() = this and
      v.getType().hasQualifiedName("volatile")
    ) and
    not this.getEnclosingFunction().hasAttribute("used") and
    not this.getEnclosingFunction().hasAttribute("retain") and
    not this.getEnclosingFunction().hasAttribute("no_sanitize")
  }
}

/**
 * Alternative approach using direct predicate matching
 */
predicate isPotentiallyOptimizedAwayFunction(FunctionCall fc) {
  fc.getTarget().getName() = "memset" or
  fc.getTarget().hasQualifiedName("std.memset") or
  fc.getTarget().hasQualifiedName("__builtin_memset")
}

predicate isStaticOrLocalVariableWrite(Expr expr) {
  exists(VariableAccess va | 
    va = expr and
    (va.getVariable() instanceof LocalVariable or 
     va.getVariable() instanceof StaticVariable)
  )
}

predicate hasNoDataFlowDependency(Expr targetExpr) {
  not exists(Expr sourceExpr, Expr sinkExpr |
    DataFlow::localFlow(sourceExpr, sinkExpr) and
    sourceExpr = targetExpr and
    sinkExpr instanceof VariableAccess and
    sinkExpr.getLocation().getStartLine() > targetExpr.getLocation().getStartLine()
  )
}

predicate lacksOptimizationBarrier(Stmt stmt) {
  not exists(Function f |
    f = stmt.getEnclosingFunction() and
    (f.hasAttribute("used") or f.hasAttribute("retain"))
  ) and
  not exists(Type t |
    t = stmt.getType() and
    t.hasQualifiedName("volatile")
  )
}

from VulnerableMemoryOperation vmo
where 
  vmo.hasNoSubsequentReads() and
  vmo.lacksCompilerBarriers()
select vmo, 
  "Potential CISB: Security-critical operation at line " + 
  vmo.getLocation().getStartLine().toString() + 
  " may be optimized away by dead code elimination. The result of " +
  vmo.getTarget().getName() + " is not subsequently used, making it vulnerable to optimization removal."

/**
 * Generic pattern for detecting any assignment that might be optimized away
 */
from Assignment a
where 
  exists(Variable v | 
    (v instanceof StaticVariable or v instanceof LocalVariable) and
    a.getLValue() = v.getAnAccess()
  ) and
  hasNoDataFlowDependency(a.getRValue()) and
  lacksOptimizationBarrier(a)
select a,
  "Potential dead store elimination: Assignment to variable may be removed during optimization."