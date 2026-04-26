/**
 * @name Unaligned access to a type-aligned pointer passed to byte-wise macros
 * @description Catch cases where a pointer with an assumed or declared alignment
 *              (e.g., extern __le32 variable without __aligned(1), or result of
 *              __builtin_assume_aligned) is passed to `get_unaligned_le32` or
 *              similar macros that rely on byte-wise reads. The compiler may
 *              optimize the access to a word-aligned load, causing faults or
 *              silent data corruption.
 * @kind problem
 * @severity error
 * @precision high
 * @id cpp/unaligned-access-through-aligned-pointer
 * @tags reliability alignment unaligned-access
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/**
 * A call to a function whose name suggests it performs byte‑wise unaligned access,
 * such as `get_unaligned_le32`, `put_unaligned_le16`, `__get_unaligned_le`, etc.
 */
class UnalignedAccessCall extends FunctionCall {
  UnalignedAccessCall() {
    this.getTarget().getName().regexpMatch("(?i).*get_unaligned.*|.*put_unaligned.*") or
    this.getTarget().getName() = "__get_unaligned_le" or
    this.getTarget().getName() = "__put_unaligned_le"
  }

  /** The pointer argument that is subject to alignment mistrust. */
  Expr getPointerArgument() { result = this.getArgument(0) }
}

/**
 * Holds if `v` is a `VariableAccess` that refers to an external variable of a 32‑bit
 * integer type (e.g. `__le32`, `uint32_t`, `int32_t`) without any `aligned` attribute.
 */
predicate isExternUnalignedVar(VariableAccess v) {
  exists(Variable var |
    var = v.getTarget() and
    exists(Specifier sp | sp = var.getASpecifier() and sp.hasName("extern")) and
    var.getType().(IntegralType).getSize() = 4 and
    not var.getAnAttribute().hasName("aligned")
  )
}

/**
 * Holds if `builtin` is a call to `__builtin_assume_aligned` with alignment > 1.
 */
predicate isAssumeAligned(FunctionCall builtin) {
  builtin.getTarget().getName() = "__builtin_assume_aligned" and
  builtin.getArgument(1).getValue().toInt() > 1
}

/**
 * A configuration that tracks data flow from:
 *   1) an external 32‑bit variable (missing `aligned`)  OR
 *   2) the address of a variable accessed through pointer arithmetic (possible
 *      misalignment) that then passes through `__builtin_assume_aligned`,
 * to the pointer argument of an `UnalignedAccessCall`.
 */
module UnalignedRiskConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Source 1: direct reference to an extern variable missing alignment
    isExternUnalignedVar(source.asExpr().(VariableAccess))
    or
    // Source 2: result of `__builtin_assume_aligned` that may have forced a lie
    isAssumeAligned(source.asExpr().(FunctionCall))
  }

  predicate isSink(DataFlow::Node sink) {
    exists(UnalignedAccessCall call |
      sink.asExpr() = call.getPointerArgument()
    )
  }

  // No barrier – we want to see even a single step propagation
  predicate isBarrier(DataFlow::Node node) { none() }
}

module UnalignedRiskFlow = DataFlow::Global<UnalignedRiskConfig>;

/**
 * A sanitizer guard: if the pointer is explicitly cast to `void *` or `char *` before
 * the call we consider it « acknowledged » and do not report.
 * Remove this if you want maximum sensitivity.
 */
predicate hasAcknowledgedCast(Expr arg) {
  arg.(Cast).getType().(PointerType).getBaseType() instanceof VoidType
  or
  arg.(Cast).getType().(PointerType).getBaseType() instanceof CharType
}

from UnalignedAccessCall call, Expr pointerArg, UnalignedRiskFlow::PathNode source, UnalignedRiskFlow::PathNode path
where
  pointerArg = call.getPointerArgument() and
  not hasAcknowledgedCast(pointerArg) and
  UnalignedRiskFlow::flowPath(source, path) and
  path.getNode() = DataFlow::exprNode(pointerArg)
select pointerArg,
  "The pointer argument to a byte‑wise unaligned access function ($@) originates from a source that assumes or enforces alignment ($@). "
  + "The compiler may replace the byte‑wise access with a word‑aligned load, causing undefined behaviour.",
  call, call.getTarget().getName(),
  source, "source of alignment assumption"