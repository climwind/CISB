/**
 * @name Non-atomic store to a multi-byte type via truncated pointer
 * @description A multi-byte atomic type (e.g., pte_t) is written without WRITE_ONCE
 *              after casting its pointer to a smaller type. This can result in
 *              torn stores observable by concurrent readers.
 * @kind problem
 * @id cpp/non-atomic-multi-byte-store
 * @severity warning
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

/**
 * Types that should be accessed atomically: unsigned integral types ≥ 8 bytes,
 * possibly wrapped in a single-field struct.
 */
predicate isMultiByteAtomicType(Type t) {
  // Direct integral type (or through typedefs)
  exists(IntegralType i |
    i = t.getUnderlyingType() and
    i.isUnsigned() and
    i.getSize() >= 8
  )
  or
  // Single-field struct wrapping an unsigned long (common in kernel)
  exists(Struct s |
    s.getSize() >= 8 and
    strictcount(Field f | f.getDeclaringType() = s) = 1 and
    forall(Field f | f.getDeclaringType() = s |
      f.getType().getUnderlyingType() instanceof IntegralType and
      f.getType().getSize() >= 8
    )
  )
}

/** A cast that narrows a multi-byte pointer to a smaller integral pointer. */
class MultiByteToSmallerCast extends Cast {
  MultiByteToSmallerCast() {
    exists(PointerType srcPtr, PointerType dstPtr, IntegralType dstBase |
      srcPtr = this.getExpr().getType() and
      dstPtr = this.getType() and
      isMultiByteAtomicType(srcPtr.getBaseType()) and
      dstPtr.getBaseType().getUnderlyingType() = dstBase and
      dstBase.getSize() < srcPtr.getBaseType().getSize()
    )
  }
}

from
  MultiByteToSmallerCast cast,
  AssignExpr assign,
  DataFlow::Node castNode,
  DataFlow::Node baseNode,
  Expr lhs,
  string msg
where
  castNode = DataFlow::exprNode(cast) and
  // The cast result reaches the base pointer used in the write.
  DataFlow::localFlow(castNode, baseNode) and
  lhs = assign.getLValue() and
  (
    // Match array indexing where the base is the cast result or contains it
    exists(ArrayExpr a |
      a = lhs and
      (
        a.getArrayBase() = baseNode.asExpr()
        or a.getArrayBase().getAChild*() = baseNode.asExpr()
      )
    )
    or
    // Match direct dereference of the pointer, or dereference of pointer arithmetic
    exists(PointerDereferenceExpr pd |
      pd = lhs and
      (
        pd.getOperand() = baseNode.asExpr()
        or pd.getOperand().getAChild*() = baseNode.asExpr()
        or exists(AddExpr add |
          pd.getOperand() = add and
          (
            add.getLeftOperand() = baseNode.asExpr() or
            add.getRightOperand() = baseNode.asExpr() or
            add.getAChild*() = baseNode.asExpr()
          )
        )
      )
    )
  ) and
  // Exclude assignments explicitly protected by WRITE_ONCE
  not assign.toString().regexpMatch("(?i).*WRITE_ONCE\\s*\\(.*") and
  // Exclude volatile destinations (they are implicitly single-copy)
  not lhs.getType().isVolatile() and
  // Message
  msg = "Non-atomic store to " + cast.getExpr().getType().(PointerType).getBaseType().toString() +
        " via truncated pointer in $@." and
  // Avoid flagging direct full-width assignments via the original pointer
  not exists(AssignExpr direct |
    direct.getLValue().(PointerDereferenceExpr).getOperand() = cast.getExpr() and
    direct = assign
  )
select assign, msg, cast, "cast here"