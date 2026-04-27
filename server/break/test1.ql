/**
 * @name Non-atomic store to a multi-byte type that may be split
 * @description A multi-byte object (e.g., pte_t) is written without WRITE_ONCE
 *              either by a direct assignment or by manual slicing through a cast
 *              to a smaller type, which can create observable intermediate states.
 * @kind problem
 * @id cpp/non-atomic-multi-byte-store
 * @severity warning
 */

import cpp

/*
 * Heuristic: types that are typedefs for an integer of 8 bytes (common in kernel pte/pmd/pud).
 * Extend this predicate when the project uses a structure wrapper (e.g., struct { unsigned long val; }).
 */
predicate isMultiByteAtomicType(Type t) {
  // Matches typedef'd unsigned 64-bit integer (pte_t, pmd_t, etc.)
  exists(TypedefType typedef, IntegralType underlying |
    typedef.getUnderlyingType() = underlying and
    underlying.getSize() >= 8 and
    underlying.isUnsigned() and
    t = typedef
  )
  or
  // Matches structure wrapping a single unsigned long (common kernel pattern)
  exists(Class c |
    c.getSize() >= 8 and
    c instanceof Struct and
    // struct only contains a single unsigned long field
    strictcount(Field f | f.getDeclaringType() = c) = 1 and
    forall(Field f | f.getDeclaringType() = c |
      f.getType().getUnderlyingType() instanceof IntegralType and
      f.getType().getSize() >= 8
    )
  )
}

/*
 * A store that can be non-atomic: either direct assignment to a dereferenced pointer
 * or manual slicing through a cast-to-smaller-type plus array/pointer write.
 */
class NonAtomicStore extends Expr {
  NonAtomicStore() {
    // Case 1: Direct multi-byte assignment *ptr = expr
    exists(PointerDereferenceExpr deref, AssignExpr assign |
      assign.getLValue() = deref and
      isMultiByteAtomicType(deref.getType()) and
      not assign.toString().regexpMatch("(?i).*WRITE_ONCE\\s*\\(.*") and
      not deref.getType().isVolatile() and
      this = assign
    )
    or
    // Case 2: Manual slicing: cast from multi-byte pointer to smaller type & assign
    exists(AssignExpr assign, PointerDereferenceExpr deref, Cast cast, PointerType srcPtr, PointerType dstPtr, IntegralType srcBase, IntegralType dstBase |
      assign.getLValue() = deref and
      deref.getOperand().getUnconverted() = cast and
      // the cast source type is a multi-byte atomic type
      cast.getExpr().getType() = srcPtr and
      cast.getType() = dstPtr and
      srcPtr.getBaseType().getUnderlyingType() = srcBase and
      dstPtr.getBaseType().getUnderlyingType() = dstBase and
      isMultiByteAtomicType(srcPtr.getBaseType()) and
      // the cast destination (deferenced) type is strictly smaller
      dstBase.getSize() < srcBase.getSize() and
      not assign.toString().regexpMatch("(?i).*WRITE_ONCE\\s*\\(.*") and
      not deref.getType().isVolatile() and
      this = assign
    )
  }
}

from NonAtomicStore s, Element context
where context = s.getEnclosingElement()
select s, "Potential non-atomic store to a multi-byte type in $@.", context, context.toString()