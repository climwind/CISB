/**
 * @name Loop condition using address of struct member against NULL with non‑zero offset
 * @description Detects loops where the condition is `&ptr->member != NULL` and the member's byte offset
 *              within its struct is greater than zero. This can cause undefined behavior under aggressive
 *              optimizations (e.g., Clang) because a NULL pointer plus a non‑zero offset is not NULL.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/loop-address-of-member-null-check
 * @tags correctness
 *       undefined-behavior
 *       optimization
 */

import cpp

/**
 * Gets the byte offset of a field within its declaring struct type.
 */
int getStructFieldByteOffset(Field f) {
  exists(Struct s | s = f.getDeclaringType() and result = f.getByteOffset())
}

from
  Loop loop, ComparisonOperation cmp, AddressOfExpr addrOf, FieldAccess fa,
  Field field, Literal zeroLit
where
  // Loop condition is a comparison
  loop.getCondition() = cmp and
  // Comparison operator is "!="
  cmp.getOperator() = "!=" and
  // One operand is the address-of expression
  cmp.getAnOperand() = addrOf and
  // The other operand is the integer literal 0 (NULL)
  cmp.getAnOperand() = zeroLit and zeroLit.getValue() = "0" and
  // Address-of applies to a field access
  addrOf.getOperand() = fa and
  // The field access must be through a pointer (->), not dot (.)
  // This is true if the qualifier's type is a pointer
  fa.getQualifier().getType() instanceof PointerType and
  // The field access refers to a specific field
  fa.getTarget() = field and
  // The field has a non-zero byte offset in its declaring struct
  getStructFieldByteOffset(field) > 0
select loop, "Loop condition checks address of struct member '" + field.getName() + "' against NULL, but member offset is " +
  getStructFieldByteOffset(field) + " bytes (non‑zero). This can lead to undefined behavior when the pointer is NULL."