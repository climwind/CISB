/**
 * @name Potentially unaligned memory operation (memcpy/memmove/memset)
 * @description Reports memcpy/memmove/memset with constant size whose
 *              destination pointer has static alignment less than the operation size.
 * @kind problem
 * @id cpp/insufficient-alignment-memcpy
 */

import cpp

/**
 * Gets the base type of the memory region that `ptr` points to.
 * For `&expr`, it's the type of `expr` (or its containing object for fields).
 * For a plain pointer, it's the pointed-to type.
 */
Type baseTypeOfPointer(Expr ptr) {
  // For `&field`, use the parent struct/union type (the object that contains the field)
  exists(FieldAccess fa | ptr.(AddressOfExpr).getOperand() = fa |
    result = fa.getQualifier().getType()
  )
  or
  // For `&variable`, use the variable's declared type
  exists(Variable var, VariableAccess va |
    ptr.(AddressOfExpr).getOperand() = va and
    va.getTarget() = var
  |
    result = var.getType()
  )
  or
  // For any other pointer expression, use the type it points to
  result = ptr.getType().(PointerType).getBaseType()
}

from FunctionCall call, string name, int size, Expr dest, int req, int actual
where
  call.getTarget().hasName(name) and
  name in ["memcpy", "memmove", "memset"] and
  // Only consider constant operation size
  size = call.getArgument(2).getValue().toInt() and
  dest = call.getArgument(0) and
  // Alignment requirement: if size is a power of two, use it directly;
  // otherwise use the smallest power-of-two >= size (conservative).
  // To keep it simple, we use size itself for sizes ≤ 8, capped at 8.
  (
    size <= 8 and req = size
    or
    size > 8 and req = 8
  ) and
  actual = baseTypeOfPointer(dest).getAlignment() and
  req > actual and
  actual > 0  // exclude unknown alignment
select call,
  "This $@ writes " + size + " bytes at a pointer with only " + actual +
  "-byte alignment, but the operation requires at least " + req + "-byte alignment.",
  call, name