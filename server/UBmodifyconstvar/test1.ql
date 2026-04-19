/**
 * @name Modification of const variable through casted non-const pointer
 * @description Modifying a const-qualified variable via a pointer that has been
 *              cast to a non-const type is undefined behavior and may be
 *              optimized away by the compiler (especially under -O1/-O2/-O3).
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/const-variable-modified-through-non-const-pointer
 * @tags reliability
 *       security
 *       external/cwe/cwe-758
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Holds if `e` is an expression that evaluates to the address of a
 * const-qualified variable `v`.
 */
predicate addressOfConstVariable(Expr e, Variable v) {
  // Direct address-of: &v
  e.(AddressOfExpr).getOperand() = v.getAnAccess() and
  v.getType().isConst()
  or
  // Array-to-pointer decay for const array: arr (where arr is const T[])
  e.(VariableAccess).getTarget() = v and
  v.getType().stripType().(ArrayType).getBaseType().isConst()
}

/**
 * Holds if `ptrUse` is a use of pointer variable `ptr` that may point to the
 * const variable `v` after a cast that removes the `const` qualifier.
 */
predicate nonConstPointerToConst(Expr ptrUse, Variable ptr, Variable v) {
  exists(Expr addr, Cast cast |
    // Address of const variable is taken
    addressOfConstVariable(addr, v) and
    // The address expression is cast to a non-const pointer type
    cast.getExpr() = addr and
    exists(PointerType pt |
      pt = cast.getType().stripType() and
      not pt.getBaseType().isConst()
    ) and
    // The cast result flows to a pointer variable `ptr`
    DataFlow::localFlowStep(DataFlow::exprNode(cast), DataFlow::exprNode(ptrUse)) and
    ptrUse.(VariableAccess).getTarget() = ptr
  )
}

from Variable constVar, Variable ptrVar, Assignment assign, Expr ptrUse, PointerDereferenceExpr deref
where
  // There exists a pointer variable `ptrVar` that holds a casted address of `constVar`
  nonConstPointerToConst(ptrUse, ptrVar, constVar) and
  // The assignment's left side is a pointer dereference
  assign.getLValue() = deref and
  // The dereferenced pointer is exactly the `ptrUse` expression
  deref.getOperand() = ptrUse
select assign,
  "The const-qualified variable '" + constVar.getName() +
  "' is being modified through a non-const pointer '" + ptrVar.getName() +
  "', which leads to undefined behavior and may be optimized away."