/**
 * @name Inline assembly dereference may invalidate subsequent null check
 * @description Inline assembly that dereferences a pointer through a memory
 *              constraint ("m"/"o") can cause the compiler to assume the pointer
 *              is non-null, eliminating a later null check and potentially
 *              introducing a vulnerability.
 * @kind problem
 * @id cpp/asm-dereference-removes-null-check
 */

import cpp

// 识别空指针常量：0, NULL, nullptr
predicate isNullConstant(Expr e) {
  e.toString().regexpMatch("(?i)^\\s*(0([uUlL]*)|NULL|nullptr)\\s*$")
}

from
  AsmStmt asm, PointerDereferenceExpr deref,
  Variable ptrVar, IfStmt ifStmt
where
  // 1. 直接在 asm 的子表达式里找解引用操作数，而不是依赖 asm.toString()
  exists(Expr asmChild |
    asmChild = asm.getAChild*() and
    asmChild = deref
  ) and
  // 2. 解引用操作数穿透类型转换，回溯到同一个指针变量
  exists(Expr base |
    base = deref.getOperand() and
    base.getAChild*() = ptrVar.getAnAccess()
  ) and
  // 3. 同一函数内存在对该指针变量的空指针检查（隐式、取反、显式比较）
  asm.getEnclosingFunction() = ifStmt.getEnclosingFunction() and
  (
    // if (ptr)
    ifStmt.getCondition() = ptrVar.getAnAccess()
    or
    // if (!ptr)
    ifStmt.getCondition().(NotExpr).getOperand() = ptrVar.getAnAccess()
    or
    // if (ptr == NULL) 等
    exists(BinaryOperation cmp |
      ifStmt.getCondition() = cmp and
      cmp.getOperator() in ["==", "!="] and
      (
        cmp.getLeftOperand() = ptrVar.getAnAccess() and isNullConstant(cmp.getRightOperand())
        or
        cmp.getRightOperand() = ptrVar.getAnAccess() and isNullConstant(cmp.getLeftOperand())
      )
    )
  ) and
  // 4. 内联汇编在空检查之前（简单行号顺序）
  asm.getLocation().getEndLine() < ifStmt.getLocation().getStartLine()

select ifStmt,
  "Inline assembly dereferences pointer $@ through memory constraint, "
  + "so the compiler may assume it is non-null and eliminate the later null check.",
  ptrVar, ptrVar.getName()