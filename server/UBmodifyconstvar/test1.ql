import cpp

from Variable v, VariableAccess va, AddressOfExpr addr, Cast cast, PointerType pt,
     PointerDereferenceExpr deref, AssignExpr assign
where
  // const 变量
  v.isConst() and

  // 取该变量地址：&v
  va.getTarget() = v and
  addr.getOperand() = va and

  // 对地址进行显式/隐式 cast
  cast.getExpr() = addr and

  // cast 结果是“指向非常量”的指针（去掉了 const）
  cast.getType() = pt and
  not pt.getBaseType().isConst() and

  // 通过 *cast 作为赋值左值进行写入
  deref.getOperand() = cast and
  assign.getLValue() = deref
select v, "Const variable modified via pointer cast, vulnerable to compiler optimization."