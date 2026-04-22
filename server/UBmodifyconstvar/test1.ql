import cpp

from AssignExpr assign, PointerDereferenceExpr deref, AddressOfExpr addr, Variable var
where
  // 左值为 *cast_expr
  assign.getLValue() = deref and
  // 解引用的操作数剥离所有转换后得到 &var
  deref.getOperand().getUnconverted() = addr and
  // 取地址的目标是 const 变量
  addr.getAddressable() = var and
  var.isConst()
select assign, "Assignment to const variable '" + var.getName() +
               "' through pointer cast leads to undefined behavior."