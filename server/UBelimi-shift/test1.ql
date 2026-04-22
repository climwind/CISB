import cpp

predicate isVarCheckCmp(BinaryOperation cmp, Variable var) {
  (
    cmp.getOperator() = "<" and
    exists(VariableAccess va | cmp.getLeftOperand() = va and va.getTarget() = var) and
    cmp.getRightOperand().toString() = "2"
  )
  or
  (
    cmp.getOperator() = "==" and
    exists(VariableAccess va | cmp.getLeftOperand() = va and va.getTarget() = var) and
    (
      cmp.getRightOperand().toString() = "0" or
      cmp.getRightOperand().toString() = "1"
    )
  )
}

predicate condContainsVarCheck(Expr cond, Variable var) {
  exists(BinaryOperation cmp |
    cond = cmp and
    isVarCheckCmp(cmp, var)
  )
  or
  exists(BinaryOperation lor |
    cond = lor and
    lor.getOperator() = "||" and
    (
      condContainsVarCheck(lor.getLeftOperand(), var)
      or
      condContainsVarCheck(lor.getRightOperand(), var)
    )
  )
}

from AssignExpr assign, BinaryOperation shift, Expr amount, Variable var,
  VariableAccess lhsVa, IfStmt ifs, Expr cond
where
  // 左移操作的模式：var = 1 << expr
  assign.getRValue() = shift and
  shift.getOperator() = "<<" and
  shift.getLeftOperand().toString() = "1" and
  amount = shift.getRightOperand() and
  exists(IntegralType it | amount.getType() = it) and
  assign.getLValue() = lhsVa and
  lhsVa.getTarget() = var and
  // 移位量可能超出操作数位宽
  (
    amount instanceof VariableAccess
    or
    exists(Literal lit |
      amount = lit and
      lit.toString().regexpMatch("^(3[2-9]|[4-9][0-9]|[1-9][0-9]{2,})$")
    )
  ) and
  // 条件检查的模式：if (var < 2) 或等效形式
  ifs.getCondition() = cond and
  condContainsVarCheck(cond, var)
select shift, "Left shift with untrusted amount may cause UB and lead to condition check removal by compiler."