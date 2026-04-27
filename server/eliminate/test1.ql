import cpp

from
  LocalVariable v,
  FieldAccess fa,
  VariableAccess read1, VariableAccess read2
where
  // 局部变量 v 通过初始化或赋值从位域成员读取值
  (
    v.getInitializer().getExpr() = fa
    or
    exists(AssignExpr a |
      a.getLValue().(VariableAccess).getTarget() = v and
      a.getRValue() = fa
    )
  ) and
  // fa 访问的是位域成员
  fa.getTarget() instanceof BitField and
  // v 被读取至少两次（非左值）
  read1.getTarget() = v and
  read2.getTarget() = v and
  read1 != read2 and
  not read1.isUsedAsLValue() and
  not read2.isUsedAsLValue() and
  // 所有操作位于 v 的作用域内
  read1.getEnclosingFunction() = v.getFunction() and
  read2.getEnclosingFunction() = v.getFunction()
select
  v,
  "Variable '" + v.getName() +
  "' loaded from bit-field access '" + fa.toString() +
  "' (in " + v.getFunction().getName() + ") is read multiple times. " +
  "Consider using READ_ONCE() or volatile to prevent TOCTOU."