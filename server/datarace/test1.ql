/**
 * @name Suspected double load / missing ACCESS_ONCE on shared struct field
 * @description A struct field is loaded into a local variable, then the
 *              same field is read or written again later in a control-flow
 *              branch that depends on the local variable. The second access
 *              may re-fetch a concurrently modified value without a barrier.
 * @kind problem
 * @precision high
 * @id cpp/concurrency-missing-access-once
 */

import cpp

from
  AssignExpr assign, FieldAccess fa_read, FieldAccess fa_write_or_read,
  LocalVariable lv, VariableAccess lv_init_access, VariableAccess lv_use,
  IfStmt if_stmt, Expr condition
where
  // (1) 赋值：lv = fa_read
  assign.getLValue() = lv_init_access and
  lv_init_access.getTarget() = lv and
  assign.getRValue() = fa_read and
  fa_read.isPure() and
  // 排除 volatile 屏障
  not fa_read.getTarget().getType().isVolatile() and

  // (2) 同一字段被再次访问（读取或写入）
  fa_write_or_read.getTarget() = fa_read.getTarget() and
  fa_write_or_read.getQualifier() = fa_read.getQualifier() and
  fa_write_or_read != fa_read and

  // (3) 读取在 if 之前
  fa_read.getBasicBlock().getASuccessor*() = if_stmt.getBasicBlock() and

  // (4) if 条件使用了该局部变量
  if_stmt.getCondition() = condition and
  lv.getAnAccess() = condition.getAChild*() and

  // (5) 第二次访问出现在 if 的 then 或 else 分支内
  (
    fa_write_or_read.getEnclosingElement+() = if_stmt.getThen()
    or
    fa_write_or_read.getEnclosingElement+() = if_stmt.getElse()
  ) and

  // (6) 局部变量在第二次访问之后仍被使用
  lv_use.getTarget() = lv and
  fa_write_or_read.getBasicBlock().getASuccessor*() = lv_use.getBasicBlock() and

  // (7) 排除编译器无法替换的情形
  not lv.getType().isConst() and
  not lv.getType().isVolatile() and
  not exists(AddressOfExpr addr | addr.getOperand() = lv.getAnAccess())

select fa_write_or_read,
  "Struct field " + fa_read.getTarget().getName() +
  " is loaded into $" + lv.getName() +
  " but accessed again without a compiler barrier (volatile/ACCESS_ONCE)."