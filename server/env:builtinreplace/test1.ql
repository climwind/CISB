/**
 * 检测：循环内对设备内存进行连续常量写入，但指针没有__iomem限定符
 * 风险：在某些平台上，这可能导致不兼容的内存访问方式，引发未定义行为
 */

import cpp

from Stmt l, ArrayExpr aa, PointerType pt, AssignExpr a, Expr rhs
where
  (l instanceof ForStmt or l instanceof WhileStmt or l instanceof DoStmt) and
  l.getAChild*() = aa and
  aa.getArrayBase().getType() = pt and
  aa = a.getLValue() and
  rhs = a.getRValue() and
  rhs instanceof Literal and
  not pt.toString().matches("%__iomem%")
select aa, "可能的设备内存访问问题：循环内对设备内存进行连续常量写入，但指针没有__iomem限定符。"