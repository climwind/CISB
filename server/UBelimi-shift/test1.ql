/**
 * @name 左移未定义行为导致条件检查被优化
 * @kind problem
 * @id cpp/undefined-left-shift-in-condition
 */

import cpp

from BinaryOperation shift, int shiftAmount
where
  shift.getOperator() = "<<" and
  // 移位量为常量
  shiftAmount = shift.getRightOperand().getValue().toInt() and
  // 获取左操作数底层类型的大小（字节）并转换为位宽
  exists(Type leftType, Type underlying, int bytes |
    leftType = shift.getLeftOperand().getType() and
    underlying = leftType.getUnderlyingType() and
    underlying instanceof IntegralType and
    bytes = underlying.getSize() and
    bytes > 0 and
    shiftAmount >= bytes * 8
  ) and
  // 左移表达式直接出现在条件中
  ( exists(IfStmt s | s.getCondition() = shift) or
    exists(WhileStmt s | s.getCondition() = shift) or
    exists(DoStmt s | s.getCondition() = shift) or
    exists(ForStmt s | s.getCondition() = shift) or
    exists(ConditionalExpr ce | ce.getCondition() = shift) )
select shift, "左移操作移位量 " + shiftAmount +
  " 大于等于左操作数位宽，属于未定义行为。此表达式用于条件判断，编译器可能优化掉该检查。"