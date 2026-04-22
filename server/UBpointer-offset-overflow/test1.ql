/**
 * 检测 Clang 优化中因 offsetof(member) > 0 导致的 &ptr->member 地址检查被优化掉的问题
 * 适用于 C 语言
 */
import cpp

predicate isNullLike(Expr e) {
    e.getValue() = "0" or
    e.toString() = "NULL" or
    e.toString() = "nullptr"
}

from AddressOfExpr addrOf, Expr cond, FieldAccess fa
where
    // 取地址操作的操作数是成员访问
        addrOf.getOperand() = fa and
    
    // 条件表达式是取地址表达式本身或基于它的操作
    (
        // 情况1: 直接在 if 语句中使用 &ptr->member
        exists(IfStmt ifs |
            cond = addrOf and
            ifs.getCondition() = cond
        ) or
        
        // 情况2: 二元操作，如 &ptr->member != NULL 或 NULL == &ptr->member
        exists(BinaryOperation bop |
            cond = bop and
            (bop.getOperator() = "!=" or bop.getOperator() = "==") and
            (
                (bop.getLeftOperand() = addrOf and isNullLike(bop.getRightOperand())) or
                (bop.getRightOperand() = addrOf and isNullLike(bop.getLeftOperand()))
            )
        ) or
        
        // 情况3: 一元操作，如 !&ptr->member
        exists(UnaryOperation uop |
            cond = uop and
            uop.getOperator() = "!" and
            uop.getOperand() = addrOf
        )
    ) and
    
    // 成员偏移量大于 0
    fa.getTarget().getByteOffset() > 0
select 
    cond, 
    "警告：条件表达式 '" + cond.toString() + "' 可能被 Clang 优化掉，" +
    "因为 offsetof(" + fa.getTarget().getName() + ") = " + 
    fa.getTarget().getByteOffset().toString() + " > 0，" +
    "导致 &" + fa.getQualifier().toString() + "->" + fa.getTarget().getName() + 
    " 被错误地假设为非 NULL。"