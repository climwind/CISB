/**
 * @name Sensitive operation may be reordered across intended guard
 * @description Detects missing compiler barriers that can cause unsafe code motion.
 * @kind problem
 * @problem.severity warning
 * @id c/reorder-cpu-check-missing-barrier
 */

import cpp

// ---------- 辅助谓词 ----------

/** 敏感的汇编指令（访问系统寄存器） */
predicate isSensitiveAsm(AsmStmt asm) {
  // 同时兼容 AT&T/Intel 风格和大小写差异，避免依赖固定文本布局
  asm.toString().regexpMatch("(?i)(^|[^a-z])(mrc|mcr|mrs|msr)([^a-z]|$)")
}

/** 汇编是否带有 "memory" 破坏列表 */
predicate hasMemoryClobber(AsmStmt asm) {
  asm.toString().regexpMatch("(?i).*\\bmemory\\b.*")
}

/** 汇编是否位于 if 语句的分支内 */
predicate isInIfBranch(AsmStmt asm, IfStmt ifs) {
  ifs.getThen().getAChild*() = asm
  or
  exists(Stmt elseStmt | elseStmt = ifs.getElse() and elseStmt.getAChild*() = asm)
}

/** 是否是编译器屏障函数调用 */
predicate isBarrierCall(FunctionCall call) {
  exists(Function f |
    call.getTarget() = f and
    (
      f.hasName("barrier") or
      f.hasName("cpu_relax") or
      f.hasName("smp_mb") or
      f.hasName("rmb") or
      f.hasName("wmb")
    )
  )
}

/** 元素是否位于某个循环语句的源码范围内（兼容部分库版本的 AST 祖先关系缺失） */
predicate isInsideLoopByLocation(Stmt loop, Expr e) {
  e.getEnclosingFunction() = loop.getEnclosingFunction() and
  e.getLocation().getStartLine() >= loop.getLocation().getStartLine() and
  e.getLocation().getEndLine() <= loop.getLocation().getEndLine()
}

/** 表达式是否是对非 volatile 全局/静态整型变量的读取 */
predicate isUnsafeGlobalRead(Expr e) {
  exists(VariableAccess va |
    va = e and
    // 不是左值（即不是被赋值的目标）
    not exists(AssignExpr assign | assign.getLValue() = va) and
    (
      va.getTarget() instanceof GlobalVariable or
      // 兼容仅声明(如 extern)但未在当前翻译单元定义的场景
      va.getTarget().toString().regexpMatch("(?i).*\\bextern\\b.*")
    ) and
    not va.getTarget().isVolatile() and
    (
      va.getTarget().getType() instanceof IntegralType or
      va.getTarget().getType().toString().regexpMatch("(?i).*(char|short|int|long|bool|size_t|u8|u16|u32|u64|s8|s16|s32|s64).*")
    )
  )
}

// ---------- 主查询 ----------

from Element n, string msg
where
  // 模式一：内联汇编缺少 memory 破坏列表，且位于条件分支内
  exists(AsmStmt asm, IfStmt ifs |
    isSensitiveAsm(asm) and
    isInIfBranch(asm, ifs) and
    not hasMemoryClobber(asm) and
    n = asm and
    msg = "Sensitive inline asm appears inside an if/else branch without a 'memory' clobber. " +
          "The compiler may reorder it across the intended CPU guard, causing crashes on unsupported hardware."
  )
  or
  // 模式二：循环内读取非 volatile 全局整型变量，且循环体内无屏障调用
  exists(Stmt loop, Expr load |
    (loop instanceof ForStmt or loop instanceof WhileStmt or loop instanceof DoStmt) and
    isInsideLoopByLocation(loop, load) and
    isUnsafeGlobalRead(load) and
    not exists(FunctionCall barrier |
      isInsideLoopByLocation(loop, barrier) and
      isBarrierCall(barrier)
    ) and
    n = load and
    msg = "Loop reads a non-volatile global/static integer variable without a barrier call " +
          "(e.g., barrier(), cpu_relax()). The optimizer may hoist the load out of the loop, " +
          "causing an infinite busy-wait."
  )
select n, msg
