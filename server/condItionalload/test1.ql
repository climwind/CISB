import cpp

/**
 * 判断变量是否具有全局或静态存储期。
 */
predicate isGlobalOrStatic(Variable v) {
  v instanceof GlobalVariable or
  v.isStatic()
}

/**
 * 判断一个赋值表达式是否写入了全局或静态变量（支持直接变量和数组元素）。
 */
predicate isGlobalWrite(AssignExpr a) {
  exists(Variable v |
    v = a.getLValue().(VariableAccess).getTarget()
    or
    v = a.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()
  |
    v instanceof GlobalVariable or v.isStatic()
  )
}

/**
 * 判断表达式是否来自已知的同步/加锁函数调用。
 */
predicate isSyncCondition(Expr cond) {
  exists(FunctionCall fc |
    fc = cond.getAChild*() and
    fc.getTarget().getName().regexpMatch(".*(lock|acquire|trylock).*")
  )
}

/**
 * 终止语句。
 */
predicate isExitStmt(Stmt s) {
  s instanceof ReturnStmt or
  s instanceof BreakStmt or
  s instanceof ContinueStmt or
  s instanceof GotoStmt
}

/**
 * 获取块（或单条语句）的最后一条语句。
 */
Stmt lastStmt(Stmt b) {
  if b instanceof BlockStmt
  then result = b.(BlockStmt).getLastStmt()
  else result = b
}

/**
 * 模式1：写入位于 if 的 then 分支内部。
 */
predicate writeInThen(IfStmt ifStmt, AssignExpr write) {
  write.getEnclosingStmt+() = ifStmt.getThen() and
  isGlobalWrite(write) and
  not isSyncCondition(ifStmt.getCondition())
}

/**
 * 模式2：写入跟在“提前返回”的 if 之后（同一个函数内，if 在前，写入在后）。
 */
predicate writeAfterGuardedReturn(IfStmt ifStmt, AssignExpr write) {
  exists(Function f, Stmt writeStmt |
    f = ifStmt.getEnclosingFunction() and
    f = write.getEnclosingFunction() and
    writeStmt = write.getEnclosingStmt() and
    // if 在写入语句之前（行号比较）
    ifStmt.getLocation().getStartLine() < writeStmt.getLocation().getStartLine() and
    // 写入不在 if 的 then / else 分支内
    not write.getEnclosingStmt+() = ifStmt.getThen() and
    not write.getEnclosingStmt+() = ifStmt.getElse() and
    // then 分支的最后一条语句是退出语句
    isExitStmt(lastStmt(ifStmt.getThen())) and
    // else 不存在，或者 else 不以退出语句结束（保证后续代码可达）
    (not exists(ifStmt.getElse()) or not isExitStmt(lastStmt(ifStmt.getElse()))) and
    // 排除显式同步条件
    not isSyncCondition(ifStmt.getCondition())
  ) and
  isGlobalWrite(write)
}

from IfStmt ifStmt, AssignExpr write, string pattern
where
  (writeInThen(ifStmt, write) and pattern = "write inside then-branch")
  or
  (writeAfterGuardedReturn(ifStmt, write) and pattern = "write after early-exit guard")
select write, "Potential misspeculated write ($@) due to compiler optimization: " + pattern, ifStmt, "guarding condition"