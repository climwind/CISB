/**
 * @name Multiple reads of non-volatile, non-atomic shared variable
 * @description A global or static variable that is written elsewhere is read
 *              multiple times in the same function without explicit ordering
 *              (volatile, atomic, or barrier). The compiler may merge these
 *              reads into a single load, causing the function to see a stale
 *              value even though the variable has been modified by another
 *              thread or interrupt.
 * @kind problem
 * @problem.severity warning
 * @id cpp/concurrency/multiple-reads-merge
 */

import cpp

/*
 * 判断一个 VariableAccess 是否为对变量的“纯读访问”：
 *  - 不在赋值左值位置
 *  - 不在自增/自减操作中
 *  - 不是取地址操作的操作数
 */
predicate isPureRead(VariableAccess va) {
  not exists(AssignExpr assign | assign.getLValue() = va) and
  not va.getParent() instanceof CrementOperation and
  not va.getParent() instanceof AddressOfExpr
}

/*
 * 判断变量是否被至少一次“写”操作修改。
 * 写操作包括：
 *  - 作为赋值的左值
 *  - 作为自增/自减的操作数
 */
predicate hasWrite(Variable v) {
  exists(VariableAccess va |
    va.getTarget() = v and
    (
      exists(AssignExpr assign | assign.getLValue() = va)
      or
      va.getParent() instanceof CrementOperation
    )
  )
}

from Function f, Variable v, VariableAccess read1, VariableAccess read2
where
  /*
   * 1. 变量为全局或静态（多执行上下文可能共享）
   * 2. 非 volatile，非 _Atomic
   * 3. 存在对其进行写入的操作（说明可能被并发修改）
   */
  (v instanceof GlobalVariable or v.isStatic()) and
  not v.isVolatile() and
  not v.getType().toString().regexpMatch("(?i).*(\\b_Atomic\\b|\\batomic\\b|std::atomic).*") and
  hasWrite(v) and

  /*
   * 4. 同一函数 f 内存在两个不同的纯读访问
   * 5. 按源码行序保证先后关系（避免自反）
   */
  read1.getTarget() = v and
  read2.getTarget() = v and
  read1 != read2 and
  read1.getEnclosingFunction() = f and
  read2.getEnclosingFunction() = f and
  isPureRead(read1) and
  isPureRead(read2) and
  read1.getLocation().getStartLine() < read2.getLocation().getStartLine() and

  /*
   * 6. 排除读发生在宏展开中的情况（可保留，便于内联场景）
   */
  read1.getLocation().getStartLine() > 0 and
  read2.getLocation().getStartLine() > 0

select f,
  "Function $@ reads non-atomic shared variable $@ multiple times; " +
  "compiler may merge the reads, leading to use of a stale value.",
  f, f.getName(), v, v.getName()