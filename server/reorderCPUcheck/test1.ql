/**
 * 检测：内联汇编读取 CP15 寄存器时缺少 memory clobber，导致编译器可能将指令重排到 is_smp() 条件判断之前
 * 风险：在单核系统上错误执行 SMP 相关指令，引发未定义行为
 */

import cpp

from AsmStmt asmStmt, FunctionCall isSmpCall
where
  asmStmt.toString().regexpMatch(".*\\bmrc\\b.*") and
  not asmStmt.toString().regexpMatch(".*\\bmemory\\b.*") and
  exists(Function f | isSmpCall.getTarget() = f and f.getName() = "is_smp") and
  asmStmt.getParent*() = isSmpCall.getParent*()
select asmStmt, "该 mrc 内联汇编缺少 'memory' clobber，可能被编译器重排到 is_smp() 条件之前，导致单核系统错误执行。"