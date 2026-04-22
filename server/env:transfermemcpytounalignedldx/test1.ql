/**
 * 检测：结构体定义缺乏显式对齐属性，导致编译器假设的对齐比运行时更高，可能引发未对齐访问错误
 * 风险：在严格对齐要求的架构（如某些 RISC）上，可能导致程序崩溃或未定义行为
 */

import cpp

from Struct s, FunctionCall fc, Expr destArg, PointerType pt
where
  fc.getTarget().hasName("memcpy") and
  destArg = fc.getArgument(0) and
  destArg.getType() = pt and
  pt.getBaseType() = s and
  not s.toString().matches("%aligned%") and
  destArg.toString().matches("%+%")
select s, "该结构体缺乏显式对齐属性，可能导致未对齐内存访问错误。"