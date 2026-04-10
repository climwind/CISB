/**
 * @name 潜在的编译器死代码消除 (CISB) - C/C++ 版
 * @description 检测对敏感内存的写入（如 memset），如果后续没有读取，可能会被编译器优化掉。
 * @kind problem
 * @problem.severity warning
 * @id cpp/cisb/dead-store-robust
 */

// 仅导入 C++ 标准库和数据流库
import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall fc, Expr targetArg
where
  // ==========================================
  // 1. 匹配敏感操作：memset 或 __builtin_memset
  // ==========================================
  (
    fc.getTarget().getName() = "memset" or
    fc.getTarget().getName() = "__builtin_memset"
  )
  and targetArg = fc.getArgument(0)

  // ==========================================
  // 2. 核心漏洞检测：检查是否存在“死存储”
  // ==========================================
  // 逻辑：如果从 targetArg 开始，在局部数据流中找不到任何“读取”节点，
  // 说明写入的数据从未被使用，会被编译器优化（死存储消除）。
  //
  // 注意：这里使用 not exists 来模拟“无后续依赖”。
  // DataFlow::localFlow 会自动处理指针别名和局部变量传递。
  //
  and not exists(DataFlow::Node source, DataFlow::Node sink |
    // 定义源：当前的 memset 目标
    source.asExpr() = targetArg and
    // 定义流：存在局部数据流
    DataFlow::localFlow(source, sink) and
    // 定义汇：必须是一个“读取”操作。
    // 在 C++ 库中，如果一个表达式是数据流的 Sink 且不是赋值的目标，通常意味着它被使用了。
    // 为了更精确，我们排除掉它仅仅作为赋值左值（写入）的情况。
    not sink.asExpr() instanceof AssignExpr and
    not sink.asExpr() = targetArg
  )

  // ==========================================
  // 3. 过滤：排除 volatile 变量（编译器不会优化 volatile）
  // ==========================================
  // 在 C++ 中，volatile 是类型修饰符。我们需要检查 targetArg 的类型是否包含 volatile。
  and not targetArg.getType().isVolatile()

select fc, "潜在的 CISB 漏洞：此内存操作（$@）的结果未被后续使用，可能被编译器优化移除。", targetArg, targetArg.toString()