/**
 * 检测C语言中可能被编译器优化掉的memset调用
 * 漏洞模式：在局部数组/变量上使用memset清零，但编译器认为该操作对程序可观察行为无影响
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall fc
where 
  // 检查是否为memset函数调用
  fc.getTarget().hasName("memset") and
  
  // 检查第二个参数是否为0
  fc.getArgument(1).getValue().toInt() = 0 and
  
  // 检查没有后续使用该内存区域
  not exists(DataFlow::Node use |
    exists(DataFlow::ExprNode src |
      src.getExpr() = fc and
      DataFlow::localFlow(src, use) and
      use.asExpr() != fc
    )
  )
select fc, "可能被编译器优化掉的memset调用：该内存区域在清零后没有被使用，编译器可能认为此操作对程序可观察行为无影响。"