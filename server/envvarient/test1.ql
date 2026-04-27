/**
 * @name 可能被编译器优化为 memset/memcpy 的代码
 * @description 检测结构体/联合体的零初始化和直接赋值。
 *              这些操作常被编译器替换为 memset 或 memcpy 调用。
 *              若操作数涉及 I/O 内存指针 (__iomem)，可能引入严重漏洞。
 * @kind problem
 * @problem.severity warning
 * @id cpp/implicit-memcpy-memset
 */

import cpp

/**
 * 判断表达式是否直接或间接引用 I/O 内存。
 * 简单实现为检查类型名是否包含 '__iomem' 或是否为 volatile 限定。
 */
predicate isIOMemoryType(Type t) {
  t.toString().matches("%__iomem%") or
  t.isVolatile()
}

/**
 * 模式1：聚合零初始化 -> 可能生成 memset
 */
predicate isAggregateZeroInit(Variable v) {
  (v.getType() instanceof Struct or v.getType() instanceof Union) and
  exists(AggregateLiteral init |
    init = v.getInitializer().getExpr() and
    (
      init.getNumChild() = 0 or
      init.getNumChild() = 1 and init.getChild(0).toString() = "0"
    )
  )
}

/**
 * 模式2：结构体/联合体直接赋值 -> 可能生成 memcpy
 */
predicate isStructOrUnionAssign(AssignExpr a) {
  a.getLValue().getType() instanceof Struct
  or a.getLValue().getType() instanceof Union
}

from Element e, string msg
where
  exists(Variable v |
    e = v and
    isAggregateZeroInit(v) and
    msg =
      "聚合类型的零初始化可能被编译器优化为 memset。如果位于 I/O 内存中可能造成问题。" +
      "类型：" + v.getType().toString()
  )
  or
  exists(AssignExpr a |
    e = a and
    isStructOrUnionAssign(a) and
    msg =
      "结构体/联合体直接赋值可能被编译器优化为 memcpy。如果目标属于 I/O 内存可能造成问题。" +
      "类型：" + a.getLValue().getType().toString()
  )
select e, msg