/**
 * @name 同一自定义段中结构体变量对齐不一致
 * @description 在同一个 __attribute__((section(...))) 段内，存在同一种结构体类型的多个变量，
 *              但它们的内存对齐要求不同（有的有 aligned，有的没有；或 aligned 值不同）。
 *              这会导致对象之间出现不可预测的填充，固定 sizeof 步长的遍历会访问无效数据。
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/mismatched-alignment-in-section
 */

import cpp

/** 获取变量所在的自定义段名称（去除编译器前缀） */
string getSectionName(Variable v) {
  exists(Attribute a | a = v.getAnAttribute() and a.getName() = "section" |
    result = a.getArgument(0).getValueText()
  )
}

/** 获取变量的有效对齐值（字节） */
int getEffectiveAlignment(Variable v) {
  // 如果有 aligned 属性，取其值；否则取默认对齐（假设为 4，或者可再查询类型对齐）
  (
    exists(Attribute a |
      a = v.getAnAttribute() and
      a.getName() = "aligned" and
      result = a.getArgument(0).getValueText().toInt()
    )
  )
  or
  (
    not exists(Attribute a | a = v.getAnAttribute() and a.getName() = "aligned") and
    result = 4
  )  // 典型默认值，实际可改为 v.getType().getAlignment()
}

from Struct s, Variable v1, Variable v2
where
  v1 != v2 and
  v1.getType().getUnderlyingType() = s and
  v2.getType().getUnderlyingType() = s and
  exists(string sec | sec = getSectionName(v1) and sec = getSectionName(v2)) and
  getEffectiveAlignment(v1) != getEffectiveAlignment(v2)
select v1, "变量 $@ 和 $@ 位于同一 section 但对齐要求不同（%d vs %d），可能破坏段内布局。",
  v1, v1.getName(), v2, v2.getName(), getEffectiveAlignment(v1), getEffectiveAlignment(v2)