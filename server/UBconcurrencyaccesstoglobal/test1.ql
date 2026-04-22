/**
 * 检测模式：非 volatile 的内联汇编读取可变硬件状态。
 *
 * 触发条件：
 * 1) 编译优化开启（-O1/-O2/-O3）时更容易被优化器重排或合并。
 * 2) 内联汇编语句未使用 volatile。
 * 3) 汇编指令读取会随时间/环境变化的硬件状态（例如 cpuid、rdtsc）。
 *
 * 说明：源码层面通常无法直接确认编译参数是否开启优化，
 * 本规则聚焦于源码可见的高风险模式（2)+(3)。
 */

import cpp

/**
 * 识别读取可变硬件状态的常见指令。
 */
predicate readsMutableHardwareState(AsmStmt asm) {
	asm.toString().regexpMatch("(?i).*(\\bcpuid\\b|\\brdtsc\\b|\\brdtscp\\b|\\bmrs\\b|\\bmrc\\b).*")
}

/**
 * 兼容当前库版本：AsmStmt 无 isVolatile()，改用文本判断 volatile 关键字。
 */
predicate hasVolatileQualifier(AsmStmt asm) {
	asm.toString().regexpMatch("(?i).*(\\bvolatile\\b|__volatile__).*")
}

from AsmStmt asm
where
	not hasVolatileQualifier(asm) and
	readsMutableHardwareState(asm)
select asm,
	"该内联汇编读取可变硬件状态但未使用 volatile；在优化编译下可能被重排/合并，导致每次调用无法保证重新执行。"
