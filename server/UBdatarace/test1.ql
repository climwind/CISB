/**
 * @name Potential reordered shared-memory read before ready-bit extraction
 * @description Detects memcpy or struct-copy reads from likely shared memory followed by
 *              ready/flag bit extraction on copied data without an intervening memory barrier.
 * @kind problem
 * @problem.severity warning
 * @id c/ub-datarace-reordered-sharedmem-read
 */

import cpp

// 1. 识别 memcpy 调用
predicate isMemcpyCall(FunctionCall call) {
  call.getTarget().hasName("memcpy")
}

// 2. 共享内存启发式判断
predicate isSharedMemAccess(Expr e) {
  exists(VariableAccess va |
    va = e.getAChild*() and
    va.getTarget().getName().regexpMatch("(?i).*(va|ring|fifo|desc|status|hw|shared|mmio).*")
  )
  or
  exists(FieldAccess fa |
    fa = e.getAChild*() and
    fa.getTarget().getName().regexpMatch("(?i).*(va|ring|fifo|desc|status|hw|shared|mmio).*")
  )
}

// 3. 识别内存屏障类函数
predicate isBarrierLikeCall(FunctionCall call) {
  call.getTarget().hasName([
    "barrier", "smp_mb", "rmb", "wmb", "mb",
    "cpu_relax", "__sync_synchronize", "atomic_thread_fence"
  ])
  or
  call.toString().regexpMatch("(?i).*(__sync_synchronize|atomic_thread_fence|smp_mb|rmb|wmb|barrier)\\s*\\(.*")
}

// 4. 表达式中是否引用了某个变量（包含取址、强转、字段访问等包装）
predicate mentionsVariable(Expr e, Variable v) {
  exists(VariableAccess va |
    va.getTarget() = v and
    (va = e or va = e.getAChild*())
  )
}

// 5. 两个表达式是否指向同一个底层对象（启发式）
predicate sameObject(Expr a, Expr b) {
  a = b
  or
  exists(Variable v |
    mentionsVariable(a, v) and
    mentionsVariable(b, v)
  )
}

// 6. producer: 函数 f 内存在从共享内存来源读取的 memcpy
predicate isSharedMemcpyProducer(Function f, FunctionCall memcpyCall) {
  memcpyCall.getEnclosingFunction() = f and
  isMemcpyCall(memcpyCall) and
  isSharedMemAccess(memcpyCall.getArgument(1))
}

// 7. consumer: 函数 f 内存在 ready/flag 风格位提取（右移）
predicate functionExtractsReadyBit(Function f, BinaryOperation shift) {
  shift.getEnclosingFunction() = f and
  shift.getOperator() = ">>"
}

// 8. 查询：同一调用函数内，先 producer 再 consumer，且中间无 barrier
from
  Function producer, FunctionCall memcpyCall,
  Function consumer, BinaryOperation shift,
  FunctionCall callProd, FunctionCall callCons,
  Function caller, Expr argProd, Expr argCons
where
  isSharedMemcpyProducer(producer, memcpyCall) and
  functionExtractsReadyBit(consumer, shift) and
  callProd.getTarget() = producer and
  callCons.getTarget() = consumer and
  caller = callProd.getEnclosingFunction() and
  callCons.getEnclosingFunction() = caller and
  callProd.getLocation().getStartLine() < callCons.getLocation().getStartLine() and
  argProd = callProd.getAnArgument() and
  argCons = callCons.getAnArgument() and
  sameObject(argProd, argCons) and
  not exists(FunctionCall barrier |
    barrier.getEnclosingFunction() = caller and
    isBarrierLikeCall(barrier) and
    barrier.getLocation().getStartLine() > callProd.getLocation().getStartLine() and
    barrier.getLocation().getStartLine() < callCons.getLocation().getStartLine()
  )
select callCons,
  "Shared-memory copy into $@ is followed by ready/flag-bit extraction without an intervening barrier.",
  argCons, "this object"