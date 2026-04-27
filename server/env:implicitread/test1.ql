/**
 * @name 内联汇编缺少 "memory" clobber 导致死存储消除
 * @description 检查对某变量写入常量后，将其地址传给含有内联汇编（无 "memory" clobber）的函数，
 *              或直接在同函数内被无 clobber 的汇编读取，可能导致编译器消除该写操作。
 * @kind problem
 * @problem.severity warning
 * @id cpp/inline-asm-missing-memory-clobber
 */
import cpp

from AssignExpr store, AsmStmt asm, Expr asmInput, Variable v
where
  // store 写入一个常量
  store.getRValue() instanceof Literal and
  // store 的左值最终引用变量 v（可穿透 FieldAccess, ArrayAccess 等）
  exists(VariableAccess lhsVa |
    lhsVa = store.getLValue().getAChild*() and
    lhsVa.getTarget() = v
  ) and
  (
    // 情况1：汇编与 store 在同一函数内（例如内联展开后），汇编输入是 &v 或直接引用 v
    asm.getEnclosingFunction() = store.getEnclosingFunction() and
    not asm.toString().regexpMatch("(?i).*\\bmemory\\b.*") and
    (
      asmInput = asm.getAChild*() and
      (asmInput.(AddressOfExpr).getOperand() = v.getAnAccess() or asmInput = v.getAnAccess())
    ) and
    store.getLocation().getStartLine() < asm.getLocation().getStartLine()
    or
    // 情况2：store 与汇编通过静态内联函数调用关联（未内联），调用前写入 v，调用时传入 &v
    exists(Function f, Call call, Parameter p |
      f.isStatic() and f.isInline() and
      asm.getEnclosingFunction() = f and
      not asm.toString().regexpMatch("(?i).*\\bmemory\\b.*") and
      asmInput = asm.getAChild*() and
      asmInput = p.getAnAccess() and
      call.getTarget() = f and
      exists(int i |
        i in [0 .. call.getNumberOfArguments()-1] and
        call.getArgument(i).(AddressOfExpr).getOperand() = v.getAnAccess() and
        f.getParameter(i) = p
      ) and
      store.getEnclosingFunction() = call.getEnclosingFunction() and
      store.getLocation().getStartLine() < call.getLocation().getStartLine()
    )
  )
select store,
  "对变量 " + v.getName() + " 的常量写入可能被消除，因为后续内联汇编缺少 'memory' clobber，"
  + "编译器可能认为该写入是死存储。"