import cpp

from FunctionCall fc, Function f
where
  fc.getTarget() = f and
  f.hasName("memset") and
  exists(AsmStmt ia | ia.getEnclosingFunction() = f) and
  not exists(ReturnStmt rs, VariableAccess va |
    rs.getEnclosingFunction() = f and
    va = rs.getExpr() and
    va.getTarget() = f.getParameter(0)
  )
select fc, "Assembly implementation of memset does not return the expected value (first argument) as per C standard specification, while compiler optimizations rely on this assumption."