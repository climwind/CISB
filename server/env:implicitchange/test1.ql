import cpp

from Function f, AsmStmt a
where
  a.getEnclosingFunction() = f and
  not a.toString().regexpMatch("(?s).*\\bvolatile\\b.*")
select f, "函数包含无 volatile 限定的 asm 语句，可能被编译器错误优化。"