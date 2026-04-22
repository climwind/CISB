/**
 * @name Direct memset/memcpy on __iomem pointer in inline/static function
 * @description Detects direct calls to standard memory functions with an I/O memory pointer.
 * @kind problem
 * @problem.severity warning
 * @id c/iomem-direct-memset-memcpy
 * @tags reliability
 *       correctness
 *       security
 */

import cpp

from FunctionCall fc, Function f
where
	(fc.getTarget().hasName("memset") or fc.getTarget().hasName("memcpy")) and
	fc.getArgument(0).getType().toString().matches("%__iomem%") and
	f = fc.getEnclosingFunction() and
	(f.isInline() or f.isStatic())
select
	fc,
	"Direct call to $@ with __iomem pointer in inline/static function may be unsafe under optimization.",
	fc.getTarget(),
	fc.getTarget().getName()
