/**
 * @name Potential unaligned pointer dereference after cast
 * @description Detects dereference of pointers cast from low-alignment pointer types (void/byte) to higher-alignment pointee types.
 * @kind problem
 * @problem.severity warning
 * @id cpp/potential-unaligned-deref-after-cast
 */
import cpp

/**
 * 源类型是低对齐指针：void 指针或基类型大小为 1 字节的字节指针。
 */
predicate isLowAlignmentPointerType(PointerType pt) {
	pt.getBaseType().toString().matches("%void%") or
	pt.getBaseType().getSize() = 1
}

/**
 * 目标类型是更高对齐需求的指针：以基类型大小 > 1 字节作为保守近似。
 */
predicate isHigherAlignmentPointerType(PointerType pt) {
	pt.getBaseType().getSize() > 1
}

from PointerDereferenceExpr deref, Cast cast
where
	// cast 位于该解引用表达式源码区间内（兼容不同库版本下的 AST 连接差异）
	cast.getFile() = deref.getFile() and
	cast.getLocation().getStartLine() = deref.getLocation().getStartLine() and
	cast.getLocation().getStartColumn() >= deref.getLocation().getStartColumn() and
	cast.getLocation().getEndColumn() <= deref.getLocation().getEndColumn() and
	exists(PointerType srcPtrTy, PointerType dstPtrTy |
		cast.getExpr().getType() = srcPtrTy and
		cast.getType() = dstPtrTy and
		isLowAlignmentPointerType(srcPtrTy) and
		isHigherAlignmentPointerType(dstPtrTy)
	)
select deref,
	"Potential unaligned access: cast from low-alignment pointer to higher-alignment pointer and then dereference."
