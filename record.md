4.28:

进展：ground truth共有29种cisb，均已完成数据库建立，已对其中22种进行试验，其中仅DSE-memset,UB pointer-offset-overflow以及UB modify const var的由提示词生成的模式可直接命中c代码，其余均不可以。而后通过修改模式，使其命中了c代码。

已对《模式问题.xlsx》中的种类进行问题描述及尝试修复，具体内容见各目录的《try.txt》文件，其余处理只保存了最终可命中的模式及ql代码。

遇到的问题：用模式对testcase进行了测试，发现生成的模式并不适用于所有情况，testcase的漏洞虽然本质上和groundtruth是相同的，但触发方式，环境因素，以及代码段所处在循环/条件判断内等不适配问题都会导致ql检测不到

例如：

情况1：解引用形式不同：模式只匹配直接对指针解引用（*ptr），但现实中还可能写成：ptr->member（同样是一次解引用）

情况2：模式中if (guard) { *ptr = value; }，写入直接放在 then 块内。而c代码中守卫是 if (g_1) return l;，写入不在 then 内，而是跟在 if 之后。若 if 为真则提前返回，写入本就不会发生（相当于隐式 else 保护）。

模式生成的ql无法命中的原因基本上都与上述情况类似，生成的模式过于局限，无法覆盖所有的漏洞触发方式和环境因素。

思考：生成的模式过于局限，无法覆盖所有的漏洞触发方式和环境因素，我先对生成的模式与testcase代码进行对比，得知问题所在后尝试改进生成的模式并重新生成ql，最终会命中testcase，但终究不是长久之计。我是否应该从模式的生成方式上寻找问题？但从提示词方面规避这类问题我认为不大可行，触发方式，环境因素，以及代码段所处在循环/条件判断内等不适配原因很多，难以通过提示词来覆盖所有情况。

以下为所有种类cisb的模式问题及尝试修复的总结：

1、UB pointer-offset-overflow

问题：

约束中 nc.isChecksNull() = false 明确要求捕获的是 “非空检查”（例如 &ptr->member、&ptr->member != NULL）。而不包含testcase中!&t->b的情况

修改：

放宽约束，代码将 &ptr->member 出现在 if 条件中的三种等价写法都考虑在内：

直接作为条件：if (&ptr->member) → 编译器会将其视为“非空检查”（隐式 != NULL）。

与 NULL 比较：if (&ptr->member != NULL) 或 if (&ptr->member == NULL) → 显式的空/非空检查。

逻辑取反：if (!&ptr->member) → 等价于 == NULL 的空检查。

2、UB elimi-shift

问题：

在 CodeQL 中，assign.getTarget() 返回的是赋值语句左侧的那个具体的 AST 节点（如某个 VariableAccess）。而后面 if (var == 0) 中的 var 是另一个 VariableAccess 节点，即使它们引用同一个变量，两个节点也不相等。
这会直接导致几乎无法匹配到任何真实代码，因为赋值左值和使用点几乎不可能是同一个 AST 节点。

修改：

修改了模式中的相关表述：vulnerable_pattern: "Assignment: **var** = 1 << expr; ... if (var < 2) ..."

ql_constraints: "... and the result is used in a Condition that checks for **var** < 2 ..."

这种表述方式直接暗示：应当基于变量符号（Variable） 来关联赋值和检查，而不是比较 AST 节点。

3、UB nonull ptr assumption

问题：deref = ptr.(PointerDereferenceExpr) 要求解引用直接作用于 ptr，当形如 *(char *)(ptr) 时，解引用的操作数是 (char *)(ptr)（一个 CastExpr），无法匹配 ptr 本身。

修改：增加 exists(Expr base | base = deref.getOperand() and base.getAChild*() = ptr.getAnAccess()) 递归穿透所有子表达式

4、UB modify const var

无问题，可直接使用

5、UB data race

问题：模式中同一函数内先 memcpy/结构体赋值再提取标志位，而testcase中需要跨函数分析：调用者依次调用“生产者”函数和“消费者”函数

修改：将 vulnerable_pattern 重写为：

“调用者函数中先调用一个从共享内存执行 memcpy 的生产者函数，再调用另一个对同一数据执行右移操作的消费者函数，且两次调用之间未插入任何内存屏障”。
这样把检测范围明确到了跨函数的调用序列，而非同一函数内的相邻语句。

6、UB reorder breaks code's atomicity

问题：模式错误地将对象限定为结构体成员，而 QL 关注的是任意全局变量。

修改：将“共享结构体成员”修正为“共享全局变量”

7、UB unaligned access

问题：原模式只针对特定函数与特定整数类型，而需要的是捕获了所有从低对齐指针类型到高对齐指针类型的强制转换后直接解引用的模式。

修改：明确“低对齐指针（void* 或基类型大小=1的指针）向更高对齐指针的强制转换并解引用”

8、UB race and reorder

问题：原始模式单一，遗漏位运算、变量名启发式，且未要求读端存在，漏报率高。

修改：
移除固定的变量名和字段名，改为指针类型字段的通用描述。

涵盖 + 和 | 两种构造方式，并补充“或由前序标记赋值派生”的语义（对应 CodeQL 的 exprComesFromEarlierTaggedAssign）。

明确要求另一函数读取同名字段，体现并发撕裂的真正风险场景。

9、UB concurrency access to global between 2 func call (which contains access to same global)

问题：模式仅提及编译器可能移除重复的 asm 指令（因缺少 volatile）。而看似“纯”的函数（访问非 volatile 全局状态）被重复调用且参数相同 → 编译器可能将函数视为无副作用并消除第二次调用。

修改：详细描述构成漏洞的具体模式：对于 cpuid asm，要求重复性、邻近性、缺失 volatile 及附近存在寄存器比较；对于函数调用，要求参数相同、被调函数访问非 volatile 全局状态且中间无屏障。

10、DB reorder(bpf)

问题：原 triggers 要求 Clang 优化、CO-RE 重定位等，但应关心 switch 内的 fall-through 导致同一变量被多次指针解引用赋值，不依赖任何编译器或宏。

修改：用一段不含特定宏的典型 C 代码替换原 __CORE_RELO 片段，展示不同 case 中通过不同宽度的指针解引用向同一变量 val 赋值，且没有 break。

11、DB invention of unaligned mem access

问题：模式局限于“没有 aligned 属性 + 数组遍历时按 sizeof 固定步长访问”这一特定场景，关注编译器默认对齐变化导致的步长错误。而只要两个同类型变量被放入同一个 section 且对齐要求不同（显式有 aligned 或无 aligned，或数值不同），都应被认为存在风险。

修改：强调 同一 section 内变量间有效对齐不一致导致段内布局破坏，无论后续是否用指针算术遍历，不一致的对齐本身就会破坏内存布局。这与 QL 的 getEffectiveAlignment(v1) != getEffectiveAlignment(v2) 以及检查相同 section 名称的逻辑一致。

12、DB byte-wide->word-wide

问题：原模式只描述了“extern <integral_type> <variable_name>;”的声明形式，未体现这种声明如何被错误使用。代码中实际的问题是：该变量（或经过 __builtin_assume_aligned 的结果）作为指针参数传给了字节级读写宏（如 get_unaligned_le32），而编译器可能因为假定对齐而生成字对齐的访存指令。

修改：把 __builtin_assume_aligned(ptr, n) （n>1）也作为源，因为它会让编译器错误地假定指针已经对齐，从而在后续经过字节宏时同样会引入字对齐指令。

13、DB transfer mem load to reg load
未实现

14、condItional load->non-condItional load

问题：模式中if (guard) { *ptr = value; }，写入直接放在 then 块内。而c代码中守卫是 if (g_1) return l;，写入不在 then 内，而是跟在 if 之后。若 if 为真则提前返回，写入本就不会发生（相当于隐式 else 保护）。

修改：引入双形态保护识别,将模式拆分为两种合法保护形式，但合并为一个统一的约束。显式保护沿用了原有“写入在 then 内”的逻辑；隐式保护通过控制流结构判断：if 的 then 以终止语句结尾，且写入在 if 之后可达。

15、reorder CPU check

问题：原模式只检测“内联汇编缺少 memory clobber 且位于条件分支内”这一种情况,而应该同时涵盖两种编译器重排序漏洞：

敏感汇编（mrc/mcr/mrs/msr）在 if 分支内未声明 "memory" 破坏列表

循环体内读取非 volatile 全局整型变量，且循环内无编译器屏障调用（如 barrier()、cpu_relax()），导致 load 被提升到循环外

修改：vulnerable_pattern 扩展为两大模式，描述覆盖 QL 中 isSensitiveAsm 和循环 load 提升检查，并指出违反的编译器重排序原理。

16、env:built in replace

问题：原模式仅描述“循环常值赋值被优化成 memset”的场景；但应同时检测 两类 编译器优化导致的潜在问题：

内联汇编缺少 "memory" clobber，且由 is_smp() 守卫

全局数组的常值填充循环可能被替换为 memset/memcpy

修改：被拆分为两段，分别描述汇编重排序和循环替换的成因。对于循环部分，不再硬编码设备内存、指针解引用或 __iomem，而是聚焦于 全局数组元素被赋予常量 这一编译器可识别模式，与 QL 中的 isBuiltinReplaceCandidate 谓词语义对齐。

17、env: transfer memcpy to unaligned ldx

问题：原约束 not s.hasAttribute("aligned") 意图排除显式对齐的结构体，但C代码中 struct a 恰恰带有 __attribute__((aligned(4)))，导致该结构体被直接排除，即使后续的 memcpy 操作确实存在对齐不足的问题。漏洞的本质是对齐属性值低于操作所需对齐，而非有无属性。

修改：将分析对象从结构体声明改为 memcpy/memmove/memset 函数调用。直接从可能存在问题的内存操作入手，提取调用参数，计算对齐需求，避免全局扫描结构体。

18、env varient->memcpy->unaligned ldx

问题：原模式检测的是源代码中显式调用 memset/memcpy 的表达式（FunctionCall）。但 C 代码里根本没有这样的显式调用，只有 struct bar x = {{0}}; 和 y = x;，所以匹配不到。
修改：不再在 AST 上寻找函数调用表达式 FunctionCall，而是寻找源代码层面两个会被编译器替换的操作

19、env: implicit change between 2 same check

问题：QL 约束中使用的谓词名称在 CodeQL 标准库中并不存在

修改：改为通过正则检查汇编文本中是否出现 volatile 关键字，以覆盖 volatile 和 __volatile__ 等多种写法。

20、env: implicit read between 2 stores

问题：原始约束因为左值类型严格限定为指针解引用、仅关注同函数且同一表达式引用，完全无法匹配这种通过结构体成员赋值和函数参数传递的典型场景。

修改：将写入左值从指针解引用放宽为“任意形式的变量访问”， 关联条件从“同一指针表达式”改为“同一变量地址传递”，覆盖跨函数调用场景（static inline 函数）

21、store tearing->race

问题：原始 ql_constraints 不能表达“多次读取”的漏洞模式

修改：增加“同一函数内两次读取”约束
使用 read1.getEnclosingFunction() = f、read2.getEnclosingFunction() = f、read1 != read2 和行序比较，确保两次不同的纯读访问发生在同一函数内。这是核心改动，直接对应编译器读合并风险。

22、eliminate local variable

问题：fa 是一个 FieldAccess（如 inet.hdrincl），fa.getTarget() 返回的是被访问的对象表达式（即 inet），它是一个普通的变量访问，类型为 VariableAccess，绝不可能是 BitField。BitField 在 CodeQL 中代表位域字段声明本身（属于 Field 的子类），只能用 FieldAccess.getField() 获得。因此该条件永远为假，查询不会返回任何结果，自然无法命中示例代码。
修改：

捕获变量的来源
原始约束仅考虑 Assignment（a.getTarget() = v），但漏洞代码使用的是声明初始化（unsigned int hdrincl = inet.hdrincl）。你的 QL 增加了 v.getInitializer().getExpr() = fa，将初始化也纳入检测范围。

位域判断方式
原始约束假想了一个 StructMemberAccess.isBitField() 谓词，实际 CodeQL 中不存在。你先后尝试了 fa.getTarget().toString().regexpMatch(".*:.*")、fa.getType() instanceof BitFieldType 等，最终选择了 fa.getTarget() instanceof BitField，但该写法错误地针对了 FieldAccess 的目标对象而非字段本身。

读取次数的判定
原始约束仅通过 not exists(ReadOrWrite r | ...) 抽象表述，你的 QL 具体化为两个不同的 VariableAccess 节点（read1 和 read2）且都不是左值，精确捕捉了“多次读取同一局部变量”的模式。

23、break atomicity(load tearing)

问题：模式 检查赋值的目标类型是否为 StructType，而不约柬类型大小，也未要求指针发生过类型转换。这会将所有结构体赋值（无论大小和是否截断）均视为潜在问题，误报率较高。

修改：严格限定为“对 ≥8 字节无符号整数/单字段结构体指针进行显式类型截断后再赋值”，不再泛指所有结构体赋值。

24、data race
未完成

25、DSE-memset
无问题

26、padding copied to user space
未完成

27、part of union not init
未完成

28、time side channel
未完成

29、noop loop for time order(concurrency)
未完成

30、switch jump table
未完成
