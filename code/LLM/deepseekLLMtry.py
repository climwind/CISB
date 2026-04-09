# Please install OpenAI SDK first: `pip3 install openai`
import os
from openai import OpenAI

report = {
    """ void __init *set_except_vector(int n, void *addr)
{
	unsigned long handler = (unsigned long) addr;
	unsigned long old_handler = exception_handlers[n];
    exception_handlers[n] = handler;
	if (n == 0 && cpu_has_divec) {
		unsigned long jump_mask = ~((1 << 28) - 1);
		u32 *buf = (u32 *)(ebase + 0x200);"""
}
prompt = "你是一个代码安全分析专家，任务是判断一段代码是否可能受到“编译器引入的安全漏洞（CISB）”的影响。\
            请按照以下五个步骤进行结构化推理：\
            \n步骤一：理解程序员的原始安全意图。分析这段代码试图实现什么安全目标（例如：防止信息泄露、防止空指针解引用、确保数据完整性、恒定时间执行等）**注意：程序员的意图可能依赖于特定的运行环境，例如在某些嵌入式系统中空指针解引用不会导致崩溃，而是可以读取特定地址的值。**。   \
            \n步骤二：识别编译器的假设与优化行为。基于语言规范，编译器可能做出哪些假设？（例如：假设没有未定义行为、假设某些操作是冗余的、假设函数总是返回等）编译器可能执行哪些优化？（例如：死代码消除、指令重排、函数内联、类型提升等）\
            \n步骤三：分析“意图”与“假设”之间的冲突。程序员的原始安全目标与编译器的假设是否冲突？如果有冲突，冲突点是什么？（例如：程序员依赖某个未定义行为，而编译器假设它不存在）\
            \n步骤四：判断是否满足CISB的四个必要条件。逐一检查以下四个条件是否同时满足：\
            1、源代码安全：代码在没有优化时，在目标机器上没有安全问题\
            2、编译器引入：编译器优化在编译期间修改代码，创建了漏洞\
            3、代码合规：代码不包含任何语言关键字的不正确使用\
            4、编译器正确：编译器优化是形式正确的，即编译器不违反任何语言规范\
            \n步骤五：分类与漏洞模式匹配。如果以上四个条件均满足，则进一步判断属于哪一类CISB：\
            \nA.隐式规范类（ISpec） 检查是否匹配以下模式之一：\
            ISpec1：安全检查被移除（如空指针检查、边界检查、整数溢出检查）。\
            ISpec2：顺序敏感的安全操作被重排（如检查后使用、内存操作顺序）\
            ISpec3：不安全指令被引入或替换（如未对齐访问、类型提升、函数替换）\
            \nB.正交规范类（OSpec）检查是否匹配以下模式之一：\
            OSpec1：敏感数据清零操作被删除（如 memset、memzero_explicit）\
            OSpec2：执行时间保证被破坏（如恒定时间比较被优化）\
            OSpec3：引入推测执行侧信道（如边界检查被绕过）\
            \n输出格式：\
            不要输出上述步骤，直接在最后一行直接输出判断结果，格式为：\
            【是CISB - [ISpec/OSpec]类】 + 简要说明/【不是CISB】 + 原因（如不满足某条件或不属于已知模式）\
            \n请不要过度推理，也不需要自由发挥。\
            "

client = OpenAI(
    api_key=os.environ.get('DEEPSEEK_API_KEY'),
    base_url="https://api.deepseek.com")

# 原代码保持不变，仅修改 model 和增加思维链输出
response = client.chat.completions.create(
    model="deepseek-reasoner",  # 使用推理模型
    messages=[
        {"role": "system", "content": prompt},
        {"role": "user", "content": str(report)},
    ],
    stream=False
)

msg = response.choices[0].message

# 先输出思维链内容
if hasattr(msg, 'reasoning_content') and msg.reasoning_content:
    print("【思维链】")
    print(msg.reasoning_content)
    print("\n【最终结果】")

# 再输出最终回答
print(msg.content)
