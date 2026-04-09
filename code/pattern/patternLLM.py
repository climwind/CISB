# -*- coding: utf-8 -*-
# Please install OpenAI SDK first: `pip3 install openai`
import os
from openai import OpenAI

report = {

}
prompt = "请扮演一位代码安全分析专家和编译器专家。你的任务是分析我提供的多个 CISB (Compiler-Induced Security Bugs) 实例，从中提取一个高度抽象的、通用的漏洞模式。这个模式将用于帮助安全工程师或自动化工具（如 CodeQL）识别和预防同类问题。\
    \n输入数据：你将收到一个列表，其中每个条目都包含一个 Linux 内核 commit 的详细信息，包括 commit 信息、代码变更（patch）以及针对该 commit 的详细五步分析。这些分析已经确认每个 commit 修复的是一个 CISB，并分类为 ISpec (隐式规范类) 或 OSpec (正交规范类)。\
    \n分析任务：请仔细研读这些实例，忽略它们各自的具体功能（如随机数、加密、调试等），专注于触发条件、漏洞代码模式、以及编译器优化行为的本质。你需要将这些实例抽象成一个统一的、通用的 CISB 模式。\
    \n输出格式：请严格按照以下三个部分输出你的抽象结果。\
    \n第一部分：triggers:一个包含最关键、最必要触发条件的数组。这些条件是导致该漏洞发生的“必要条件”。每个条件需要高度概括且简洁。\
    示例元素：特定的编译优化级别（如 -O2 或更高）、程序上下文（如 局部变量、静态变量、自定义节区）、编译器行为（如 死代码消除、常量传播、内联）、代码特征（如 存在无副作用的函数调用、存在未使用的返回值）、安全意图特征（如 数据清理、安全测试、关键数据存储）\
    \n第二部分：vulnerable_pattern:一个高度抽象、与具体功能无关的漏洞代码片段表示。它应该描述程序员意图与编译器假设发生冲突的那个代码结构。\
    \n第三部分ql_constraints:作为 CodeQL 检测模板中最应关注的约束条件。用 QL 语法风格表示，目标是帮助编写一个可以定位潜在 CISB 的查询。" 


client = OpenAI(
    api_key=os.environ.get('DEEPSEEK_API_KEY'),
    base_url="https://api.deepseek.com")

response = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "system", "content":prompt},
        {"role": "user", "content": str(report)},
    ],
    stream=False
)
with open("output.txt", "a", encoding="utf-8") as f:
    f.write(response.choices[0].message.content + "\n")
print(response.choices[0].message.content)
