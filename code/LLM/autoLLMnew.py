# -*- coding: utf-8 -*-
import os
import json
from openai import OpenAI

# 固定的分析提示（保持不变）
prompt = "你是一个代码安全分析专家，任务是分析一个补丁，判断该补丁所修改的原始代码是否可能受到“编译器引入的安全漏洞（CISB）”的影响。\
            补丁以JSON格式提供，每个条目包含commit信息、修改的内容及前后代码片段。你需要结合修改前后的变化，综合推理原始代码中是否存在CISB。\
            请按照以下五个步骤进行结构化推理：\
            \n步骤一：理解程序员的原始安全意图。分析原始代码试图实现什么安全目标（例如：防止信息泄露、防止空指针解引用、确保数据完整性、恒定时间执行等）**注意：程序员的意图可能依赖于特定的运行环境，例如在某些嵌入式系统中空指针解引用不会导致崩溃，而是可以读取特定地址的值。**。如果修改是为了修复一个漏洞，那么原始代码中可能存在某种安全缺陷，需推断出原始代码本应达到但未达成的安全属性。   \
            \n步骤二：识别编译器的假设与优化行为。基于代码语言规范，编译器编译原始代码时可能做出哪些假设？（例如：假设没有未定义行为、假设某些操作是冗余的、假设函数总是返回等）编译器可能执行哪些优化？（例如：死代码消除、指令重排、函数内联、类型提升等）\
            \n步骤三：分析“意图”与“假设”之间的冲突。程序员的原始安全目标与编译器的假设是否冲突？如果有冲突，冲突点是什么？（例如：程序员依赖某个未定义行为来保证安全，而编译器假设该未定义行为不存在并据此优化掉检查；或者程序员期望敏感数据被清零，而编译器认为存储是冗余的并消除它）\
            \n步骤四：判断是否满足CISB的四个必要条件。逐一检查以下四个条件在原始代码中是否同时满足：（注意：如果开发者利用未定义行为来实现某个特定目的或功能，则该未定义行为不能作为判断源代码不存在CISB的依据）\
            1、源代码安全：原始代码在没有经过编译器优化时，在目标机器上没有安全问题（注意：如果开发者利用了未定义行为来实现某个特定目的或功能，视为该未定义行为并非源代码中的安全问题）\
            2、编译器引入：编译器优化在编译期间修改代码，创建了漏洞\
            3、代码合规：原始代码不包含任何语言关键字的错误使用。（注意：如果开发者利用了未定义行为来实现某个特定目的或功能，则该未定义行为视为代码合规）\
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
            不要输出上述步骤，直接在最后一行直接输出判断结果。\
            最后一行输出判断结果，格式为：\
            【是CISB - [ISpec/OSpec]类】 + 简要说明/【不是CISB】 + 原因（如不满足某条件或不属于已知模式）\
            \n注意：请不要过度推理，也不需要自由发挥。"

# 初始化客户端
client = OpenAI(
    api_key=os.environ.get('DEEPSEEK_API_KEY'),
    base_url="https://api.deepseek.com"
)

# 创建 output 文件夹（如果不存在）
output_dir = "output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# 读取 commits.json 文件
with open('commits.json', 'r', encoding='utf-8') as f:
    commits = json.load(f)

# 遍历每个 commit
for commit_id, commit_info in commits.items():
    print(f"正在处理 commit: {commit_id} ...")
    
    user_content = str(commit_info)
    
    try:
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_content},
            ],
            stream=False
        )
        msg = response.choices[0].message
        reasoning = getattr(msg, 'reasoning_content', '')
        final_answer = msg.content or ''
        
        # 构建输出内容：先 commit 原始内容，再思维链，最后结果
        output_parts = []
        output_parts.append("【Commit 原始内容】")
        output_parts.append(json.dumps(commit_info, indent=2, ensure_ascii=False))
        output_parts.append("")  # 空行分隔
        if reasoning:
            output_parts.append("【思维链】")
            output_parts.append(reasoning)
            output_parts.append("")
        output_parts.append("【最终结果】")
        output_parts.append(final_answer)
        
        output_text = "\n".join(output_parts)
        
    except Exception as e:
        output_text = f"【Commit 原始内容】\n{json.dumps(commit_info, indent=2, ensure_ascii=False)}\n\n【错误】\nAPI 调用失败: {e}"
    
    # 保存到 output/{commit_id}.txt
    output_file_path = os.path.join(output_dir, f"{commit_id}.txt")
    with open(output_file_path, "w", encoding="utf-8") as out_f:
        out_f.write(output_text)
    
    print(f"完成 commit {commit_id}，结果已保存到 {output_file_path}\n")

print("所有 commit 处理完毕。")