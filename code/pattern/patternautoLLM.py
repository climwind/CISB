# -*- coding: utf-8 -*-
# Please install OpenAI SDK first: `pip3 install openai`
import os
from openai import OpenAI

# 读取输入文件
def read_input_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"错误：找不到文件 {filename}")
        return None

# 写入输出文件
def write_output_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)

prompt = """你是一个软件安全专家，精通静态分析相关的技术。请根据我提供的漏洞复现代码，提炼“编译器引入型漏洞模式”，并服务于后续 CodeQL 模板生成。

核心要求（非常重要）：
1) 只关注“直接导致漏洞语义变化”的根因代码行。
2) 忽略与根因无关的样板代码和上下文（如 for/while 循环框架、变量初始化、日志、普通数据搬运）。
3) 只有当循环本身就是漏洞触发点时，才允许在模式中出现循环。
4) 输出要最小化：用最少代码语义表达漏洞，不要复述大段上下文。
5) 对“空值判断”做语义归一化：把不同写法统一为同一语义，不因语法形式不同而遗漏模式。

空值判断等价归一化规则（必须遵守）：
- `EXPR == NULL`、`EXPR == 0`、`!EXPR` 归一为 `isNull(EXPR)`。
- `EXPR != NULL`、`EXPR != 0`、`!!EXPR`、`if(EXPR)` 归一为 `isNonNull(EXPR)`。
- 若漏洞根因是“某个空值判断被优化为恒真/恒假或被错误折叠”，请输出该归一化后的语义，而不是只绑定某一种写法。

请仅输出 JSON，包含以下字段：
- triggers: 数组。仅保留必要触发条件（如编译器/优化级别/UB前提）。每项一句短语。
- vulnerable_pattern: 字符串。仅描述根因语句的抽象模式，禁止引入非根因控制流；需要覆盖等价空值判断写法（如 `==NULL` 与 `!EXPR`）。
- ql_constraints: 字符串。给出最关键的 CodeQL 约束（QL 风格），聚焦根因表达式及其被优化后的语义偏差；应使用“等价写法并集约束”（OR 形式）避免漏掉 `!EXPR` 这类写法。

抽取步骤（在内部执行，不要输出步骤）：
A. 先定位“哪一条表达式/条件在优化后语义被改变”。
B. 仅保留该表达式及其必要数据依赖。
C. 删除与根因无关的循环、拷贝、分配、打印等上下文。
D. 将根因条件归一化后，再生成可覆盖等价语法的模式与约束。

格式约束：
- 输出必须是合法 JSON 对象。
- 不要输出 Markdown、解释文字、代码块标记。
- 信息精简但完整。"""

# 主程序
def main():
    input_filename = "/home/test/my-awesome-project/CISB/code/pattern/patternInput.txt"
    output_filename = "/home/test/my-awesome-project/CISB/code/pattern/patternOutput.txt"
    
    # 读取输入文件
    print(f"正在读取输入文件: {input_filename}")
    input_content = read_input_file(input_filename)
    
    if input_content is None:
        return
    
    print(f"成功读取 {len(input_content)} 个字符")
    
    # 初始化 OpenAI 客户端
    api_key = os.environ.get('DEEPSEEK_API_KEY')
    if not api_key:
        print("错误：未设置 DEEPSEEK_API_KEY 环境变量")
        return
    
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com"
    )
    
    # 调用 API
    print("正在调用 API 进行分析...")
    try:
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": input_content},
            ],
            stream=False,
            timeout=180  # 设置超时时间为180秒
        )
        
        # 获取结果
        result = response.choices[0].message.content
        
        # 写入输出文件
        print(f"正在写入输出文件: {output_filename}")
        write_output_file(output_filename, result)
        
        print("分析完成！结果已保存到 patternOutput.txt")
        print("\n=== 分析结果预览 ===")
        print(result[:500] + "..." if len(result) > 500 else result)
        
    except Exception as e:
        print(f"调用 API 时发生错误: {e}")

if __name__ == "__main__":
    main()