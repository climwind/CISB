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

prompt = """你是一名代码安全分析专家，专注于“编译器引入的安全漏洞”（CISB）模式提取。  
请根据我提供的多个 CISB 案例（每个案例包含原始代码、补丁、安全意图分析），完成以下任务：

1. **提取一个高度抽象的 CISB 模式**，该模式应能覆盖所有案例中出现的共性特征。  
2. 以 **JSON 格式** 输出结果，确保结构清晰、字段完整，便于后续自动化检测工具（如 CodeQL）集成。  
3. JSON 应包含以下三个字段：  
   - `triggers`：数组类型，列出触发该模式的最关键必要条件（环境、程序上下文、编译器行为等），要求高度概括且简洁且用中文表示。  
   - `vulnerable_pattern`：字符串类型，**漏洞代码片段的高度抽象表示**，要求使用代码形式（伪代码或带占位符的真实代码片段），将具体变量名、函数名、常量等泛化为占位符（例如 `__FUNC__`、`__VAR__`、`__SIZE__`），突出易被优化的关键操作。  
   - `ql_constraints`：字符串类型，用 CodeQL 查询语言（QL）语法表达该模式检测中最应关注的约束条件，聚焦于数据流、控制流、编译器行为等。

**要求**：  
- 不要进行“具体情况具体分析”，而是给出一个适用于所有案例的统一抽象模式。  
- `vulnerable_pattern` 必须表现为代码块形式，而非文字描述。  
- 输出仅包含 JSON 内容，不要添加额外解释。"""

# 主程序
def main():
    input_filename = "patternInput.txt"
    output_filename = "patternOutput.txt"
    
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
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": input_content},
            ],
            stream=False,
            timeout=60  # 设置超时时间为60秒
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