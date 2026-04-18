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

prompt = """你是一个软件安全专家，精通静态分析相关的技术。现在请你根据我筛选出的漏洞代码提取总结出漏洞模式。要求既包含漏洞的完整语义和触发条件，同时便于后续的 QL 模板代码生成参考。
请从下面的 C 语言漏洞复现代码中提取编译器引入型漏洞模式，并以JSON格式输出结果。输出应包括以下字段：

- triggers: 包含最关键必要的触发条件的数组，例如环境信息，程序上下文，编译优化选项等。需要高度概括且简洁。
- vulnerable\_pattern: 漏洞代码片段的高度抽象表示。
- ql\_constraints: 作为CodeQL检测的模板中最应关注的约束条件，用 QL 语法表示。
  代码示例：
  c
  int main(int argc, char\* argv\[]) {
  //  ./a.out 30 Getit,pleasedonottellanyoneelse
  int n;
  char \*password;
- n = atoi(argv\[1]);
  password = malloc(n);
  for(int i = 0; i < 30; i++){
  password\[i] = argv\[2]\[i];
  }
  memset(password, '\x00', n); // memset will be eliminated with option -O1/O2/O3
  return 0;
  }
  请确保输出仅为JSON格式，且每一字段的信息要尽可能精简但完整。"""

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