# -*- coding: utf-8 -*-
# Please install OpenAI SDK first: `pip3 install openai`
import os
from openai import OpenAI

report = {

}
prompt = ""

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
