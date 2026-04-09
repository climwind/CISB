import requests
import json
import os
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# === 配置 ===
GITHUB_REPO = "torvalds/linux"          # 格式: owner/repo
COMMIT_LIST_PATH = "commits.txt"
OUTPUT_PATH = "commits.json"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # 如果你有 token，可填写以避免速率限制

# === API Headers ===
HEADERS = {
    "Accept": "application/vnd.github.v3+json"
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

# === 函数定义 ===
def get_commit_info(commit_sha):
    url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{commit_sha}"
    response = requests.get(url, headers=HEADERS,verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"[ERROR] {commit_sha}: HTTP {response.status_code} - {response.text}")
        return None

def read_commit_ids(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]
    
# === 剔除不需要分析的元数据 ===
def strip_redundant_lines(commit_msg:str) -> str:
    return "\n".join(
        line for line in commit_msg.splitlines()
        if not re.match(r"^\s*(Signed-off-by|Reviewed-by|Tested-by|Acked-by|Cc|Co-authored-by|Debugged-by|Suggested-by|Reported-by):", line)
    ).strip()

def main():
    commit_ids = read_commit_ids(COMMIT_LIST_PATH)
    commits = {}
    with open(OUTPUT_PATH, "w") as out:
        for sha in commit_ids:
            print(f"[INFO] Fetching {sha}...")
            data = get_commit_info(sha)
            if not data:
                continue
            commit_date = data.get("commit", {}).get("committer", {}).get("date", "")
            commit_year = commit_date[:4] if commit_date else None
            entry = {
                "id": sha,
                # "author": data.get("commit", {}).get("author", {}),
                # "committer": data.get("commit", {}).get("committer", {}),
                "year": commit_year,
                "message": strip_redundant_lines(data.get("commit", {}).get("message", "")),
                # "files_changed": [f["filename"] for f in data.get("files", [])],
                "patches": {f["filename"]: f.get("patch", "") for f in data.get("files", [])}
            }
            commits[sha] = entry
        json.dump(commits, out, indent=4)
        out.write("\n")
    print(f"[DONE] Wrote to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
