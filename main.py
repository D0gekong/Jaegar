import asyncio
import os
import json
import sys
from dotenv import load_dotenv
from openai import AsyncOpenAI

# [关键] 直接导入工具函数，像 Web 端一样
from servers.smart_fofa import (
    step1_check_risk, step2_google_intel_rag, step3_fofa_search,
    step4_tide_fingerprint, step5_port_scan, step6_js_finder,
    step7_trace_real_ip, step8_check_special_routes, step9_generate_report,
    step10_nuclei_scan, step11_hydra_crack, step12_dirsearch_scan, step13_sqlmap_scan
)

BANNER = r"""
      ██╗ █████╗ ███████╗ ██████╗  █████╗ ██████╗ 
      ██║██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔══██╗
      ██║███████║█████╗  ██║  ███╗███████║██████╔╝
 ██   ██║██╔══██║██╔══╝  ██║   ██║██╔══██║██╔══██╗
 ╚█████╔╝██║  ██║███████╗╚██████╔╝██║  ██║██║  ██║
  ╚════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
          [ Jaegar-Ultimate Direct CLI ]
"""

# 配置加载
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")
MODEL_NAME = os.getenv("MODEL_NAME")

if not API_KEY:
    print("❌ 错误：找不到 API_KEY")
    sys.exit(1)

client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)

# 工具映射表 (与 Web 端一致)
TOOL_MAP = {
    "step1_check_risk": step1_check_risk,
    "step2_google_intel_rag": step2_google_intel_rag,
    "step3_fofa_search": step3_fofa_search,
    "step4_tide_fingerprint": step4_tide_fingerprint,
    "step5_port_scan": step5_port_scan,
    "step6_js_finder": step6_js_finder,
    "step7_trace_real_ip": step7_trace_real_ip,
    "step8_check_special_routes": step8_check_special_routes,
    "step9_generate_report": step9_generate_report,
    "step10_nuclei_scan": step10_nuclei_scan,
    "step11_hydra_crack": step11_hydra_crack,
    "step12_dirsearch_scan": step12_dirsearch_scan,
    "step13_sqlmap_scan": step13_sqlmap_scan
}

# 工具定义 (Schema)
TOOLS_SCHEMA = [
    {"type": "function", "function": {"name": "step1_check_risk", "description": "检测风险", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "step2_google_intel_rag", "description": "Google搜索", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}, "intent": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "step3_fofa_search", "description": "FOFA搜索", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "step4_tide_fingerprint", "description": "指纹识别", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step5_port_scan", "description": "端口扫描", "parameters": {"type": "object", "properties": {"target_ip": {"type": "string"}}, "required": ["target_ip"]}}},
    {"type": "function", "function": {"name": "step6_js_finder", "description": "JS挖掘", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step7_trace_real_ip", "description": "CDN溯源", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step8_check_special_routes", "description": "路由探测", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step9_generate_report", "description": "生成报告", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "step10_nuclei_scan", "description": "Nuclei漏扫", "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "tags": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step11_hydra_crack", "description": "Hydra爆破", "parameters": {"type": "object", "properties": {"target_ip": {"type": "string"}, "service": {"type": "string"}, "port": {"type": "integer"}}, "required": ["target_ip", "service"]}}},
    {"type": "function", "function": {"name": "step12_dirsearch_scan", "description": "Dirsearch", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step13_sqlmap_scan", "description": "SQLMap", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}}
]

async def main():
    print(BANNER)
    print(f"🚀 直连模式已启动 | 加载工具数: {len(TOOL_MAP)}")
    
    system_prompt = """
    你是一个红队侦察专家 Jaegar。请根据用户需求灵活调用以下工具：
    1. 风控检测 (step1)
    2. 情报搜集 (step2)
    3. 资产搜集 (step3)
    4. 指纹识别 (step4)
    5. 端口扫描 (step5)
    6. JS挖掘 (step6)
    7. 资产溯源 (step7)
    8. 路由探测 (step8)
    9. 生成报告 (step9)
    10. 漏洞扫描 (step10_nuclei_scan)
    11. 弱口令爆破 (step11_hydra_crack)
    12. 目录扫描 (step12_dirsearch_scan)
    13. SQL注入 (step13_sqlmap_scan)
    
    SOP: 发现指纹->Nuclei; 发现端口->Hydra; 发现参数->SQLMap; 结束->报告。
    """
    
    history = [{"role": "system", "content": system_prompt}]

    print("\n[Jaegar] 终端就绪。请输入指令 (quit退出)：")
    
    while True:
        try:
            user_input = input("\n[User] > ").strip()
        except EOFError: break
        if user_input.lower() in ['quit', 'exit']: break
        if not user_input: continue

        history.append({"role": "user", "content": user_input})
        print("(思考中...)")

        try:
            response = await client.chat.completions.create(
                model=MODEL_NAME, messages=history, tools=TOOLS_SCHEMA
            )
            msg = response.choices[0].message
            
            if msg.tool_calls:
                history.append(msg)
                for tool_call in msg.tool_calls:
                    func_name = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    
                    print(f"--> [执行] {func_name} {args} ...")
                    
                    if func_name in TOOL_MAP:
                        # 直接本地调用，不走 MCP 协议
                        try:
                            result = await TOOL_MAP[func_name](**args)
                            # 截断过长输出，防止刷屏
                            print(f"<-- [结果] {str(result)[:200]}...")
                            history.append({
                                "role": "tool", 
                                "tool_call_id": tool_call.id, 
                                "content": str(result)
                            })
                        except Exception as e:
                            print(f"❌ 执行错误: {e}")
                            history.append({
                                "role": "tool", 
                                "tool_call_id": tool_call.id, 
                                "content": f"Error: {e}"
                            })
                    else:
                        print(f"❌ 未找到工具: {func_name}")

                # 获取总结
                final_res = await client.chat.completions.create(model=MODEL_NAME, messages=history)
                ai_reply = final_res.choices[0].message.content
            else:
                ai_reply = msg.content

            print(f"\n[Jaegar]:\n{ai_reply}")
            history.append({"role": "assistant", "content": ai_reply})

        except Exception as e:
            print(f"❌ API 错误: {e}")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\nBye.")