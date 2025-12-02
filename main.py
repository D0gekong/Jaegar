import asyncio
import os
import json
import sys
import yaml  # [新] 导入 YAML 库
from dotenv import load_dotenv
from openai import AsyncOpenAI

# 导入MCP相关的库
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

BANNER = r"""
      ██╗ █████╗ ███████╗ ██████╗  █████╗ ██████╗ 
      ██║██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔══██╗
      ██║███████║█████╗  ██║  ███╗███████║██████╔╝
 ██   ██║██╔══██║██╔══╝  ██║   ██║██╔══██║██╔══██╗
 ╚█████╔╝██║  ██║███████╗╚██████╔╝██║  ██║██║  ██║
  ╚════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
          [ Jaegar-Ultimate CLI Edition ]
"""

# 加载配置
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")
MODEL_NAME = os.getenv("MODEL_NAME")

if not API_KEY:
    print("❌ 错误：找不到 API_KEY，请检查 .env 文件")
    sys.exit(1)

client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)

# [新] 动态加载 workflows.yaml 配置
def load_system_prompt():
    yaml_path = os.path.join(os.path.dirname(__file__), "workflows.yaml")
    
    # 默认的保底 Prompt (防止配置文件丢失)
    default_prompt = """
    你是一个红队侦察专家 Jaegar。请根据用户需求灵活调度工具。
    SOP: 风控->情报->资产->指纹->端口->漏洞->报告。
    """
    
    if not os.path.exists(yaml_path):
        return default_prompt

    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # 拼接 Prompt
        role = config.get('role', {})
        prompt = f"{role.get('description', '')}\n风格：{role.get('style', '')}\n\n"
        
        prompt += "【工具箱能力】\n"
        for tool in config.get('tools', []):
            prompt += f"- {tool['name']}: {tool['desc']}\n"
            
        prompt += f"\n【SOP 标准作业流程】\n{config.get('workflow', '')}"
        
        print(f"✅ 已加载战术配置文件: workflows.yaml")
        return prompt
    except Exception as e:
        print(f"⚠️ 加载 YAML 配置失败: {e}，将使用默认配置。")
        return default_prompt

async def main():
    print(BANNER)
    print("正在初始化 Jaegar 核心系统...")

    try:
        with open('mcp.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
            server_config = config['servers'][0]
    except Exception as e:
        print(f"❌ 读取 mcp.json 失败: {e}")
        return

    current_env = os.environ.copy()
    if "FOFA_KEY" not in current_env and os.getenv("FOFA_KEY"):
        current_env["FOFA_KEY"] = os.getenv("FOFA_KEY")
    
    # 尝试传递 WEBHOOK_URL
    if os.getenv("WEBHOOK_URL"):
        current_env["WEBHOOK_URL"] = os.getenv("WEBHOOK_URL")

    server_params = StdioServerParameters(
        command=server_config['params']['command'],
        args=server_config['params']['args'],
        env={**current_env, **server_config['params']['env']}
    )

    print(f"正在连接工具箱: {server_config['name']} ...")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            tools_list = await session.list_tools()
            tool_names = [t.name for t in tools_list.tools]
            print(f"✅ 成功连接！已加载 {len(tool_names)} 个核武级工具：")
            print(f"   {', '.join(tool_names)}\n")
            
            # [修改] 这里不再硬编码，而是调用函数加载
            system_prompt = load_system_prompt()
            
            history = [{"role": "system", "content": system_prompt}]

            print("==============================================")
            print("我是 Jaegar 命令行终端。请输入指令：")
            print("例：对 testphp.vulnweb.com 进行全流程侦察")
            print("输入 'quit' 结束程序")
            print("==============================================\n")

            while True:
                try:
                    user_input = input("\n[Jaegar] > ").strip()
                except EOFError: break
                
                if user_input.lower() in ['quit', 'exit', '退出']:
                    break
                
                if not user_input: continue

                history.append({"role": "user", "content": user_input})
                print("\n(正在思考作战方案...)\n")

                available_tools = [{
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema
                    }
                } for tool in tools_list.tools]

                try:
                    response = await client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=history,
                        tools=available_tools
                    )
                except Exception as e:
                    print(f"❌ API请求出错: {e}")
                    continue

                message = response.choices[0].message
                
                if message.tool_calls:
                    history.append(message) 

                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        try:
                            func_args = json.loads(tool_call.function.arguments)
                        except:
                            func_args = {}
                        
                        print(f"--> [执行] {func_name} | 参数: {func_args}")

                        try:
                            # 设置 10 分钟超时，防止 Nuclei/Ffuf 卡死
                            result = await asyncio.wait_for(
                                session.call_tool(func_name, arguments=func_args),
                                timeout=600 
                            )
                            
                            tool_output = ""
                            if isinstance(result, CallToolResult):
                                for content in result.content:
                                    if content.type == 'text':
                                        tool_output += content.text
                            else:
                                tool_output = str(result)
                            
                            # 打印预览
                            preview = tool_output[:200].replace('\n', ' ') + "..." if len(tool_output) > 200 else tool_output
                            print(f"<-- [返回] {preview}\n")

                            history.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": tool_output
                            })

                        except asyncio.TimeoutError:
                            print(f"❌ 工具 {func_name} 执行超时！")
                            history.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": "Error: Tool execution timed out."
                            })
                        except Exception as e:
                            print(f"❌ 工具执行出错: {e}")
                            history.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": f"Error: {str(e)}"
                            })

                    final_response = await client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=history
                    )
                    ai_reply = final_response.choices[0].message.content
                else:
                    ai_reply = message.content

                print(f"\n[Jaegar]:\n{ai_reply}")
                history.append({"role": "assistant", "content": ai_reply})

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程序已安全退出。")