import streamlit as st
import yaml
import sqlite3
import pandas as pd
import os
import asyncio
import json
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI
from pyvis.network import Network
import streamlit.components.v1 as components

# 引入所有工具
from servers.smart_fofa import (
    step1_check_risk, step2_google_intel_rag, step3_fofa_search,
    step4_tide_fingerprint, step5_port_scan, step6_js_finder,
    step7_trace_real_ip, step8_check_special_routes, step9_generate_report,
    step10_nuclei_scan, step11_hydra_crack, step12_dirsearch_scan, step13_sqlmap_scan,step14_python_interpreter
)

st.set_page_config(page_title="Jaegar AI 终端", layout="wide", page_icon="🦅")
load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")
MODEL_NAME = os.getenv("MODEL_NAME")
DB_PATH = os.path.join(os.path.dirname(__file__), "assets.db")

def load_workflow_config():
    yaml_path = os.path.join(os.path.dirname(__file__), "workflows.yaml")
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        # 动态拼接 System Prompt
        # 1. 角色定义
        prompt = f"{config['role']['description']} 你的风格是：{config['role']['style']}\n\n"
        
        # 2. 工具能力
        prompt += "【工具箱能力说明】\n"
        for t in config['tools']:
            prompt += f"- {t['name']}: {t['desc']}\n"
            
        # 3. SOP 流程
        prompt += f"\n【SOP 标准作业流程】\n{config['workflow']}"
        
        return prompt, config['role']['name']
    except Exception as e:
        st.error(f"加载 workflows.yaml 失败: {e}")
        # 降级方案
        return "你是一个红队专家...", "Jaegar"

if "client" not in st.session_state:
    st.session_state.client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

if "messages" not in st.session_state:
    system_prompt, bot_name = load_workflow_config()
    
    st.session_state.messages = [
        {"role": "system", "content": system_prompt},
        {"role": "assistant", "content": f"🦅 {bot_name} (SOP配置版) 已就绪。请下达指令。"}
    ]

TOOLS_SCHEMA = [
    {"type": "function", "function": {"name": "step1_check_risk", "description": "风控", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "step2_google_intel_rag", "description": "情报", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}, "intent": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "step3_fofa_search", "description": "FOFA", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "step4_tide_fingerprint", "description": "指纹", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step5_port_scan", "description": "端口扫描。默认使用快速模式(Socket)，若需要服务版本信息请使用深度模式(Nmap)", "parameters": {"type": "object", "properties": {"target_ip": {"type": "string"},"mode": {"type": "string", "enum": ["fast", "deep"], "description": "deep: 调用Nmap进行服务版本识别; fast: 仅检测端口是否开放"}}, "required": ["target_ip"]}}},
    {"type": "function", "function": {"name": "step6_js_finder", "description": "JS挖掘", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step7_trace_real_ip", "description": "溯源", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step8_check_special_routes", "description": "路由", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step9_generate_report", "description": "报告", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "step10_nuclei_scan", "description": "Nuclei", "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "tags": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step11_hydra_crack", "description": "Hydra", "parameters": {"type": "object", "properties": {"target_ip": {"type": "string"}, "service": {"type": "string"}, "port": {"type": "integer"}}, "required": ["target_ip", "service"]}}},
    {"type": "function", "function": {"name": "step12_dirsearch_scan", "description": "Dirsearch", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step13_sqlmap_scan", "description": "SQLMap", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "step14_python_interpreter", "description": "代码解释器", "parameters": {"type": "object", "properties": {"code": {"type": "string"}, "data_context": {"type": "string"}}, "required": ["code"]}}}
]

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
    "step13_sqlmap_scan": step13_sqlmap_scan,
    "step14_python_interpreter": step14_python_interpreter
}

def load_data():
    if not os.path.exists(DB_PATH): return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM assets ORDER BY id DESC", conn)
        conn.close()
        return df
    except: return pd.DataFrame()

def draw_topology(df):
    if df.empty: return None
    net = Network(height='300px', width='100%', bgcolor='#0E1117', font_color='white')
    net.force_atlas_2based()
    color_map = {"Subdomain": "#00ff00", "IP": "#ff0000", "Port": "#ffff00", "Fingerprint": "#00ffff", "Vuln": "#ff00ff", "Dir": "#0000ff", "Crack": "#ff0000"}
    for _, row in df.head(50).iterrows():
        try:
            target = str(row['target'])
            atype = str(row['type'])
            info = str(row['info'])
            net.add_node(target, label=target[:15], title=f"[{atype}]\n{info}", color=color_map.get(atype, "#cccccc"), size=15)
        except: pass
    try:
        path = os.path.join(os.path.dirname(__file__), "topology.html")
        net.save_graph(path)
        return path
    except: return None

with st.sidebar:
    st.header("📊Jaegar 实时态势")
    if st.button("🔄 刷新"): st.rerun()
    if st.button("🧹 清除缓存"): 
        st.session_state.messages = []
        st.rerun()
    df = load_data()
    if not df.empty:
        c1, c2 = st.columns(2)
        c1.metric("总资产", len(df))
        c2.metric("漏洞/风险", len(df[df['type'].str.contains('Vuln|Crack|Dir', na=False)]))
        html_path = draw_topology(df)
        if html_path:
            with open(html_path, 'r', encoding='utf-8') as f: components.html(f.read(), height=320)
        st.dataframe(df[['target', 'type', 'info']].head(10), hide_index=True, width=300)

st.title("🛡️ Jaegar 交互式侦察终端")

for msg in st.session_state.messages:
    if isinstance(msg, dict):
        role = msg.get("role")
        content = msg.get("content")
    else:
        role = getattr(msg, "role", None)
        content = getattr(msg, "content", None)
    if role != "system" and content:
        with st.chat_message(role): st.markdown(content)

if prompt := st.chat_input("请输入指令..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"): st.markdown(prompt)

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        response = st.session_state.client.chat.completions.create(
            model=MODEL_NAME, messages=st.session_state.messages, tools=TOOLS_SCHEMA
        )
        msg = response.choices[0].message
        
        if msg.tool_calls:
            # 存入字典格式
            st.session_state.messages.append({"role": msg.role, "content": msg.content, "tool_calls": msg.tool_calls})
            for tool_call in msg.tool_calls:
                func_name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                with st.status(f"执行: {func_name} ...", expanded=True) as status:
                    st.write(f"参数: {args}")
                    if func_name in TOOL_MAP:
                        # 异步运行工具
                        result = asyncio.run(TOOL_MAP[func_name](**args))
                        st.code(str(result)[:500], language="text")
                        
                        # 回传工具结果
                        st.session_state.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": str(result)
                        })
                        status.update(label=f"{func_name} 完成!", state="complete", expanded=False)
                    else:
                        # 【关键修复】即使找不到工具，也要回传一个错误消息，防止 400
                        err_msg = f"Error: Tool {func_name} not implemented locally."
                        st.error(err_msg)
                        st.session_state.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": err_msg
                        })
            
            # 第二次调用获取回答
            final_response = st.session_state.client.chat.completions.create(model=MODEL_NAME, messages=st.session_state.messages)
            ai_reply = final_response.choices[0].message.content
            message_placeholder.markdown(ai_reply)
            st.session_state.messages.append({"role": "assistant", "content": ai_reply})
            st.rerun()
        else:
            ai_reply = msg.content
            message_placeholder.markdown(ai_reply)
            st.session_state.messages.append({"role": "assistant", "content": ai_reply})