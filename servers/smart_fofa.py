import os
import json
import base64
import asyncio
import httpx
import requests
import dns.resolver
import ipaddress
import sqlite3
import random
import string
import chromadb
import re
import hashlib
import mmh3
import codecs
import ssl
import socket
import sys
from urllib.parse import urljoin
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from duckduckgo_search import DDGS
import subprocess
from dotenv import load_dotenv

# 初始化工具
mcp = FastMCP("Jaegar-Ultimate-Final")

# --- 1. 基础配置 ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

FOFA_KEY = os.getenv("FOFA_KEY", "")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

KB_DIR = os.path.join(BASE_DIR, "knowledge_base_docs")
FINGER_DIR = os.path.join(BASE_DIR, "fingerprints") 
DB_PATH = os.path.join(BASE_DIR, "assets.db")
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db")

# 路径配置
NUCLEI_PATH = os.path.join(BASE_DIR, "tools", "nuclei.exe")
if not os.path.exists(NUCLEI_PATH): NUCLEI_PATH = "nuclei"

HYDRA_DIR = os.path.join(BASE_DIR, "tools", "hydra")
HYDRA_PATH = os.path.join(HYDRA_DIR, "hydra.exe")
if not os.path.exists(HYDRA_PATH): HYDRA_PATH = "hydra"

# [配置] Dirsearch 路径
DIRSEARCH_DIR = os.path.join(BASE_DIR, "tools", "dirsearch")
DIRSEARCH_SCRIPT = os.path.join(DIRSEARCH_DIR, "dirsearch.py")

SQLMAP_DIR = os.path.join(BASE_DIR, "tools", "sqlmap")
SQLMAP_SCRIPT = os.path.join(SQLMAP_DIR, "sqlmap.py")
if not os.path.exists(SQLMAP_SCRIPT): SQLMAP_DIR = "SQLMAP"

# [配置] Nmap 路径
NMAP_DIR = os.path.join(BASE_DIR, "tools", "nmap")
NMAP_EXE = os.path.join(NMAP_DIR, "nmap.exe")
# 如果本地 tools 里没有，尝试调系统环境变量
if not os.path.exists(NMAP_EXE): NMAP_EXE = "nmap"

CDN_KEYWORDS = ['cloudflare', 'akamai', 'cdn', 'aliyun', 'qiniu', 'amazon', 'azure', 'incapsula']
TOP_PORTS = [21, 22, 23, 80, 81, 443, 3306, 3389, 5432, 6379, 7001, 8080, 8888, 9200, 27017]
PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 
    7001: "WebLogic", 8080: "Tomcat/Proxy", 27017: "MongoDB"
}
SPECIAL_ROUTES = {
    "/prod-api/": ["RuoYi-Vue Backend", [200, 401, 403]],
    "/dev-api/": ["RuoYi-Vue Dev", [200, 401, 403]],
    "/ispirit/": ["通达OA", [200, 302]],
    "/seeyon/": ["致远OA", [200, 302]],
    "/actuator/env": ["Spring Boot Actuator", [200]],
    "/swagger-ui.html": ["Swagger UI", [200]]
}

# --- 辅助函数 ---
def log(msg):
    try: sys.stderr.write(f"[Log] {msg}\n"); sys.stderr.flush()
    except: pass

async def push_to_webhook(title, content):
    if not WEBHOOK_URL: return
    data = {"msgtype": "text", "text": {"content": f"[Jaegar]\n【{title}】\n{content}\nTime: {datetime.now().strftime('%H:%M:%S')}"}}
    try:
        async with httpx.AsyncClient() as client:
            await client.post(WEBHOOK_URL, json=data, timeout=5)
    except: pass

# --- 2. TideFinger ---
class TideEngine:
    def __init__(self):
        self.passive_rules, self.active_rules = [], []
        self._load_db()
    def _load_db(self):
        db = os.path.join(FINGER_DIR, "cms_finger.db")
        if not os.path.exists(db): return
        try:
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            try:
                cur.execute("SELECT name, keys FROM tide")
                for r in cur.fetchall(): self.passive_rules.append({"name": r[0], "key": r[1]})
            except: pass
            try:
                cur.execute("SELECT cms_name, path, match_pattern, options FROM cms ORDER BY hit DESC")
                for r in cur.fetchall(): self.active_rules.append({"name": r[0], "path": r[1], "pattern": r[2], "option": r[3]})
            except: pass
            conn.close()
        except: pass
    def check_rule(self, key, header, body, title):
        try:
            if 'title="' in key: return re.findall(r'title="(.*)"', key)[0].lower() in title.lower()
            elif 'body="' in key: return re.findall(r'body="(.*)"', key)[0] in body
            else: return re.findall(r'header="(.*)"', key)[0] in header
        except: return False
    def match_passive(self, header, body, title):
        detected = set()
        for r in self.passive_rules:
            try:
                if '||' in r['key']:
                    for k in r['key'].split('||'): 
                        if self.check_rule(k, header, body, title): detected.add(r['name']); break
                elif '&&' in r['key']:
                    if all(self.check_rule(k, header, body, title) for k in r['key'].split('&&')): detected.add(r['name'])
                else:
                    if self.check_rule(r['key'], header, body, title): detected.add(r['name'])
            except: pass
        return list(detected)
    @staticmethod
    def get_md5(content): return hashlib.md5(content).hexdigest()

tide_engine = TideEngine()

# --- 3. RAG ---
class RAGEngine:
    def __init__(self):
        import logging; logging.getLogger('chromadb').setLevel(logging.ERROR)
        self.client = chromadb.PersistentClient(path=CHROMA_PATH)
        self.collection = self.client.get_or_create_collection(name="security_knowledge")
        self._load_all_knowledge()
    def _load_all_knowledge(self):
        if self.collection.count() > 0: return
        log("Init RAG...")
        docs, ids, metas = [], [], []; doc_id = 0
        if os.path.exists(KB_DIR):
            for f in os.listdir(KB_DIR):
                if f.endswith(".md"):
                    with open(os.path.join(KB_DIR, f), 'r', encoding='utf-8') as file:
                        for line in file:
                            if len(line.strip())>5 and not line.startswith("#"):
                                docs.append(line.strip()); ids.append(f"doc_{doc_id}"); metas.append({"source": f, "type": "syntax"}); doc_id+=1
        for idx, r in enumerate(tide_engine.passive_rules[:1500]):
            docs.append(f"CMS Fingerprint {r['name']}: {r['key']}"); ids.append(f"fp_{idx}"); metas.append({"source": "tide", "type": "fingerprint", "cms": r['name']})
        if docs: self.collection.add(documents=docs, ids=ids, metadatas=metas)
    def search_with_meta(self, query, n=3):
        try:
            res = self.collection.query(query_texts=[query], n_results=n)
            return list(zip(res['documents'][0], res['metadatas'][0])) if res['documents'] else []
        except: return []

rag = RAGEngine()

# --- 4. DB ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, type TEXT, info TEXT, source TEXT, discovery_date TEXT)''')
    conn.close()

def save_asset_to_db(target, type, info, source):
    init_db(); conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM assets WHERE target=? AND type=?", (target, type))
        if not cur.fetchone():
            cur.execute('INSERT INTO assets (target, type, info, source, discovery_date) VALUES (?, ?, ?, ?, ?)', 
                       (target, type, info, source, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
    except: 
        pass; 
    finally: 
        conn.close()

async def check_url_alive(client, target):
    urls = [f"http://{target}", f"https://{target}"] if not target.startswith("http") else [target]
    for u in urls:
        try:
            r = await client.get(u, timeout=5.0, follow_redirects=True)
            if r.status_code < 500: return u, r.status_code, str(r.headers)
        except: pass
    return None, None, None

async def check_port_open(ip, port):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.8)
        w.close(); await w.wait_closed(); return port, True
    except: return port, False

# --- 5. MCP Tools ---

@mcp.tool()
async def step1_check_risk(domain: str):
    """[1.风控]"""
    report = []
    try: dns.resolver.resolve(''.join(random.choices(string.ascii_lowercase, k=8))+"."+domain, 'A'); return "【高风险】泛解析域名"
    except: report.append("Pass: 无泛解析")
    try:
        for r in dns.resolver.resolve(domain, 'CNAME'):
            if any(k in str(r.target).lower() for k in CDN_KEYWORDS): return f"【高风险】CDN: {r.target}"
    except: report.append("Pass: 无CDN")
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        try:
            r = await client.get(f"http://{domain}")
            wafs = ['cloudflare', 'aliyun', 'safedog', 'nginx', 'bigip']
            found = [w for w in wafs if w in str(r.headers).lower()]
            if found: 
                save_asset_to_db(domain, "Risk", f"WAF:{found}", "WAFCheck")
                await push_to_webhook("发现WAF", f"{domain} {found}")
                return f"【警告】WAF: {found}"
        except: pass
    return "【风控通过】\n" + "\n".join(report)

@mcp.tool()
async def step2_google_intel_rag(domain: str, intent: str = "sensitive file"):
    """[2.情报]"""
    dorks = [d[0] for d in rag.search_with_meta(intent, n=5)]
    if not dorks: return "无匹配语法"
    ddgs = DDGS(); found = 0; res_str = ""
    for tpl in dorks:
        clean = tpl.split(":")[-1].strip() if ":" in tpl else tpl
        if "filetype" not in clean and "inurl" not in clean: clean = tpl
        try:
            for res in list(ddgs.text(f"site:{domain} {clean}", max_results=2)):
                found += 1; info = f"Title:{res['title']} Link:{res['href']}"
                save_asset_to_db(res['href'], "Intel", info, "Google-RAG"); res_str += f"- {info}\n"
        except: pass
    return f"【情报】发现 {found} 条线索。\n{res_str}"

@mcp.tool()
async def step3_fofa_search(query: str, size: int = 20):
    """[3.资产]"""
    if not FOFA_KEY: return "无 FOFA_KEY"
    try:
        data = requests.get(f"https://fofa.info/api/v1/search/all?email=&key={FOFA_KEY}&qbase64={base64.b64encode(query.encode()).decode()}&size={size}&fields=host,ip", timeout=15, verify=False).json()
        items = data.get("results", [])
    except: return "FOFA失败"
    alive = 0
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        tasks = [check_url_alive(client, i[0]) for i in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for idx, res in enumerate(results):
            if isinstance(res, Exception) or res is None: continue
            u, c, h = res
            if u: 
                alive += 1; ip_val = items[idx][1] if len(items[idx])>1 else "N/A"
                save_asset_to_db(u, "Asset", f"IP:{ip_val} Code:{c}", "FOFA")
    return f"【FOFA】存活 {alive}/{len(items)}。"

@mcp.tool()
async def step4_tide_fingerprint(url: str, active_scan: bool = False):
    """[4.指纹]"""
    if not url.startswith("http"): url = f"http://{url}"
    detected = []
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        try:
            resp = await client.get(url)
            title = resp.text.split("<title>")[1].split("</title>")[0].strip() if "<title>" in resp.text else ""
            detected.extend([f"{n} (Rule)" for n in tide_engine.match_passive(str(resp.headers), resp.text, title)])
        except: return "访问失败"
        if active_scan or not detected:
            for rule in tide_engine.active_rules[:50]:
                try:
                    r = await client.get(url.rstrip('/')+rule['path'])
                    match = (rule['option']=='md5' and tide_engine.get_md5(r.content)==rule['pattern']) or (rule['option']=='keyword' and rule['pattern'] in r.text)
                    if match: detected.append(f"{rule['name']} ({rule['path']})"); break
                except: pass
        if not detected:
            rag_res = rag.search_with_meta(f"Title:{title} Header:{str(resp.headers)[:100]}", n=2)
            detected.extend([f"{m['cms']} (RAG)" for d, m in rag_res if m.get('type')=='fingerprint'])
    info = ", ".join(list(set(detected))) if detected else "未识别"
    save_asset_to_db(url, "Fingerprint", info, "TideFinger")
    return f"【指纹】{title} | {info}"

@mcp.tool()
async def step5_port_scan(target_ip: str, mode: str = "fast"):
    """
    [5.端口] 端口扫描 (支持 Socket 快速扫描 和 Nmap 深度扫描)。
    Args:
        target_ip: 目标 IP 或 域名
        mode: "fast" (Python原生,快) 或 "deep" (Nmap,准,含服务版本)
    """
    # 清洗目标，去掉 http://
    target = target_ip.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    
    # 1. 尝试解析 IP (如果是域名)
    try:
        if not target.replace('.', '').isdigit():
            target = dns.resolver.resolve(target, 'A')[0].to_text()
    except:
        return f"❌ 无法解析目标: {target_ip}"

    # === 模式 A: Nmap 深度扫描 (推荐) ===
    if mode == "deep":
        log(f"启动 Nmap 深度扫描: {target} (Exe: {NMAP_EXE})")
        
        # 构造命令
        # -sS: SYN半开扫描 (速度快)
        # -p: 指定常用端口 (为了速度，不建议扫全端口)
        # -sV: 探测服务版本 (核心价值)
        # --open: 只显示开放端口
        # -T4: 加速
        # -n: 不做 DNS 反解
        ports = "21,22,23,25,53,80,81,88,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,7001,8000,8080,8081,8443,8888,9200,27017"
        cmd = [
            NMAP_EXE, 
            "-sS", "-sV", "-Pn", "-n", "-T4", "--open",
            "-p", ports,
            target
        ]
        
        def run_nmap():
            try:
                # 必须设置 cwd 到 nmap 目录，因为它依赖很多 NSE 脚本和配置文件
                cwd_path = NMAP_DIR if os.path.exists(NMAP_DIR) else None
                
                res = subprocess.run(
                    cmd,
                    cwd=cwd_path, # [关键] 设置工作目录
                    capture_output=True,
                    text=True,
                    encoding='utf-8', # Nmap 在 Windows 有时编码会有问题，若乱码可试 'mbcs'
                    errors='ignore',
                    timeout=300
                )
                return res.stdout
            except Exception as e:
                return str(e)

        try:
            output = await asyncio.to_thread(run_nmap)
            
            # 解析 Nmap 输出
            open_ports = []
            for line in output.splitlines():
                # 典型输出: 80/tcp open http Apache httpd 2.4.49
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_info = parts[0] # 80/tcp
                    service_info = " ".join(parts[2:]) # http Apache...
                    
                    msg = f"{port_info} -> {service_info}"
                    open_ports.append(msg)
                    
                    # 入库
                    save_asset_to_db(target, "Port", msg, "Nmap")

            if open_ports:
                return f"【Nmap 深度扫描报告】\n发现 {len(open_ports)} 个开放端口：\n" + "\n".join(open_ports)
            elif "is up" in output:
                return "【Nmap】目标存活，但未发现指定的高危端口开放。"
            else:
                return f"【Nmap】扫描失败或目标不可达。\n原始输出片段: {output[:200]}"

        except Exception as e:
            return f"Nmap 执行出错: {e} (请检查 tools/nmap/nmap.exe 是否存在)"

    # === 模式 B: Socket 快速扫描 (原生兜底) ===
    else:
        log(f"启动 Socket 快速扫描: {target}")
        tasks = [check_port_open(target, p) for p in TOP_PORTS]
        res = await asyncio.gather(*tasks)
        
        open_services = []
        for port, is_open in res:
            if is_open:
                s_name = PORT_SERVICE_MAP.get(port, "Unknown")
                info = f"{port}/tcp ({s_name})"
                open_services.append(info)
                save_asset_to_db(target, "Port", info, "SocketScan")
                
        if open_services:
            return f"【Socket 快速扫描】\n" + "\n".join(open_services)
        else:
            return "【Socket】未发现高危端口开放。"

@mcp.tool()
async def step6_js_finder(url: str):
    """[6.JS挖掘]"""
    if not url.startswith("http"): url = f"http://{url}"
    found = []
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        try:
            r = await client.get(url); links = set(re.findall(r'src=["\'](.*?\.js)["\']', r.text))
            for link in list(links)[:10]:
                try:
                    js_r = await client.get(urljoin(url, link), timeout=3)
                    # 简化的正则示例，完整版见之前回答
                    if "AKIA" in js_r.text: found.append(f"AWS Key in {link}")
                except: pass
        except: pass
    return f"【JS挖掘】\n"+"\n".join(found) if found else "JS无敏感信息"

@mcp.tool()
async def step7_trace_real_ip(url: str):
    """[7.溯源]"""
    if not url.startswith("http"): url = f"http://{url}"
    domain = url.split("//")[-1].split(":")[0].split("/")[0]
    results = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            r = await client.get(url.rstrip('/')+"/favicon.ico")
            if r.status_code==200:
                h = mmh3.hash(codecs.encode(r.content, "base64"))
                results.append(f"IconHash: {h}"); save_asset_to_db(url, "Trace", f"Hash:{h}", "Icon")
    except: pass
    return f"【溯源】\n"+"\n".join(results)

@mcp.tool()
async def step8_check_special_routes(url: str):
    """[8.路由]"""
    if not url.startswith("http"): url = f"http://{url}"
    found = []
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for route, (name, codes) in SPECIAL_ROUTES.items():
            try:
                r = await client.get(url.rstrip('/')+route)
                if (codes and r.status_code in codes) or (not codes and r.status_code!=404):
                    if r.status_code==403 and "waf" in r.text.lower(): continue
                    found.append(f"{name}: {route} ({r.status_code})")
                    save_asset_to_db(url, "Route", f"{name}", "RouteScan")
            except: pass
    return f"【路由】\n"+"\n".join(found) if found else "无特殊路由"

@mcp.tool()
async def step9_generate_report():
    """[9.报告]"""
    init_db(); conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM assets ORDER BY id DESC").fetchall(); conn.close()
    if not rows: return "无数据"
    md = f"# FlySec Report {datetime.now()}\n| Target | Type | Info | Source |\n|---|---|---|---|\n"
    for r in rows: md += f"| {str(r[1]).replace('|','/')} | {r[2]} | {str(r[3]).replace('|','/').replace(chr(10),';')} | {r[4]} |\n"
    fname = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    try:
        with open(os.path.join(BASE_DIR, fname), "w", encoding="utf-8") as f: f.write(md)
        await push_to_webhook("任务完成", f"报告: {fname}")
        return f"✅ 报告已保存: {fname}"
    except Exception as e: return f"保存失败: {e}"

@mcp.tool()
async def step10_nuclei_scan(url: str, tags: str = ""):
    """
    [10.漏扫] Nuclei (性能优化版)
    """
    if not url.startswith("http"): url = f"http://{url}"
    
    nuclei_path = os.path.abspath(os.path.join(BASE_DIR, "tools", "nuclei.exe"))
    if not os.path.exists(nuclei_path): return f"❌ 错误：tools/nuclei.exe 不存在"
    
    log(f"Nuclei启动: {url} (Tags: {tags or 'Default'})")
    
    # [关键优化]
    # -timeout 5: 单个请求超时5秒 (防止卡死)
    # -retries 1: 失败只重试1次
    # -rl 150: 限制发包速率每秒150个 (防止被封)
    # -bs 25: 并发批量大小
    cmd = [
        nuclei_path, 
        "-u", url, 
        "-nc", 
        "-disable-update-check",
        "-timeout", "5",
        "-retries", "1",
        "-rl", "150",
        "-bs", "25"
    ]
    
    # 智能等级: 如果指定了tags，扫全等级；否则只扫中高危
    if not tags:
        cmd.extend(["-s", "critical,high,medium"])
    else:
        cmd.extend(["-tags", tags])

    # 强制指定模板路径
    tpl_path = os.path.join(BASE_DIR, "tools", "nuclei-templates")
    if os.path.exists(tpl_path): cmd.extend(["-t", tpl_path])
    else:
        user_tpl = os.path.join(os.path.expanduser("~"), "nuclei-templates")
        if os.path.exists(user_tpl): cmd.extend(["-t", user_tpl])

    def run_sync_nuclei():
        try:
            # 依然使用 subprocess.run，但我们把总超时设为 5 分钟
            # 如果5分钟没跑完，强制结束，防止前端卡死
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=300
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "扫描超时，仅返回部分结果。"
        except Exception as e: 
            return "", str(e)

    try:
        stdout, stderr = await asyncio.to_thread(run_sync_nuclei)
        
        # 如果超时了，提示用户
        if stdout == "TIMEOUT":
            return f"【Nuclei】扫描耗时过长已强制停止。建议缩小扫描范围 (指定更精确的 tags)。"

        vulns = []
        for line in stdout.splitlines():
            try:
                line = line.strip()
                if line.startswith("["):
                    vulns.append(line)
                    save_asset_to_db(url, "Vuln", line, "Nuclei")
                    if "critical" in line.lower() or "high" in line.lower():
                        await push_to_webhook("Nuclei高危", line)
            except: pass
            
        if vulns:
            preview = "\n".join(vulns[:20])
            if len(vulns) > 20: preview += f"\n... (共 {len(vulns)} 条)"
            return f"【Nuclei 扫描报告】\n{preview}"
        else:
            return f"【Nuclei】扫描结束，未发现漏洞。"

    except Exception as e:
        return f"Nuclei 执行异常: {e}"

@mcp.tool()
async def step11_hydra_crack(target_ip: str, service: str, port: int = 0):
    """
    [11.爆破] 调用 Hydra 进行服务弱口令检测 (DLL兼容修正版)。
    """
    # 1. 确保字典存在 (使用绝对路径)
    u_path = os.path.abspath(os.path.join(HYDRA_DIR, "users.txt"))
    p_path = os.path.abspath(os.path.join(HYDRA_DIR, "pass.txt"))
    
    if not os.path.exists(u_path):
        with open(u_path, "w") as f: f.write("\n".join(["root", "admin", "test", "user"]))
    if not os.path.exists(p_path):
        with open(p_path, "w") as f: f.write("\n".join(["123456", "password", "admin", "root"]))

    # 2. 构造命令
    # [关键修改] 使用 HYDRA_PATH 绝对路径
    cmd = [
        HYDRA_PATH, 
        "-L", "users.txt", 
        "-P", "pass.txt", 
        "-t", "4", 
        "-f", 
        "-I", 
        "-w", "2", 
        f"{service}://{target_ip}"
    ]
    
    if port and port != 0:
        cmd.extend(["-s", str(port)])
    
    log(f"Hydra启动: {service}://{target_ip} CWD={HYDRA_DIR}")

    def run_sync_hydra():
        try:
            # 关键：设置 cwd 参数，让 hydra 能找到 dll
            result = subprocess.run(
                cmd,
                cwd=HYDRA_DIR, # 切换工作目录到 tools/hydra
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=120
            )
            return result.stdout, result.stderr
        except Exception as e:
            return "", str(e)

    try:
        stdout, stderr = await asyncio.to_thread(run_sync_hydra)
        
        # 3. 解析结果
        cracked = []
        for line in stdout.splitlines():
            # Hydra 成功特征: "[22][ssh] host: ... login: ... password: ..."
            if "login:" in line and "password:" in line:
                cracked.append(line.strip())
                save_asset_to_db(target_ip, "Crack", line.strip(), "Hydra")
                await push_to_webhook("弱口令成功", f"{target_ip}\n{line.strip()}")
        
        if cracked:
            return f"【Hydra 战果】\n" + "\n".join(cracked)
        
        # 错误检查
        if not stdout and stderr:
            # 过滤掉一些无关紧要的 stderr 信息
            if "Hydra" not in stderr: 
                return f"❌ Hydra 启动失败: {stderr}"
        
        return f"【Hydra】扫描结束，未发现弱口令。\n(日志: {stdout[-200:] if stdout else '无输出'})"

    except Exception as e:
        return f"Hydra 执行异常: {e}"

@mcp.tool()
async def step12_dirsearch_scan(url: str):
    """
    [12.目录] 原生极速目录扫描 (不再依赖外部工具)。
    使用内置的高危字典 + 本地字典进行并发探测。
    Args:
        url: 目标 URL
    """
    if not url.startswith("http"): url = f"http://{url}"
    print(f"启动原生目录扫描: {url}")
    
    # 1. 准备字典 (混合模式：内置高危 + 外部文件)
    # 内置一份精选的 Top 50 高危路径，确保没文件也能扫
    targets = [
        "admin", "login", "system", "backup", "api", "test", "upload", "shell", 
        ".git/config", "config.php", "web.rar", "www.zip", "backup.sql", "database.sql",
        "robots.txt", "sitemap.xml", "console", "dashboard", "manage", "admin.php",
        "actuator/env", "v2/api-docs", "swagger-ui.html", "druid/index.html",
        "phpinfo.php", ".env", "wp-admin", "wp-login.php", "administrator",
        "data", "db", "static", "uploads", "api/v1", "admin/login"
    ]
    
    # 如果有外部字典，也加载进来
    dict_path = os.path.join(BASE_DIR, "dictionaries", "sensitive_dirs.txt")
    if os.path.exists(dict_path):
        try:
            with open(dict_path, 'r', encoding='utf-8') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except: pass
    
    # 去重
    targets = list(set(targets))
    
    found = []
    
    # 2. 定义单个扫描任务
    async def scan_one(client, path):
        if not path.startswith("/"): path = "/" + path
        target_url = url.rstrip('/') + path
        try:
            # follow_redirects=False 禁止重定向，防止误报
            resp = await client.get(target_url, follow_redirects=False)
            
            # 命中逻辑：状态码不是 404
            if resp.status_code != 404:
                # 过滤掉一些常见的误报 (比如 403, 500 有时是防火墙)
                # 这里我们只收录 200, 301, 302, 401, 500(可能是报错泄露)
                if resp.status_code in [200, 301, 302, 401, 403, 500]:
                    return f"{path} (Code: {resp.status_code}, Size: {len(resp.content)})"
        except: 
            pass
        return None

    # 3. 并发执行 (限制并发数为 20，防止封IP)
    semaphore = asyncio.Semaphore(20)
    
    async def bounded_scan(client, path):
        async with semaphore:
            return await scan_one(client, path)

    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        tasks = [bounded_scan(client, path) for path in targets]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                found.append(res)
                # 入库
                save_asset_to_db(url, "Dir", res, "NativeDirScan")

    if found:
        # 结果展示
        preview = "\n".join(found[:20])
        if len(found) > 20: preview += f"\n... (共 {len(found)} 条)"
        
        await push_to_webhook("目录扫描发现", f"目标: {url}\n{str(found[:5])}")
        return f"【目录扫描报告】\n发现 {len(found)} 个路径：\n{preview}"
    else:
        return f"【目录扫描】结束，对 {len(targets)} 个路径未发现有效响应。"

@mcp.tool()
async def step13_sqlmap_scan(url: str):
    """
    [13.SQL注入] 深度注入测试 (Windows 兼容修正版)。
    """
    if not url.startswith("http"): url = f"http://{url}"
    
    # 1. 定义路径
    local_script = os.path.join(BASE_DIR, "tools", "sqlmap", "sqlmap.py")
    
    # 2. 决定启动命令
    if os.path.exists(local_script):
        log(f"调用本地 SQLMap: {local_script}")
        cmd = [sys.executable, local_script]
    else:
        log("未找到本地脚本，尝试全局命令...")
        cmd = ["sqlmap"]

    # 3. 添加参数
    cmd.extend(["-u", url, "--batch", "--random-agent", "--level", "1", "--tech", "BEUST"])

    # 4. 定义同步执行函数 (专门用来绕过 Windows 异步限制)
    def run_sync_sqlmap():
        try:
            # 使用标准的 subprocess.run
            result = subprocess.run(
                cmd,
                capture_output=True, # 捕获输出
                text=True,           # 自动转字符串
                encoding="utf-8",    # 强制 UTF-8
                errors="ignore",     # 忽略乱码
                timeout=120          # 120秒超时
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "TIMEOUT"
        except Exception as e:
            return "", str(e)

    try:
        # 5. 【关键修改】使用 to_thread 将任务扔到线程池，避开 EventLoop 限制
        stdout, stderr = await asyncio.to_thread(run_sync_sqlmap)
        
        if stdout == "TIMEOUT":
            return "【SQLMap】扫描超时 (超过120秒)，可能目标响应过慢。"

        # 6. 分析结果
        if "Parameter:" in stdout and "Type:" in stdout:
            vuln_info = []
            capture = False
            for line in stdout.splitlines():
                if "Parameter:" in line: capture = True
                if capture and line.strip(): vuln_info.append(line.strip())
                if len(vuln_info) > 8: break 
            
            msg = "\n".join(vuln_info)
            save_asset_to_db(url, "Vuln", "SQL Injection", "SQLMap")
            await push_to_webhook("发现SQL注入", f"目标: {url}\n{msg}")
            
            return f"【SQLMap 战果】\n发现注入点！\n{msg}"
            
        elif "all tested parameters do not appear to be injectable" in stdout:
            return "【SQLMap】扫描结束，未发现注入点。"
        
        # 错误兜底
        if not stdout and stderr:
             return f"❌ SQLMap 启动失败: {stderr}"
             
        return f"【SQLMap】扫描完成，未发现明显漏洞 (或被WAF拦截)。"

    except Exception as e:
        import traceback
        return f"SQLMap 执行异常: {e}"

if __name__ == "__main__":
    init_db()
    mcp.run()