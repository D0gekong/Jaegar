# Jaegar 红队工具作战手册

本文档用于指导 AI Agent 理解底层安全工具的能力边界、使用场景及常见错误处理。

---

## 1. Nuclei (综合漏洞扫描器)
**工具定位**: 核武级漏洞扫描器，基于 YAML 模板，用于精准打击。
**对应函数**: `step10_nuclei_scan`

### 核心能力
- **CVE 扫描**: 检测最新的高危 CVE 漏洞 (如 Log4j, Spring4Shell)。
- **配置错误**: 检测 `.git` 泄露、`.env` 泄露、未授权访问面板。
- **指纹联动**: 当指纹识别出具体组件 (如 "ThinkPHP", "Shiro") 时，效果最佳。

### 战术建议 (Tactics)
- **何时使用**: 
    - 当 `step4_tide_fingerprint` 识别出明确的 CMS 或框架时 (如 "Apache Flink")，应立即调用 Nuclei 并指定 `-tags flink`。
    - 当目标是大范围资产时，使用默认的高危扫描策略。
- **局限性**: 不适合用于端口扫描或密码爆破。

### 常见错误与解释 (Troubleshooting)
- **Error**: `No templates found`
    - **原因**: 漏洞模板未下载或路径配置错误。
    - **建议**: 需要在 `tools` 目录下运行 `nuclei -update-templates`。
- **Error**: `Could not resolve host`
    - **原因**: DNS 解析失败，目标可能不存在或网络不通。
- **Result**: `[INFO] ...`
    - **解释**: 这通常是技术指纹信息，非漏洞。如果只发现 INFO 级别，说明目标相对安全。

---

## 2. Hydra (暴力破解工具)
**工具定位**: 在线服务弱口令爆破之王。
**对应函数**: `step11_hydra_crack`

### 核心能力
- **多协议支持**: SSH (22), FTP (21), MySQL (3306), Redis (6379), MSSQL (1433), RDP (3389), PostgreSQL (5432)。
- **字典爆破**: 使用内置的 Top 100 弱口令字典进行快速筛选。

### 战术建议 (Tactics)
- **何时使用**: 
    - 仅当 `step5_port_scan` 发现上述特定端口 **Open (开放)** 时使用。
    - 不要对 Web 端口 (80/443) 使用 Hydra，Web 表单爆破应使用其他工具。
- **风控提示**: 暴力破解极易触发防火墙封禁 IP，应控制线程数 (代码已限制为 4)。

### 常见错误与解释 (Troubleshooting)
- **Error**: `Connection refused` / `Connect failed`
    - **原因**: 目标端口虽然显示开放，但可能配置了白名单，或者瞬间并发太高被防火墙拦截。
- **Error**: `Unknown service`
    - **原因**: 尝试爆破了 Hydra 不支持的协议，或协议名称拼写错误。
- **Error**: `[ERROR] target ... does not support ...`
    - **原因**: 目标服务关闭了密码登录 (例如 SSH 仅允许密钥登录)。

---

## 3. SQLMap (SQL注入自动化工具)
**工具定位**: 数据库注入漏洞的检测与利用专家。
**对应函数**: `step13_sqlmap_scan`

### 核心能力
- **注入检测**: 自动识别 Boolean-based, Time-based, Error-based, UNION query 等注入类型。
- **数据库接管**: 理论上可执行 `--os-shell` (但在自动化侦察阶段仅用于验证漏洞存在)。

### 战术建议 (Tactics)
- **何时使用**: 
    - 当 URL 中包含明显的参数时 (例如 `?id=1`, `?cat=admin`, `?search=keyword`)。
    - 纯静态页面 (如 `.html`) 不需要使用 SQLMap。
- **效率提示**: 自动化脚本默认使用 `--level 1` 和 `--tech BEUST` (排除时间盲注) 以提高速度。

### 常见错误与解释 (Troubleshooting)
- **Result**: `all tested parameters do not appear to be injectable`
    - **原因**: 参数可能被过滤，或者确实不存在注入。
    - **建议**: 如果确信有漏洞，人工复测时可增加 `--level 3 --tamper`。
- **Error**: `connection timed out`
    - **原因**: 目标响应过慢，或 WAF 识别到了 SQLMap 的特征流量并丢包。

---

## 4. Dirsearch / Ffuf (目录扫描器)
**工具定位**: Web 路径暴力枚举工具。
**对应函数**: `step12_dirsearch_scan`

### 核心能力
- **隐藏资产发现**: 寻找未在页面中链接的敏感文件 (如 `/backup.zip`, `/admin/`, `/.git/config`)。
- **状态码分析**: 自动过滤 404 页面，关注 200 (存在), 301 (跳转), 403 (禁止访问) 的路径。

### 战术建议 (Tactics)
- **何时使用**: 
    - 每一台 Web 服务器都值得扫一遍，特别是当指纹识别无果时。
    - 发现 403 Forbidden 页面时，可能意味着找对了管理后台，但被限制访问。
- **指纹联动**: 如果识别出是 Java 站点，应重点关注 `.jsp` 后缀；PHP 站点关注 `.php`。

### 常见错误与解释 (Troubleshooting)
- **Error**: `Connection timeout`
    - **原因**: 扫描速度过快 (QPS过高)，触发了 WAF 的频次限制。
- **Result**: 大量 403 或 500
    - **原因**: 目标可能有 WAF 防护，建议停止扫描或更换代理 IP。

---

## 5. TideFinger (指纹识别引擎)
**工具定位**: Web 资产的“身份证”识别器。
**对应函数**: `step4_tide_fingerprint`

### 核心能力
- **被动识别**: 匹配 Title, Header, Body 中的关键词。
- **主动探测**: 主动请求 `/robots.txt` 或特定指纹路径 (如 `/seeyon/`) 进行哈希比对。

### 战术建议 (Tactics)
- **优先级**: 这是 Web 渗透的第一步。所有后续的 POC 攻击 (Nuclei) 都应基于指纹识别的结果。
- **联动**: 
    - 识别出 "ThinkPHP" -> 建议执行 ThinkPHP RCE POC。
    - 识别出 "Shiro" -> 建议检查 Shiro 反序列化。