# Google Hacking Database (GHDB) 终极指令库

## 一、高危配置文件泄露 (最高优先级)
- 查找 .env 环境配置 (含DB密码): filetype:env "DB_PASSWORD" OR "AWS_ACCESS_KEY_ID"
- 查找 Spring Boot 配置文件: filetype:yml "spring.datasource.password"
- 查找 WordPress 配置文件: filetype:php "wp-config.php" intext:"define('DB_PASSWORD'"
- 查找 Git 仓库配置: inurl:".git/config"
- 查找 Docker Compose 配置: filetype:yml "docker-compose" "password"
- 查找 Kubernetes Config: filetype:yaml "apiVersion" "kind: Secret"
- 查找 VSCode 配置 (含Key): inurl:".vscode/sftp.json" "password"
- 查找 IDEA 配置: inurl:".idea/workspace.xml"
- 查找 Web.config (IIS): filetype:config "connectionString"
- 查找 Nginx 配置: filetype:conf "nginx.conf" "server_name"
- 查找 Apache htpasswd: filetype:htpasswd

## 二、数据库文件与备份
- 查找 SQL 导出文件: filetype:sql "insert into" (pass|password|uid)
- 查找 SQL Dump 大文件: filetype:sql "dump" OR "backup"
- 查找 MySQL 连接历史: filetype:log "mysql_history"
- 查找 Access 数据库: filetype:mdb "standard jet db"
- 查找 SQLite 数据库: filetype:sqlite OR filetype:db "SQLite format 3"
- 查找 网站源码备份包: intitle:"index of" (backup.zip|www.rar|site.tar.gz|web.7z)
- 查找 备份文件后缀: inurl:".bak" OR inurl:".old" OR inurl:".swp"

## 三、SSH 与 密钥凭证
- 查找 SSH 私钥 (id_rsa): intitle:"index of" "id_rsa"
- 查找 SSH 公钥 (authorized_keys): intitle:"index of" "authorized_keys"
- 查找 OpenVPN 配置文件: filetype:ovpn "client"
- 查找 Putty 配置文件: filetype:ppk "private-lines"
- 查找 AWS 密钥文件: filetype:pem "BEGIN RSA PRIVATE KEY"

## 四、企业内部敏感文档
- 查找 “机密” PDF: site:target.com filetype:pdf "confidential" OR "internal use only"
- 查找 含有密码的 Excel: site:target.com filetype:xls OR filetype:xlsx "password" OR "username"
- 查找 员工通讯录/手机号: site:target.com filetype:xls "mobile" OR "phone" OR "address"
- 查找 财务/预算文件: site:target.com filetype:xls "budget" OR "salary" OR "finance"
- 查找 网络拓扑图: site:target.com filetype:vsd OR filetype:pdf "topology" OR "network"
- 查找 项目需求/设计书: site:target.com filetype:docx "SRS" OR "design"

## 五、后台入口与管理面板
- 查找 默认后台: site:target.com inurl:admin OR inurl:manage OR inurl:login
- 查找 管理员登录: site:target.com intitle:"admin login"
- 查找 门户/Dashboard: site:target.com intitle:"dashboard" OR intitle:"portal"
- 查找 找回密码页: site:target.com inurl:"forgot-password"
- 查找 注册页面: site:target.com inurl:"register"
- 查找 报错页面 (信息泄露): site:target.com "syntax error" OR "fatal error"
- 查找 PHP探针: site:target.com filetype:php "phpinfo()"
- 查找 目录遍历 (Index of): site:target.com intitle:"index of /"

## 六、日志文件
- 查找 错误日志: filetype:log "error"
- 查找 访问日志: filetype:log "access"
- 查找 调试日志: filetype:log "debug"
- 查找 数据库日志: filetype:log "database"

## 七、特定组件漏洞特征
- 查找 Grafana 面板: intitle:"Grafana" inurl:"/login"
- 查找 Kibana 面板: intitle:"Kibana" inurl:"/app/kibana"
- 查找 Jenkins 面板: intitle:"Dashboard [Jenkins]"
- 查找 Swagger UI: inurl:"swagger-ui.html"
- 查找 JIRA 系统: inurl:"/secure/Dashboard.jspa"
- 查找 Confluence: inurl:"/pages/viewpage.action"