import asyncio
import socket
import threading
import struct
import sys
from datetime import datetime
from typing import Dict, List
import os
import json
import pathlib
import re
import requests

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

AUTH_TEMPLATE = """

<!DOCTYPE html>
<html>

<head>
	<meta charset="UTF-8">
	<meta name="robots" content="noindex, nofollow">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
    {{notice_bar}}

	<title>访问认证</title>
	<style>
		body {
			font-family: 'Microsoft YaHei';
			background: rgb(241, 241, 241);
			padding: 48px 16px 0 16px;
		}

		.Main,
		.notice {
			margin: 0 auto;
			max-width: 35em;
			opacity: 0.87;
			box-shadow: 0 2px 2px 0 rgba(0, 0, 0, .14), 0 3px 1px -2px rgba(0, 0, 0, .2), 0 1px 5px 0 rgba(0, 0, 0, .12);
			border-radius: 2px;
		}

		.notice {
			padding: 16px 24px;
			max-width: calc(35em + 16px);
			background: #f8332c;
			color: white;
			margin-bottom: 16px;
		}

		.Main {
			padding: 24px 32px;
			background: white;
			position: relative;
		}

		.textbox {
			border: rgb(225, 229, 232) solid 2px;
			box-sizing: border-box;
			font-size: 14px;
			font-weight: 400;
			height: 40px;
			padding: 0px 16px;
			display: flex;
			flex-grow: 1;
		}

		.divider {
			width: 100%;
			border-top: 1px solid #e1e1e1;
			text-align: center;
			margin-top: 20px;
		}

		.divider span {
			display: inline-block;
			position: relative;
			padding: 0 17px;
			top: -11px;
			font-size: 16px;
			background-color: #fff;
			color: #333;
		}

		.button {
			color: #fff;
			border: 0;
			background-color: #1d74f5;
			position: relative;
			display: flex;
			height: 40px;
			min-height: 40px;
			padding: 0 1.5rem;
			cursor: pointer;
			transition: opacity .3s, background-color .3s, color .3s;
			text-align: center;
			font-size: .875rem;
			font-weight: 600;
			-webkit-box-align: center;
			align-items: center;
			-webkit-box-pack: center;
			justify-content: center;
			border-radius: 2px;
		}

		.button:hover {
			opacity: .6;
		}

		.button:active {
			transform: translateY(2px);
			opacity: .9;
		}

		input:focus {
			outline: none;
		}

		.switch {
			flex-shrink: 0;
			position: relative;
			display: inline-block;
			width: 52px;
			height: 30px;
		}

		.switch input {
			opacity: 0;
			width: 0;
			height: 0;
		}

		.slider {
			position: absolute;
			cursor: pointer;
			top: 0;
			left: 0;
			right: 0;
			bottom: 0;
			background-color: #ccc;
			-webkit-transition: .4s;
			transition: .4s;
			border-radius: 30px;
		}

		.slider:before {
			position: absolute;
			content: "";
			height: 22px;
			width: 22px;
			left: 4px;
			bottom: 4px;
			background-color: white;
			-webkit-transition: .4s;
			transition: .4s;
			border-radius: 50%;
		}

		input:checked+.slider {
			background-color: #2196F3;
		}

		input:focus+.slider {
			box-shadow: 0 0 1px #2196F3;
		}

		input:checked+.slider:before {
			-webkit-transform: translateX(22px);
			transform: translateX(22px);
		}

		@media all and (max-width: 600px) {
			body {
				padding: 48px 8px 0 8px;
			}

			.Main {
				padding: 16px 24px 24px 24px;
			}
		}
	</style>
</head>

<body>
	
	<div class="Main">
		<h1 style="margin: 0;margin-bottom: 8px">访问认证</h1>
		<p style="margin-top: 8px">当前 IP (<b style="color: olive">{{Auth_Client_IP}}</b>) 尚未完成访问认证, 无法访问此隧道</p>
		<form action="#" method="post">
			<div style="display: flex;margin-bottom: 16px;flex-wrap: wrap;gap: 16px">
				<div style="display: flex;gap: 16px;flex-direction: column;flex: 20">
					
					<input class="textbox" type="password" name="pw" id="pw" placeholder="访问密码" autocomplete="current-password" />
					
					
				</div>
				<input class="button" type="submit" value="提交" style="flex: 1" />
			</div>
			<input type="hidden" name="csrf" value="0000000000000000">
			<input type="hidden" name="ip" value="{{Auth_Client_IP}}">
		</form>
		<style>
			@media all and (max-width: 340px) {
				#qr-button {
					display: none;
				}
			}
		</style>
	</div>
</body>

</html>

"""

# 路径配置
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
#获取当前执行exe的路径
pathx_pyinstaller = os.path.dirname(os.path.realpath(sys.argv[0]))

# 默认配置模板
CONFIG_TEMPLATE = {
    "authHttpPort": 3390,
    "tcpPort": 3391,
    "targetIp": "127.0.0.1",
    "targetPort": 3389,
    "authPassword": "PASSWORD",
    "whitelistTimeout": 3600,
    "persistWhitelist": False,
    "pushNotification": {
        "enabled": False,
        "service": "serverchan",
        "sendKey": "",
        "maxAttempts": 10,
        "timeWindow": 60,
        "banDuration": 1800,
        "reportCount": 10
    }
}

# 全局配置变量
HTTP_PORT = CONFIG_TEMPLATE["authHttpPort"]
TCP_PORT = CONFIG_TEMPLATE["tcpPort"]
TARGET_IP = CONFIG_TEMPLATE["targetIp"]
TARGET_PORT = CONFIG_TEMPLATE["targetPort"]
ACCESS_PASSWORD = CONFIG_TEMPLATE["authPassword"]
WHITELIST_TIMEOUT = CONFIG_TEMPLATE["whitelistTimeout"]
PERSIST_WHITELIST = CONFIG_TEMPLATE["persistWhitelist"]
PUSH_CONFIG = CONFIG_TEMPLATE["pushNotification"].copy()

# 加载配置文件
def load_config():
    """加载配置文件，失败则使用默认配置"""
    global HTTP_PORT, TCP_PORT, TARGET_IP, TARGET_PORT, ACCESS_PASSWORD, WHITELIST_TIMEOUT, PERSIST_WHITELIST, PUSH_CONFIG
    
    config_path = pathlib.Path(pathx_pyinstaller) / "config.json"
    
    try:
        if not config_path.exists():
            logging.warning("配置文件不存在，创建默认配置")
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(CONFIG_TEMPLATE, f, indent=4, ensure_ascii=False)
            CONFIG = CONFIG_TEMPLATE.copy()
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                CONFIG = json.load(f)
        
        # 验证并应用配置
        required_keys = ["authHttpPort", "tcpPort", "targetIp", "targetPort", "authPassword"]
        missing_keys = [key for key in required_keys if key not in CONFIG]
        
        if missing_keys:
            logging.warning(f"配置文件缺少以下字段: {missing_keys}，将使用默认值")
            for key in missing_keys:
                CONFIG[key] = CONFIG_TEMPLATE[key]
        
        # 应用配置到全局变量
        HTTP_PORT = CONFIG["authHttpPort"]
        TCP_PORT = CONFIG["tcpPort"]
        TARGET_IP = CONFIG["targetIp"]
        TARGET_PORT = CONFIG["targetPort"]
        ACCESS_PASSWORD = CONFIG["authPassword"]
        
        # 加载白名单配置
        WHITELIST_TIMEOUT = CONFIG.get("whitelistTimeout", CONFIG_TEMPLATE["whitelistTimeout"])
        PERSIST_WHITELIST = CONFIG.get("persistWhitelist", CONFIG_TEMPLATE["persistWhitelist"])
        
        if WHITELIST_TIMEOUT == 0:
            logging.info("白名单有效期：永久（永不过期）")
        else:
            logging.info(f"白名单有效期：{WHITELIST_TIMEOUT}秒 ({WHITELIST_TIMEOUT//60}分钟)")
        
        logging.info(f"持久化白名单：{'启用' if PERSIST_WHITELIST else '禁用'}")
        
        # 加载推送配置
        if "pushNotification" in CONFIG:
            PUSH_CONFIG.update(CONFIG["pushNotification"])
        
        logging.info(f"配置加载成功 - HTTP:{HTTP_PORT}, TCP:{TCP_PORT}, Target:{TARGET_IP}:{TARGET_PORT}")
        if PUSH_CONFIG["enabled"]:
            logging.info(f"推送服务已启用 - 服务:{PUSH_CONFIG['service']}, 阈值:{PUSH_CONFIG['maxAttempts']}次/{PUSH_CONFIG['timeWindow']}秒")
        
    except json.JSONDecodeError as e:
        logging.error(f"配置文件格式错误: {e}，使用默认配置")
        CONFIG = CONFIG_TEMPLATE.copy()
        HTTP_PORT = CONFIG["authHttpPort"]
        TCP_PORT = CONFIG["tcpPort"]
        TARGET_IP = CONFIG["targetIp"]
        TARGET_PORT = CONFIG["targetPort"]
        ACCESS_PASSWORD = CONFIG["authPassword"]
        WHITELIST_TIMEOUT = CONFIG_TEMPLATE["whitelistTimeout"]
        PERSIST_WHITELIST = CONFIG_TEMPLATE["persistWhitelist"]
        PUSH_CONFIG = CONFIG_TEMPLATE["pushNotification"].copy()
    except Exception as e:
        logging.error(f"读取配置文件时出现错误: {e}，使用默认配置")
        CONFIG = CONFIG_TEMPLATE.copy()
        HTTP_PORT = CONFIG["authHttpPort"]
        TCP_PORT = CONFIG["tcpPort"]
        TARGET_IP = CONFIG["targetIp"]
        TARGET_PORT = CONFIG["targetPort"]
        ACCESS_PASSWORD = CONFIG["authPassword"]
        WHITELIST_TIMEOUT = CONFIG_TEMPLATE["whitelistTimeout"]
        PERSIST_WHITELIST = CONFIG_TEMPLATE["persistWhitelist"]
        PUSH_CONFIG = CONFIG_TEMPLATE["pushNotification"].copy()

# 初始化配置
load_config()

# 加载持久化白名单
def load_persisted_whitelist():
    """从文件加载持久化的白名单"""
    if not PERSIST_WHITELIST:
        return
    
    try:
        if WHITELIST_FILE.exists():
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                persisted_data = json.load(f)
            
            current_time = datetime.now().timestamp()
            loaded_count = 0
            
            for ip, timestamp in persisted_data.items():
                # 如果设置为永久有效或未过期
                if WHITELIST_TIMEOUT == 0 or (current_time - timestamp) <= WHITELIST_TIMEOUT:
                    ip_whitelist[ip] = timestamp
                    loaded_count += 1
            
            if loaded_count > 0:
                logging.info(f"已加载 {loaded_count} 个持久化白名单IP")
        else:
            logging.info("白名单文件不存在，跳过加载")
    except Exception as e:
        logging.error(f"加载持久化白名单失败: {e}")

def save_persisted_whitelist():
    """保存白名单到文件"""
    if not PERSIST_WHITELIST:
        return
    
    try:
        with whitelist_lock:
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                json.dump(ip_whitelist, f, indent=4, ensure_ascii=False)
        logging.debug(f"已保存 {len(ip_whitelist)} 个IP到持久化白名单")
    except Exception as e:
        logging.error(f"保存持久化白名单失败: {e}")

# 启动时加载持久化白名单
load_persisted_whitelist()

# PROXY Protocol v2 常量
PROXY_V2_SIG = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'

# 白名单管理
ip_whitelist: Dict[str, float] = {}
whitelist_lock = threading.Lock()
WHITELIST_FILE = pathlib.Path(CURRENT_PATH) / "whitelist.json"

# IP封禁管理
banned_ips: Dict[str, float] = {}  # {ip: ban_expire_timestamp}
failed_login_attempts: Dict[str, List[dict]] = {}  # {ip: [{timestamp, password}]}
banned_ips_lock = threading.Lock()

# FastAPI 应用初始化
app = FastAPI(title="TCP 安全转发服务")

# 认证成功页面HTML
HTML_SUCCESS = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="robots" content="noindex, nofollow">
    <style>
        .notice {
            margin: 0 auto;
            max-width: 35em;
            opacity: 0.87;
            box-shadow: 0 2px 2px 0 rgba(0, 0, 0, .14), 0 3px 1px -2px rgba(0, 0, 0, .2), 0 1px 5px 0 rgba(0, 0, 0, .12);
            border-radius: 2px;
            padding: 16px 24px;
            max-width: calc(35em + 16px);
            background: #0fa32f;
            color: white;
            margin-bottom: 16px;
            text-align: center;
            font-weight: bold;
            font-size: 16px;
        }
    </style>
</head>
<body style="font-family: 'Microsoft YaHei';background: rgb(241, 241, 241);padding: 48px 16px">
    <div class="notice">
        认证成功，现在可以关闭页面并正常连接隧道了
    </div>
    <script>setTimeout(()=>{window.close()}, 2000);</script>
</body>
</html>
"""
# HTML 模板处理
def get_auth_html(client_ip: str, error_msg: str = "") -> str:
    """生成认证页面HTML"""
    notice_bar = ""
    
    # 检查IP是否被封禁
    current_time = datetime.now().timestamp()
    with banned_ips_lock:
        if client_ip in banned_ips:
            ban_expire = banned_ips[client_ip]
            if current_time < ban_expire:
                remaining = int(ban_expire - current_time)
                minutes = remaining // 60
                seconds = remaining % 60
                error_msg = f"IP已被封禁，剩余时间: {minutes}分{seconds}秒"
            else:
                # 封禁已过期，移除
                del banned_ips[client_ip]
                if client_ip in failed_login_attempts:
                    del failed_login_attempts[client_ip]
    
    if error_msg:
        notice_bar = f"<div class='notice'>{error_msg}</div>"
    
    auth_html_path = pathlib.Path(pathx_pyinstaller) / "Auth.html"
    if not os.path.exists(auth_html_path):
        print("未在当前路径下发现Auth.html文件, 已自动创建默认模板文件")
        with open (auth_html_path, "w", encoding="utf-8") as f:
            f.write(AUTH_TEMPLATE)
            f.close()

    try:
        with open(auth_html_path, "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        logging.warning("Auth.html 文件不存在，使用内置模板")
        template = AUTH_TEMPLATE
    
    return template.replace("{{Auth_Client_IP}}", client_ip).replace("{{notice_bar}}", notice_bar)

# IP 提取工具函数
def get_real_ip_from_header(request: Request) -> str:
    """从 X-Forwarded-For Header 提取真实 IP（FastAPI 自动解析）"""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # 格式: client, proxy1, proxy2 → 取第一个
        ips = [ip.strip() for ip in forwarded.split(",")]
        if ips and ips[0]:
            logging.info(f"[HTTP] 从 X-Forwarded-For 获取真实 IP: {ips[0]}")
            return ips[0]
    
    # Fallback 到直接连接 IP
    host = request.client.host if request.client else "unknown"
    logging.info(f"[HTTP] 使用直连 IP: {host}")
    return host

# 推送服务
def send_push_notification(title: str, message: str) -> bool:
    """发送推送通知
    
    Args:
        title: 推送标题
        message: 推送内容
        
    Returns:
        bool: 是否发送成功
    """
    if not PUSH_CONFIG["enabled"]:
        return False
    
    service = PUSH_CONFIG["service"]
    send_key = PUSH_CONFIG.get("sendKey", "")
    
    if not send_key:
        logging.warning("[推送] SendKey 未配置，跳过推送")
        return False
    
    try:
        if service == "serverchan":
            # Server酱推送 - 支持两种格式
            if send_key.startswith('sctp'):
                # sctp 格式: sctp{数字}t...
                match = re.match(r'^sctp(\d+)t', send_key)
                if match:
                    url = f'https://{match.group(1)}.push.ft07.com/send/{send_key}.send'
                else:
                    logging.error("[推送] 无效的 sctp sendkey 格式")
                    return False
            else:
                # 普通格式: SCT...
                url = f'https://sctapi.ftqq.com/{send_key}.send'
            
            params = {
                'title': title,
                'desp': message
            }
            
            # 使用 POST 请求发送 JSON 数据
            response = requests.post(url, json=params, timeout=5)
            result = response.json()
            logging.info(f"[推送] Server酱推送成功: {result}")
            return True
        else:
            logging.warning(f"[推送] 不支持的推送服务: {service}")
            return False
            
    except Exception as e:
        logging.error(f"[推送] 发送失败: {e}")
        return False

def check_and_handle_brute_force(ip: str, password: str) -> tuple:
    """检查并处理暴力破解行为
    
    Args:
        ip: 客户端IP
        password: 尝试的密码
        
    Returns:
        tuple: (是否被封禁, 封禁提示信息)
    """
    current_time = datetime.now().timestamp()
    max_attempts = PUSH_CONFIG["maxAttempts"]
    time_window = PUSH_CONFIG["timeWindow"]
    ban_duration = PUSH_CONFIG["banDuration"]
    report_count = PUSH_CONFIG["reportCount"]
    
    with banned_ips_lock:
        # 初始化IP记录
        if ip not in failed_login_attempts:
            failed_login_attempts[ip] = []
        
        # 添加失败记录
        failed_login_attempts[ip].append({
            "timestamp": current_time,
            "password": password
        })
        
        # 清理过期的记录（超出时间窗口）
        failed_login_attempts[ip] = [
            record for record in failed_login_attempts[ip]
            if current_time - record["timestamp"] <= time_window
        ]
        
        # 检查是否超过阈值
        attempt_count = len(failed_login_attempts[ip])
        
        if attempt_count >= max_attempts:
            # 触发封禁
            if ban_duration > 0:
                ban_expire = current_time + ban_duration
                banned_ips[ip] = ban_expire
                
                # 获取前N个尝试的密码
                reported_passwords = failed_login_attempts[ip][:report_count]
                password_list = "\n".join([
                    f"{i+1}. {record['password']} (时间: {datetime.fromtimestamp(record['timestamp']).strftime('%H:%M:%S')})"
                    for i, record in enumerate(reported_passwords)
                ])
                
                # 构建推送消息
                title = f"TCP 暴力破解警告 - {ip}"
                message = f"""**检测到暴力破解攻击**

**IP地址:** {ip}
**尝试次数:** {attempt_count}次 / {time_window}秒内
**封禁时长:** {ban_duration}秒 ({ban_duration//60}分钟)

**前{min(report_count, attempt_count)}个尝试密码:**
{password_list}

**时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
                
                # 发送推送
                send_push_notification(title, message)
                
                logging.warning(f"[安全] IP {ip} 因暴力破解被封禁 {ban_duration}秒")
                
                minutes = ban_duration // 60
                seconds = ban_duration % 60
                return True, f"IP已被封禁，剩余时间: {minutes}分{seconds}秒"
            else:
                # 不封禁，仅推送警告
                reported_passwords = failed_login_attempts[ip][:report_count]
                password_list = "\n".join([
                    f"{i+1}. {record['password']} (时间: {datetime.fromtimestamp(record['timestamp']).strftime('%H:%M:%S')})"
                    for i, record in enumerate(reported_passwords)
                ])
                
                title = f"TCP 暴力破解警告 - {ip}"
                message = f"""****

**IP地址:** {ip}
**尝试次数:** {attempt_count}次 / {time_window}秒内
**未启用封禁**

**前{min(report_count, attempt_count)}个尝试密码:**
{password_list}

**时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
                
                send_push_notification(title, message)
                logging.warning(f"[安全] IP {ip} 疑似暴力破解，已发送告警（未封禁）")
                return False, "密码错误，请重试"
        
        return False, None


@app.get("/", response_class=HTMLResponse)
async def auth_page(request: Request):
    """GET: 显示认证页面"""
    client_ip = get_real_ip_from_header(request)
    html = get_auth_html(client_ip)
    return HTMLResponse(content=html)


@app.post("/", response_class=HTMLResponse)
async def handle_auth(request: Request, pw: str = Form(...), ip: str = Form(...)):
    """POST: 验证密码并加入白名单"""
    # 安全：以 Header 解析的 IP 为准，防止表单伪造
    real_ip = get_real_ip_from_header(request)
    
    # 如果 Header 解析失败（如本地直连），则使用表单 IP
    target_ip = real_ip if real_ip and real_ip != "unknown" else ip
    
    logging.info(f"[Auth] 认证请求 - Header IP: {real_ip}, 表单 IP: {ip}, 最终使用: {target_ip}")
    
    # 检查是否被封禁
    current_time = datetime.now().timestamp()
    with banned_ips_lock:
        if target_ip in banned_ips:
            ban_expire = banned_ips[target_ip]
            if current_time < ban_expire:
                remaining = int(ban_expire - current_time)
                minutes = remaining // 60
                seconds = remaining % 60
                logging.warning(f"[-] 认证拒绝: IP {target_ip} 已被封禁，剩余 {minutes}分{seconds}秒")
                html = get_auth_html(target_ip, f"IP已被封禁，剩余时间: {minutes}分{seconds}秒")
                return HTMLResponse(content=html)
            else:
                # 封禁已过期，清理
                del banned_ips[target_ip]
                if target_ip in failed_login_attempts:
                    del failed_login_attempts[target_ip]
    
    if pw == ACCESS_PASSWORD:
        with whitelist_lock:
            ip_whitelist[target_ip] = datetime.now().timestamp()
        
        # 如果启用持久化，保存白名单
        if PERSIST_WHITELIST:
            save_persisted_whitelist()
        
        # 认证成功，清理失败记录
        with banned_ips_lock:
            if target_ip in failed_login_attempts:
                del failed_login_attempts[target_ip]
        
        logging.info(f"[+] 认证成功: IP {target_ip} 已加入白名单")
        
        server_info = f"{TARGET_IP}:{TARGET_PORT}"
        success_html = HTML_SUCCESS.replace("{{SERVER_INFO}}", server_info)
        return HTMLResponse(content=success_html)
    else:
        # 认证失败，检查暴力破解
        is_banned, ban_message = check_and_handle_brute_force(target_ip, pw)
        
        if is_banned:
            logging.warning(f"[-] 认证失败且IP被封禁: IP {target_ip}")
            html = get_auth_html(target_ip, ban_message)
        else:
            logging.warning(f"[-] 认证失败: IP {target_ip} 密码错误")
            html = get_auth_html(target_ip, "密码错误，请重试")
        
        return HTMLResponse(content=html)


# Socket TCP 转发逻辑

def parse_proxy_v2(header_data: bytes):
    """解析 HAProxy PROXY Protocol v2 二进制头
    
    Args:
        header_data: 接收到的原始数据
        
    Returns:
        tuple: (解析出的真实IP或None, 剩余数据)
    """
    if len(header_data) < 16:
        return None, header_data

    if not header_data.startswith(PROXY_V2_SIG):
        return None, header_data

    # 解析头部长度
    plen = struct.unpack('!H', header_data[14:16])[0]
    total_len = 16 + plen
    
    if len(header_data) < total_len:
        return None, header_data

    proxy_header = header_data[:total_len]
    remaining_data = header_data[total_len:]

    cmd_ver = proxy_header[12]
    fam = proxy_header[13]

    # TCP IPv4
    if cmd_ver == 0x21 and fam == 0x11:
        src_ip = socket.inet_ntoa(proxy_header[16:20])
        logging.info(f"[PROXY v2] 检测到真实 IP: {src_ip}")
        return src_ip, remaining_data
    # TCP IPv6
    elif cmd_ver == 0x21 and fam == 0x21:
        src_ip = socket.inet_ntop(socket.AF_INET6, proxy_header[16:32])
        logging.info(f"[PROXY v2] 检测到真实 IP (IPv6): {src_ip}")
        return src_ip, remaining_data

    return None, remaining_data


def forward_traffic(src: socket.socket, dst: socket.socket):
    """双向流量转发线程函数"""
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            dst.sendall(data)
    except Exception as e:
        logging.debug(f"流量转发中断: {e}")
    finally:
        for sock in [src, dst]:
            try:
                sock.close()
            except:
                pass


def handle_tcp_connection(client_socket: socket.socket, client_address: tuple):
    """处理 TCP 连接（支持 PROXY v2）"""
    tcp_conn_ip = client_address[0]
    real_ip = tcp_conn_ip
    buffer = b""

    try:
        # 设置初始超时用于接收数据
        client_socket.settimeout(3.0)
        initial_data = client_socket.recv(4096)
        
        if not initial_data:
            client_socket.close()
            return

        buffer = initial_data
        client_socket.settimeout(None)  # 恢复阻塞模式

        # 尝试解析 PROXY Protocol v2
        parsed_ip, remaining = parse_proxy_v2(buffer)
        if parsed_ip:
            real_ip = parsed_ip
            buffer = remaining
            logging.info(f"[TCP] PROXY v2 激活，真实 IP: {real_ip}")
        else:
            logging.info(f"[TCP] 直连模式，IP: {real_ip}")

        # 检查白名单
        is_allowed = False
        current_time = datetime.now().timestamp()
        
        with whitelist_lock:
            if real_ip in ip_whitelist:
                # 如果设置为永久有效或未过期
                if WHITELIST_TIMEOUT == 0 or (current_time - ip_whitelist[real_ip]) <= WHITELIST_TIMEOUT:
                    is_allowed = True
                else:
                    del ip_whitelist[real_ip]  # 过期清理
                    logging.info(f"[TCP] IP {real_ip} 白名单已过期，已移除")
                    # 如果启用持久化，保存更新后的白名单
                    if PERSIST_WHITELIST:
                        save_persisted_whitelist()

        if is_allowed:
            logging.info(f"[>] 允许连接: {real_ip} -> {TARGET_IP}:{TARGET_PORT}")
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(5)
                remote_socket.connect((TARGET_IP, TARGET_PORT))
                remote_socket.settimeout(None)

                # 发送缓冲的数据（如果有）
                if buffer:
                    remote_socket.sendall(buffer)

                # 启动双向转发线程
                t1 = threading.Thread(target=forward_traffic, args=(client_socket, remote_socket))
                t2 = threading.Thread(target=forward_traffic, args=(remote_socket, client_socket))
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()
                t1.join()
                t2.join()
            except Exception as e:
                logging.error(f"[TCP] 连接目标服务器失败 ({real_ip}): {e}")
                client_socket.close()
        else:
            logging.warning(f"[-] 拒绝未授权连接: IP {real_ip} (不在白名单中)")
            client_socket.close()

    except socket.timeout:
        logging.warning(f"[TCP] 连接超时: {real_ip}")
        client_socket.close()
    except Exception as e:
        logging.error(f"[TCP] 处理连接错误: {e}")
        try:
            client_socket.close()
        except:
            pass


def run_tcp_server():
    """运行 TCP 服务器（独立线程）"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', TCP_PORT))
        server.listen(20)
        logging.info(f"[√] TCP 转发服务就绪 (端口 {TCP_PORT})")
        
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_tcp_connection, args=(client_sock, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        logging.info("[TCP] 服务被用户中断")
    except Exception as e:
        logging.error(f"[!] TCP 服务启动失败: {e}")
    finally:
        server.close()
        logging.info("[TCP] 服务已关闭")

def run_http_server():
    """运行 FastAPI HTTP 服务器"""
    logging.info(f"[√] HTTP 认证服务就绪 (端口 {HTTP_PORT})")
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT, log_level="warning")


def main():
    """主函数：启动 HTTP 和 TCP 服务"""
    print("=" * 60)
    print("TCP 安全转发服务")
    print(f"  HTTP 认证端口：{HTTP_PORT} (浏览器访问 http://IP:{HTTP_PORT})")
    print(f"  TCP 连接端口：{TCP_PORT} (需通过访问认证后才连接的端口)")
    print(f"  目标 TCP 地址：{TARGET_IP}:{TARGET_PORT}")
    print("=" * 60)
    
    # 线程 1: FastAPI HTTP 认证服务
    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_http.start()
    
    # 线程 2: Socket TCP 转发服务
    t_tcp = threading.Thread(target=run_tcp_server, daemon=True)
    t_tcp.start()
    
    # 保持主线程运行
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[!] 服务停止")


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        logging.error("权限不足或端口被占用，请以管理员身份运行。")
        print("权限不足或端口被占用，请以管理员身份运行。")
    except Exception as e:
        logging.error(f"启动失败：{e}")
        print(f"启动失败：{e}")
