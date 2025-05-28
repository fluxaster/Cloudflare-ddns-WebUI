import os
import subprocess
import configparser
import re
import json 
import uuid 
import requests
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session # 新增 session
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash # 用于密码安全

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger(__name__)

# --- 全局状态 ---
app_status = {
    "current_ipv6": "N/A",
    "current_ipv4": "N/A",
    "last_checked": "N/A",
    "status_message": "等待首次运行...",
    "log_history": [],
    "is_running_update": False,
    "records_status": [] 
}
MAX_LOG_HISTORY = 50

def add_log_entry(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{level}] {message}"
    if level == "ERROR":
        logger.error(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "DEBUG":
        logger.debug(message)
    else:
        logger.info(message)
    
    app_status["log_history"].insert(0, entry)
    if len(app_status["log_history"]) > MAX_LOG_HISTORY:
        app_status["log_history"] = app_status["log_history"][:MAX_LOG_HISTORY]

# --- 全局配置变量和DDNS记录列表 ---
GLOBAL_CONFIG = {
    "CF_API_TOKEN": "", 
    "CF_ZONE_ID": "",   
    "DDNS_CHECK_INTERVAL_MINUTES": 5,
    "ENABLE_IPV4_DDNS": False,
    "ENABLE_IPV6_DDNS": False,
    "DDNS_INTERFACE_NAME": ""
}

DDNS_RECORDS = [] 

# --- 管理员账户相关 ---
ADMIN_CREDENTIALS_FILE = 'admin_credentials.json'
ADMIN_ACCOUNT_SET = False # 标记管理员账户是否已设置

def load_admin_credentials():
    """从文件加载管理员凭证"""
    global ADMIN_ACCOUNT_SET
    if os.path.exists(ADMIN_CREDENTIALS_FILE):
        try:
            with open(ADMIN_CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                creds = json.load(f)
                if creds and "username" in creds and "password_hash" in creds:
                    ADMIN_ACCOUNT_SET = True
                    add_log_entry("管理员账户已加载。", "INFO")
                    return creds
        except json.JSONDecodeError as e:
            add_log_entry(f"解析管理员凭证文件出错: {e}", "ERROR")
        except Exception as e:
            add_log_entry(f"读取管理员凭证文件时发生未知错误: {e}", "ERROR")
    ADMIN_ACCOUNT_SET = False
    add_log_entry("管理员账户未设置或加载失败。", "WARNING")
    return None

def save_admin_credentials(username, password_hash):
    """保存管理员凭证到文件"""
    try:
        with open(ADMIN_CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
            json.dump({"username": username, "password_hash": password_hash}, f, indent=4, ensure_ascii=False)
        add_log_entry("管理员账户已成功保存。", "INFO")
        global ADMIN_ACCOUNT_SET
        ADMIN_ACCOUNT_SET = True
        return True
    except Exception as e:
        add_log_entry(f"保存管理员凭证失败: {e}", "ERROR")
        return False

# --- 配置加载与保存函数 ---

def save_ddns_records():
    """保存 DDNS 记录到 records.json，确保 UTF-8 编码"""
    records_file_path = 'records.json'
    try:
        with open(records_file_path, 'w', encoding='utf-8') as f:
            json.dump(DDNS_RECORDS, f, indent=4, ensure_ascii=False)
        add_log_entry(f"已成功保存 {len(DDNS_RECORDS)} 条 DDNS 记录到 {records_file_path}。", "INFO")
    except Exception as e:
        add_log_entry(f"保存 DDNS 记录到 {records_file_path} 失败: {e}", "ERROR")

def save_global_config():
    """保存全局配置到 config.ini，确保 UTF-8 编码"""
    config_file_path = 'config.ini'
    cfg = configparser.ConfigParser()
    
    if os.path.exists(config_file_path):
        try:
            cfg.read(config_file_path, encoding='utf-8') 
        except Exception as e:
            add_log_entry(f"读取 config.ini 以更新时出错 (可能编码问题): {e}", "WARNING")

    if 'Cloudflare' not in cfg: cfg['Cloudflare'] = {}
    if 'DDNS' not in cfg: cfg['DDNS'] = {}

    cfg['Cloudflare']['ApiToken'] = GLOBAL_CONFIG["CF_API_TOKEN"]
    cfg['Cloudflare']['ZoneId'] = GLOBAL_CONFIG["CF_ZONE_ID"]

    cfg['DDNS']['CheckIntervalMinutes'] = str(GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
    cfg['DDNS']['EnableIPv4DDNS'] = str(GLOBAL_CONFIG["ENABLE_IPV4_DDNS"])
    cfg['DDNS']['EnableIPv6DDNS'] = str(GLOBAL_CONFIG["ENABLE_IPV6_DDNS"])
    cfg['DDNS']['InterfaceName'] = GLOBAL_CONFIG["DDNS_INTERFACE_NAME"]

    try:
        with open(config_file_path, 'w', encoding='utf-8') as f:
            cfg.write(f)
        add_log_entry(f"已成功保存全局配置到 {config_file_path}。", "INFO")
    except Exception as e:
        add_log_entry(f"保存全局配置到 {config_file_path} 失败: {e}", "ERROR")

def _sync_app_status_records_display():
    """
    根据 DDNS_RECORDS（配置）更新 app_status["records_status"]（显示状态）。
    此函数在 CRUD 操作后调用，不触发实际的 IP 获取和 Cloudflare API 调用，
    但会保留已知的 IP 状态，对新记录或类型改变的记录则显示“待检查”。
    """
    new_records_status = []
    old_records_status_map = {rs["id"]: rs for rs in app_status["records_status"]}

    for record_conf in DDNS_RECORDS:
        record_id = record_conf.get("id")
        record_name = record_conf.get("name")
        record_type = record_conf.get("type")
        record_proxied = record_conf.get("proxied", False)
        record_ttl = record_conf.get("ttl", 120)
        record_enabled = record_conf.get("enabled", True)

        current_record_status = {
            "id": record_id,
            "name": record_name,
            "type": record_type,
            "proxied": record_proxied,
            "ttl": record_ttl,
            "enabled": record_enabled,
            "local_ip": "N/A",  
            "cloudflare_ip": "N/A", 
            "last_updated_cloudflare": "N/A", 
            "message": "待检查..." 
        }

        if record_id in old_records_status_map:
            old_status = old_records_status_map[record_id]
            if old_status.get("type") == record_type:
                current_record_status["local_ip"] = old_status.get("local_ip", "N/A")
                current_record_status["cloudflare_ip"] = old_status.get("cloudflare_ip", "N/A")
                current_record_status["last_updated_cloudflare"] = old_status.get("last_updated_cloudflare", "N/A")
                current_record_status["message"] = old_status.get("message", "待检查...")
            else:
                current_record_status["message"] = f"类型已更改为 {record_type}，待检查..."
        
        if not record_enabled:
            current_record_status["message"] = "此记录已禁用。"
        elif current_record_status["message"] == "此记录已禁用。": 
             current_record_status["message"] = "已启用，待检查..."


        new_records_status.append(current_record_status)
    
    app_status["records_status"] = new_records_status
    add_log_entry("已同步应用状态中的记录显示信息。", "DEBUG")


def load_all_config():
    """加载所有配置：config.ini, records.json, admin_credentials.json"""
    global GLOBAL_CONFIG, DDNS_RECORDS

    # 1. 从 config.ini 加载配置
    config = configparser.ConfigParser()
    config_file_path = 'config.ini'
    if os.path.exists(config_file_path):
        try:
            config.read(config_file_path, encoding='utf-8') 
            if 'Cloudflare' in config:
                GLOBAL_CONFIG["CF_API_TOKEN"] = config.get('Cloudflare', 'ApiToken', fallback=GLOBAL_CONFIG["CF_API_TOKEN"])
                GLOBAL_CONFIG["CF_ZONE_ID"] = config.get('Cloudflare', 'ZoneId', fallback=GLOBAL_CONFIG["CF_ZONE_ID"])
            if 'DDNS' in config:
                GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] = config.getint('DDNS', 'CheckIntervalMinutes', fallback=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
                GLOBAL_CONFIG["ENABLE_IPV4_DDNS"] = config.getboolean('DDNS', 'EnableIPv4DDNS', fallback=GLOBAL_CONFIG["ENABLE_IPV4_DDNS"])
                GLOBAL_CONFIG["ENABLE_IPV6_DDNS"] = config.getboolean('DDNS', 'EnableIPv6DDNS', fallback=GLOBAL_CONFIG["ENABLE_IPV6_DDNS"])
                GLOBAL_CONFIG["DDNS_INTERFACE_NAME"] = config.get('DDNS', 'InterfaceName', fallback=GLOBAL_CONFIG["DDNS_INTERFACE_NAME"])
            add_log_entry("已从 config.ini 加载配置。", "INFO")
        except Exception as e:
            add_log_entry(f"读取 config.ini 出错: {e}", "ERROR")
    else:
        add_log_entry("config.ini 文件未找到。将使用默认值。", "WARNING")

    # 2. 从 records.json 加载 DDNS 记录并确保 ID 存在
    records_file_path = 'records.json'
    if os.path.exists(records_file_path):
        try:
            with open(records_file_path, 'r', encoding='utf-8') as f:
                loaded_records = json.load(f)
            
            needs_save = False
            for i, record in enumerate(loaded_records):
                if "id" not in record or not record["id"]: 
                    record["id"] = str(uuid.uuid4())
                    needs_save = True
            
            DDNS_RECORDS = loaded_records
            if needs_save:
                add_log_entry("检测到部分 records.json 记录缺少ID，已自动生成并保存。", "INFO")
                save_ddns_records() 

            add_log_entry(f"已成功从 {records_file_path} 加载 {len(DDNS_RECORDS)} 条 DDNS 记录。", "INFO")
        except json.JSONDecodeError as e:
            add_log_entry(f"解析 {records_file_path} 出错: {e}。请检查JSON格式。", "ERROR")
            DDNS_RECORDS = []
        except Exception as e:
            add_log_entry(f"读取 {records_file_path} 时发生未知错误: {e}", "ERROR")
            DDNS_RECORDS = []
    else:
        add_log_entry(f"records.json 文件未找到。将以空记录列表启动。", "WARNING")
        DDNS_RECORDS = []

    # 3. 加载管理员凭证
    load_admin_credentials()

    # 验证关键配置
    if not GLOBAL_CONFIG["CF_API_TOKEN"] or not GLOBAL_CONFIG["CF_ZONE_ID"]:
        add_log_entry("警告: Cloudflare API Token 或 Zone ID 未能成功加载。DDNS 功能将无法正常工作。", "ERROR")
        GLOBAL_CONFIG["CF_API_TOKEN"] = ""
        GLOBAL_CONFIG["CF_ZONE_ID"] = ""

    add_log_entry(f"最终加载的 Cloudflare API Token (部分显示): {GLOBAL_CONFIG['CF_API_TOKEN'][:8]}...", "DEBUG")
    add_log_entry(f"最终加载的 Cloudflare Zone ID: {GLOBAL_CONFIG['CF_ZONE_ID']}", "DEBUG")


# --- DDNS 核心功能 (保持不变) ---
def get_stable_ipv6_windows():
    script_path = os.path.join(os.path.dirname(__file__), "get_ipv6.ps1")
    if not os.path.exists(script_path):
        add_log_entry("错误: get_ipv6.ps1 脚本未找到!", "ERROR")
        return None

    command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path]
    
    if GLOBAL_CONFIG["DDNS_INTERFACE_NAME"]:
        add_log_entry(f"配置的网络接口名 (供参考，当前未传递给脚本): {GLOBAL_CONFIG['DDNS_INTERFACE_NAME']}", "DEBUG")
    
    add_log_entry(f"执行 PowerShell 命令: {' '.join(command)}", "DEBUG")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', timeout=15)
        
        if process.returncode == 0 and process.stdout:
            raw_output = process.stdout.strip()
            potential_ips = [ip.strip() for ip in raw_output.splitlines() if ip.strip()]
            
            if not potential_ips:
                add_log_entry("PowerShell 未返回任何 IPv6 地址。", "WARNING")
                if process.stderr: add_log_entry(f"PowerShell 错误输出: {process.stderr.strip()}", "WARNING")
                return None

            add_log_entry(f"PowerShell 返回的潜在 IPv6 地址: {potential_ips}", "DEBUG")
            
            valid_gua_ips = []
            for ip_str in potential_ips:
                if re.match(r'^([23][0-9a-fA-F]{3}:)', ip_str) and ':' in ip_str and len(ip_str) <= 39:
                    valid_gua_ips.append(ip_str)
                else:
                    add_log_entry(f"地址 '{ip_str}' 不是有效的 GUA IPv6 格式，已忽略。", "DEBUG")
            
            if not valid_gua_ips:
                add_log_entry("在 PowerShell 返回的地址中未找到有效的公网 IPv6 (GUA)。", "WARNING")
                return None

            best_ip = min(valid_gua_ips, key=len) 
            
            add_log_entry(f"从候选列表 {valid_gua_ips} 中选择的最佳 IPv6: {best_ip}", "INFO")
            return best_ip
            
        else:
            add_log_entry(f"PowerShell 获取 IPv6 失败。Return code: {process.returncode}", "ERROR")
            if process.stdout: add_log_entry(f"PowerShell 标准输出: {process.stdout.strip()}", "ERROR")
            if process.stderr: add_log_entry(f"PowerShell 错误输出: {process.stderr.strip()}", "ERROR")
            return None
    except subprocess.TimeoutExpired:
        add_log_entry("PowerShell 命令执行超时。", "ERROR")
        return None
    except Exception as e:
        add_log_entry(f"执行 PowerShell 时发生异常: {e}", "ERROR")
        return None

def get_public_ipv4():
    ipv4_check_urls = [
        "https://api.ipify.org?format=json",
        "https://ipv4.icanhazip.com/",
        "http://whatismyip.akamai.com/",
        "http://ipinfo.io/ip"
    ]
    
    add_log_entry("正在尝试获取当前公网 IPv4 地址...")
    for url in ipv4_check_urls:
        try:
            add_log_entry(f"尝试从 {url} 获取 IPv4...", "DEBUG")
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            content = response.text.strip()
            if "ipify.org" in url and "ip" in content:
                try:
                    data = json.loads(content)
                    ipv4 = data.get("ip")
                except json.JSONDecodeError:
                    ipv4 = None
            else:
                ipv4 = content
            
            if ipv4 and re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ipv4):
                add_log_entry(f"成功获取到公网 IPv4 地址: {ipv4} (来自 {url})", "INFO")
                return ipv4
            else:
                add_log_entry(f"从 {url} 获取到的内容 '{content}' 不是有效的 IPv4 地址。", "WARNING")
        except requests.exceptions.RequestException as e:
            add_log_entry(f"从 {url} 获取 IPv4 失败: {e}", "WARNING")
        except Exception as e:
            add_log_entry(f"获取 IPv4 时发生未知错误: {e}", "WARNING")
            
    add_log_entry("未能获取到有效的公网 IPv4 地址。", "ERROR")
    return None

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"

def _cf_api_request(method, endpoint, data=None):
    if not GLOBAL_CONFIG['CF_API_TOKEN'] or not GLOBAL_CONFIG['CF_ZONE_ID']:
        add_log_entry("Cloudflare API Token 或 Zone ID 未配置，无法执行API请求。", "ERROR")
        return None

    headers = {
        "Authorization": f"Bearer {GLOBAL_CONFIG['CF_API_TOKEN']}",
        "Content-Type": "application/json"
    }
    url = f"{CLOUDFLARE_API_BASE_URL}{endpoint}"
    try:
        response = requests.request(method, url, headers=headers, json=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        add_log_entry(f"Cloudflare API 请求失败 ({method} {url}): {e}", "ERROR")
        if hasattr(e, 'response') and e.response is not None:
            try:
                add_log_entry(f"API 错误详情: {e.response.json()}", "ERROR")
            except ValueError:
                 add_log_entry(f"API 错误详情 (非JSON): {e.response.text}", "ERROR")
        return None

def _get_cloudflare_dns_record(record_name, record_type):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records?type={record_type}&name={record_name}"
    data = _cf_api_request("GET", endpoint)

    if data and data.get("success"):
        if data["result"]:
            record = data["result"][0]
            add_log_entry(f"Cloudflare 记录 '{record_name}' ({record_type}) 当前 IP: {record['content']}, ID: {record['id']}", "DEBUG")
            return record["id"], record["content"]
        else:
            add_log_entry(f"在 Cloudflare 上未找到名为 '{record_name}' 的 {record_type} 记录。")
            return None, None
    else:
        add_log_entry(f"从 Cloudflare 获取 DNS 记录 '{record_name}' ({record_type}) 失败。", "ERROR")
        return None, None


def _update_cloudflare_dns_record(record_id, record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records/{record_id}"
    payload = {
        "type": record_type,
        "name": record_name,
        "content": current_ip,
        "ttl": ttl,
        "proxied": proxied
    }
    add_log_entry(f"正在更新 Cloudflare 记录 '{record_name}' (ID: {record_id}) 指向 '{current_ip}'...", "DEBUG")
    data = _cf_api_request("PUT", endpoint, data=payload)

    if data and data.get("success"):
        add_log_entry(f"成功更新 Cloudflare 记录 '{record_name}' 为 '{current_ip}'。ଘ(੭ˊᵕˋ)੭*", "INFO")
        return True
    else:
        add_log_entry(f"更新 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

def _create_cloudflare_dns_record(record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records"
    payload = {
        "type": record_type,
        "name": record_name,
        "content": current_ip,
        "ttl": ttl,
        "proxied": proxied
    }
    add_log_entry(f"正在创建新的 Cloudflare 记录 '{record_name}' ({record_type}) 指向 '{current_ip}'...", "DEBUG")
    data = _cf_api_request("POST", endpoint, data=payload)

    if data and data.get("success"):
        add_log_entry(f"成功创建 Cloudflare 记录 '{record_name}' 指向 '{current_ip}'。太棒啦~ (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", "INFO")
        return True
    else:
        add_log_entry(f"创建 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

def run_ddns_update_job(manual_trigger=False):
    """
    DDNS 更新主任务。获取本机IP并更新Cloudflare记录。
    支持IPv4和IPv6，并遍历所有配置的DDNS记录。
    此函数会更新 app_status 中的 IP 信息和记录状态。
    """
    if app_status["is_running_update"] and not manual_trigger:
        add_log_entry("DDNS 更新任务已在运行中，跳过此次调度。", "DEBUG")
        return

    app_status["is_running_update"] = True
    app_status["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    app_status["status_message"] = "DDNS 更新任务正在运行..."
    add_log_entry("--- 开始 DDNS 更新检查 ---")

    if not GLOBAL_CONFIG["CF_API_TOKEN"] or not GLOBAL_CONFIG["CF_ZONE_ID"]:
        app_status["status_message"] = "错误: Cloudflare API Token 或 Zone ID 未配置，DDNS 功能将无法工作。"
        add_log_entry(app_status["status_message"], "ERROR")
        app_status["is_running_update"] = False
        _sync_app_status_records_display() 
        return

    current_public_ipv4 = None
    if GLOBAL_CONFIG["ENABLE_IPV4_DDNS"]:
        current_public_ipv4 = get_public_ipv4()
        app_status["current_ipv4"] = current_public_ipv4 if current_public_ipv4 else "获取失败"
    else:
        app_status["current_ipv4"] = "已禁用 (全局)"
        add_log_entry("IPv4 DDNS 功能已全局禁用。", "DEBUG")

    current_public_ipv6 = None
    if GLOBAL_CONFIG["ENABLE_IPV6_DDNS"]:
        current_public_ipv6 = get_stable_ipv6_windows()
        app_status["current_ipv6"] = current_public_ipv6 if current_public_ipv6 else "获取失败"
    else:
        app_status["current_ipv6"] = "已禁用 (全局)"
        add_log_entry("IPv6 DDNS 功能已全局禁用。", "DEBUG")
    
    app_status["records_status"] = []

    if not DDNS_RECORDS:
        app_status["status_message"] = "未配置任何 DDNS 记录。请添加记录。"
        add_log_entry(app_status["status_message"], "WARNING")
        app_status["is_running_update"] = False
        return

    for record_conf in DDNS_RECORDS:
        record_id = record_conf.get("id") 
        record_name = record_conf.get("name")
        record_type = record_conf.get("type")
        record_proxied = record_conf.get("proxied", False)
        record_ttl = record_conf.get("ttl", 120)
        record_enabled = record_conf.get("enabled", True)

        record_status = {
            "id": record_id,
            "name": record_name,
            "type": record_type,
            "proxied": record_proxied,
            "ttl": record_ttl,
            "enabled": record_enabled,
            "local_ip": "N/A", 
            "cloudflare_ip": "N/A",
            "last_updated_cloudflare": "N/A",
            "message": ""
        }
        
        if not record_enabled:
            record_status["message"] = "此记录已禁用。"
            app_status["records_status"].append(record_status)
            add_log_entry(f"记录 '{record_name}' ({record_type}) 已禁用，跳过更新。", "INFO")
            continue

        target_ip = None
        if record_type == "AAAA":
            if GLOBAL_CONFIG["ENABLE_IPV6_DDNS"]:
                target_ip = current_public_ipv6
                record_status["local_ip"] = target_ip if target_ip else "获取失败"
            else:
                record_status["message"] = "IPv6 DDNS 已全局禁用。"
                app_status["records_status"].append(record_status)
                add_log_entry(f"记录 '{record_name}' ({record_type}) IPv6 DDNS 已全局禁用，跳过。", "INFO")
                continue
        elif record_type == "A":
            if GLOBAL_CONFIG["ENABLE_IPV4_DDNS"]:
                target_ip = current_public_ipv4
                record_status["local_ip"] = target_ip if target_ip else "获取失败"
            else:
                record_status["message"] = "IPv4 DDNS 已全局禁用。"
                app_status["records_status"].append(record_status)
                add_log_entry(f"记录 '{record_name}' ({record_type}) IPv4 DDNS 已全局禁用，跳过。", "INFO")
                continue
        else:
            record_status["message"] = f"不支持的记录类型: {record_type}"
            app_status["records_status"].append(record_status)
            add_log_entry(f"记录 '{record_name}' 包含不支持的记录类型: {record_type}，跳过。", "ERROR")
            continue

        if not target_ip:
            record_status["message"] = f"未能获取当前公网 {record_type} 地址。"
            app_status["records_status"].append(record_status)
            add_log_entry(f"记录 '{record_name}' ({record_type}) 未能获取目标IP，跳过更新。", "ERROR")
            continue

        add_log_entry(f"--- 正在处理记录: {record_name} ({record_type}) ---")
        cf_record_id, cloudflare_ip = _get_cloudflare_dns_record(record_name, record_type)
        record_status["cloudflare_ip"] = cloudflare_ip if cloudflare_ip else "未找到/失败"

        if cf_record_id:
            if target_ip == cloudflare_ip:
                record_status["message"] = f"IP 未更改 ({target_ip})，无需更新。"
            else:
                add_log_entry(f"记录 '{record_name}' IP 地址已更改 (本机: {target_ip}, Cloudflare: {cloudflare_ip})。")
                record_status["message"] = f"正在更新 Cloudflare IP..."
                if _update_cloudflare_dns_record(cf_record_id, record_name, record_type, target_ip, record_ttl, record_proxied):
                    record_status["message"] = f"Cloudflare IP 更新成功为 {target_ip}。"
                    record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                else:
                    record_status["message"] = f"Cloudflare IP 更新失败。"
        else:
            if cloudflare_ip is None: 
                add_log_entry(f"记录 '{record_name}' ({record_type}) 不存在，尝试创建。")
                record_status["message"] = f"正在创建 Cloudflare 记录..."
                if _create_cloudflare_dns_record(record_name, record_type, target_ip, record_ttl, record_proxied):
                    record_status["message"] = f"Cloudflare 记录创建成功，IP: {target_ip}。"
                    record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                else:
                    record_status["message"] = f"Cloudflare 记录创建失败。"
            else:
                record_status["message"] = "获取 Cloudflare 记录信息失败，无法继续。"
        
        app_status["records_status"].append(record_status)
        add_log_entry(f"--- 记录 {record_name} ({record_type}) 处理完毕 ---")

    app_status["status_message"] = "DDNS 更新检查完成。"
    add_log_entry("--- DDNS 更新检查结束 ---")
    app_status["is_running_update"] = False

# --- Flask Web 应用 ---
flask_app = Flask(__name__)
flask_app.secret_key = os.urandom(24) 

# --- 全局认证检查器 ---
@flask_app.before_request
def check_authentication():
    # 允许 setup_admin, login, 和 static 文件在未认证状态下访问
    # 这样用户才能设置账户或登录
    if request.endpoint in ['setup_admin', 'login', 'static']:
        return None # 继续处理请求，不进行重定向

    # 如果管理员账户未设置，则强制重定向到设置页面
    # 即使是访问其他页面，也会先引导到设置页面
    if not ADMIN_ACCOUNT_SET:
        flash("请先设置管理员账户。", "warning")
        return redirect(url_for('setup_admin'))

    # 如果管理员账户已设置但用户未登录，则强制重定向到登录页面
    if 'logged_in' not in session:
        flash("请先登录以访问此页面。", "warning")
        return redirect(url_for('login'))
    
    # 如果已登录，继续处理请求
    return None

# --- 登录页面 ---
@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session: # 如果已经登录，则直接跳转主页
        return redirect(url_for('index')) 

    # 在尝试登录前，确保管理员账户已设置。如果没有，仍然重定向到 setup_admin
    # 否则 load_admin_credentials() 返回 None 会导致 admin_creds 为空
    admin_creds = load_admin_credentials() # 重新加载以确保最新状态
    if not ADMIN_ACCOUNT_SET: # 重新检查全局变量，可能因为之前load_admin_credentials()未成功设置
        return redirect(url_for('setup_admin')) 

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 验证用户名和密码
        if username == admin_creds["username"] and \
           check_password_hash(admin_creds["password_hash"], password):
            session['logged_in'] = True
            session['username'] = username
            flash(f"欢迎回来！{username}！(っ.❛ ᴗ ❛.)っ", "success")
            add_log_entry(f"用户 '{username}' 成功登录。", "INFO")
            return redirect(url_for('index'))
        else:
            flash("用户名或密码不正确，请重新输入。", "error")
            add_log_entry(f"用户尝试登录失败，用户名: {username}", "WARNING")
    return render_template('login.html')

# --- 登出页面 ---
@flask_app.route('/logout')
def logout(): # 不再需要 @login_required 装饰器，全局 before_request 已经处理
    session.pop('logged_in', None)
    session.pop('username', None)
    flash("您已成功登出。欢迎下次再来~", "info")
    add_log_entry("用户已登出。", "INFO")
    return redirect(url_for('login'))

# --- 首次设置管理员账户 ---
@flask_app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    if ADMIN_ACCOUNT_SET:
        flash("管理员账户已设置，请登录。", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash("用户名和密码都不能为空！", "error")
            return render_template('setup_admin.html')
        
        if password != confirm_password:
            flash("两次输入的密码不一致！", "error")
            return render_template('setup_admin.html')
        
        if len(password) < 6: # 简单密码强度检查
            flash("密码长度至少为6个字符。", "error")
            return render_template('setup_admin.html')

        hashed_password = generate_password_hash(password)
        if save_admin_credentials(username, hashed_password):
            flash("管理员账户设置成功！请登录。", "success")
            add_log_entry(f"管理员账户 '{username}' 首次设置成功。", "INFO")
            return redirect(url_for('login'))
        else:
            flash("保存管理员账户时发生错误，请检查日志。", "error")
            add_log_entry("保存管理员账户失败。", "ERROR")

    return render_template('setup_admin.html')


# --- 主面板路由 (全局状态总览) ---
@flask_app.route('/')
def index(): # 移除 @login_required 装饰器
    status_snapshot = {
        "current_ipv6": app_status["current_ipv6"],
        "current_ipv4": app_status["current_ipv4"],
        "last_checked": app_status["last_checked"],
        "status_message": app_status["status_message"],
        "log_history": list(app_status["log_history"]),
        "records_status": list(app_status["records_status"]) # 虽然这里不渲染，但确保数据完整
    }
    return render_template('index.html', status=status_snapshot, username=session.get('username', '访客'))

@flask_app.route('/trigger_update', methods=['POST'])
def trigger_update(): # 移除 @login_required 装饰器
    add_log_entry("收到手动更新请求。")
    if app_status["is_running_update"]:
        flash("更新任务已在运行中，请稍候。", "warning")
        add_log_entry("更新任务已在运行中，请稍候。", "WARNING")
    else:
        run_ddns_update_job(manual_trigger=True)
        flash("DDNS 更新检查已触发！", "success")
    return redirect(url_for('index'))

@flask_app.route('/status_json')
def status_json(): # 这个接口是公开的，供前端自动刷新，不需要登录
    return jsonify({
        "current_ipv6": app_status["current_ipv6"],
        "current_ipv4": app_status["current_ipv4"],
        "last_checked": app_status["last_checked"],
        "status_message": app_status["status_message"],
        "log_history": list(app_status["log_history"]),
        "records_status": list(app_status["records_status"])
    })

# --- 全局设置管理 ---
@flask_app.route('/settings', methods=['GET', 'POST'])
def settings(): # 移除 @login_required 装饰器
    if request.method == 'POST':
        try:
            interval_str = request.form.get('interval')
            if interval_str and interval_str.isdigit() and int(interval_str) > 0:
                GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] = int(interval_str)
            else:
                flash("检查间隔必须是大于0的有效整数！", "error")
                return redirect(url_for('settings'))

            GLOBAL_CONFIG["ENABLE_IPV4_DDNS"] = 'enable_ipv4' in request.form
            GLOBAL_CONFIG["ENABLE_IPV6_DDNS"] = 'enable_ipv6' in request.form
            GLOBAL_CONFIG["DDNS_INTERFACE_NAME"] = request.form.get('interface_name', '').strip()
            
            save_global_config() 
            
            global scheduler 
            if scheduler.running:
                scheduler.shutdown() 
            
            scheduler = BackgroundScheduler(daemon=True) 
            if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
                scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
                scheduler.start()
                add_log_entry(f"DDNS 自动更新任务间隔已更新为 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟。", "INFO")
            else:
                add_log_entry("DDNS 自动更新间隔设置为0或无效，将不会自动运行。", "WARNING")

            flash("全局设置已成功更新！", "success")
        except Exception as e:
            add_log_entry(f"保存设置时发生错误: {e}", "ERROR")
            flash(f"保存设置时发生错误: {e}", "error")
        return redirect(url_for('settings'))
    
    return render_template('settings.html', config=GLOBAL_CONFIG, username=session.get('username', '访客'))


# --- DDNS 记录管理页面 ---
@flask_app.route('/records', methods=['GET'])
def records_management(): # 移除 @login_required 装饰器
    return render_template('records_management.html', records=app_status["records_status"], username=session.get('username', '访客'))

# --- 添加 DDNS 记录 ---
@flask_app.route('/records/add', methods=['GET', 'POST'])
def add_record(): # 移除 @login_required 装饰器
    if request.method == 'POST':
        record_name = request.form['name'].strip()
        record_type = request.form['type'].strip().upper()
        proxied = 'proxied' in request.form
        ttl = int(request.form.get('ttl', 120))
        enabled = 'enabled' in request.form

        if not record_name or not record_type:
            flash("记录名和类型不能为空！", "error")
            return render_template('record_form.html', record=None, form_title="添加新记录", username=session.get('username', '访客'))
        
        if record_type not in ["A", "AAAA"]:
            flash("记录类型只能是 A 或 AAAA！", "error")
            return render_template('record_form.html', record=None, form_title="添加新记录", username=session.get('username', '访客'))
        
        if any(r['name'].lower() == record_name.lower() and r['type'] == record_type for r in DDNS_RECORDS):
            flash(f"已存在同名同类型的记录: '{record_name}' ({record_type})。", "error")
            return render_template('record_form.html', record=None, form_title="添加新记录", username=session.get('username', '访客'))

        new_record = {
            "id": str(uuid.uuid4()), 
            "name": record_name,
            "type": record_type,
            "proxied": proxied,
            "ttl": ttl,
            "enabled": enabled
        }
        DDNS_RECORDS.append(new_record)
        save_ddns_records() 

        _sync_app_status_records_display() 

        flash(f"记录 '{record_name}' 已成功添加！", "success")
        return redirect(url_for('records_management')) 
    
    return render_template('record_form.html', record=None, form_title="添加新记录", username=session.get('username', '访客'))

# --- 编辑 DDNS 记录 ---
@flask_app.route('/records/edit/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id): # 移除 @login_required 装饰器
    add_log_entry(f"尝试编辑记录，收到的 record_id: {record_id}", "DEBUG")
    record_to_edit = next((r for r in DDNS_RECORDS if r["id"] == record_id), None)
    
    if not record_to_edit:
        add_log_entry(f"编辑失败: 未找到 ID 为 '{record_id}' 的记录。当前 DDNS_RECORDS: {DDNS_RECORDS}", "ERROR")
        flash("未找到指定记录！请尝试刷新页面。", "error")
        return redirect(url_for('records_management'))

    if request.method == 'POST':
        new_record_name = request.form['name'].strip()
        new_record_type = request.form['type'].strip().upper()
        
        if any(r['id'] != record_id and r['name'].lower() == new_record_name.lower() and r['type'] == new_record_type for r in DDNS_RECORDS):
            flash(f"不能修改为已存在的记录名和类型组合: '{new_record_name}' ({new_record_type})。", "error")
            return render_template('record_form.html', record=record_to_edit, form_title=f"编辑记录: {record_to_edit['name']}", username=session.get('username', '访客'))

        record_to_edit['name'] = new_record_name
        record_to_edit['type'] = new_record_type
        record_to_edit['proxied'] = 'proxied' in request.form
        record_to_edit['ttl'] = int(request.form.get('ttl', 120))
        record_to_edit['enabled'] = 'enabled' in request.form

        if not record_to_edit['name'] or not record_to_edit['type']:
            flash("记录名和类型不能为空！", "error")
            return render_template('record_form.html', record=record_to_edit, form_title="编辑记录", username=session.get('username', '访客'))
        
        if record_to_edit['type'] not in ["A", "AAAA"]:
            flash("记录类型只能是 A 或 AAAA！", "error")
            return render_template('record_form.html', record=record_to_edit, form_title="编辑记录", username=session.get('username', '访客'))

        save_ddns_records() 

        _sync_app_status_records_display()

        flash(f"记录 '{record_to_edit['name']}' 已成功更新！", "success")
        return redirect(url_for('records_management')) 
    
    return render_template('record_form.html', record=record_to_edit, form_title=f"编辑记录: {record_to_edit['name']}", username=session.get('username', '访客'))

# --- 删除 DDNS 记录 ---
@flask_app.route('/records/delete/<record_id>', methods=['POST'])
def delete_record(record_id): # 移除 @login_required 装饰器
    global DDNS_RECORDS
    add_log_entry(f"尝试删除记录，收到的 record_id: {record_id}", "DEBUG")
    original_len = len(DDNS_RECORDS)
    DDNS_RECORDS = [r for r in DDNS_RECORDS if r["id"] != record_id]
    
    if len(DDNS_RECORDS) < original_len:
        save_ddns_records() 

        _sync_app_status_records_display()

        flash("记录已成功删除。", "success")
    else:
        add_log_entry(f"删除失败: 未找到 ID 为 '{record_id}' 的记录。当前 DDNS_RECORDS: {DDNS_RECORDS}", "ERROR")
        flash("未找到要删除的记录。", "error")
    return redirect(url_for('records_management')) 

# --- 切换单条记录的启用/禁用状态 ---
@flask_app.route('/records/toggle/<record_id>', methods=['POST'])
def toggle_record(record_id): # 移除 @login_required 装饰器
    add_log_entry(f"尝试切换记录状态，收到的 record_id: {record_id}", "DEBUG")
    record_to_toggle = next((r for r in DDNS_RECORDS if r["id"] == record_id), None)
    
    if record_to_toggle:
        record_to_toggle['enabled'] = not record_to_toggle['enabled']
        save_ddns_records() 

        _sync_app_status_records_display()

        flash(f"记录 '{record_to_toggle['name']}' 已{'启用' if record_to_toggle['enabled'] else '禁用'}。", "success")
    else:
        add_log_entry(f"切换状态失败: 未找到 ID 为 '{record_id}' 的记录。当前 DDNS_RECORDS: {DDNS_RECORDS}", "ERROR")
        flash("未找到指定记录以切换状态。", "error")
    return redirect(url_for('records_management')) 

# --- 管理员账户设置 ---
@flask_app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings(): # 移除 @login_required 装饰器
    admin_creds = load_admin_credentials() # 确保在处理 POST 前加载
    if not admin_creds: 
        flash("管理员账户信息缺失，无法进行设置。", "error")
        return redirect(url_for('index'))

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'password_change':
            old_password = request.form.get('old_password', '').strip()
            new_password = request.form.get('new_password', '').strip()
            confirm_new_password = request.form.get('confirm_new_password', '').strip()

            # 密码修改逻辑
            if not old_password and (new_password or confirm_new_password):
                flash("如需修改密码，请输入当前密码。", "error")
            elif old_password: # 只有输入了旧密码才尝试修改
                if not check_password_hash(admin_creds["password_hash"], old_password):
                    flash("当前密码不正确。", "error")
                elif not new_password and not confirm_new_password:
                    flash("未输入新密码，密码未更改。", "info") # 用户可能只是点了保存按钮
                elif not new_password or not confirm_new_password:
                    flash("新密码和确认密码均不能为空以进行修改。", "error")
                elif new_password != confirm_new_password:
                    flash("新密码和确认密码不一致。", "error")
                elif len(new_password) < 6:
                    flash("新密码长度至少为6个字符。", "error")
                else:
                    new_hashed_password = generate_password_hash(new_password)
                    if save_admin_credentials(admin_creds["username"], new_hashed_password):
                        flash("管理员密码已成功修改！请使用新密码重新登录。", "success")
                        add_log_entry(f"管理员 '{session.get('username')}' 成功修改密码。", "INFO")
                        session.pop('logged_in', None) 
                        session.pop('username', None)
                        return redirect(url_for('login'))
                    else:
                        flash("修改密码时发生错误，请检查日志。", "error")
                        add_log_entry("修改管理员密码失败。", "ERROR")
            # 如果旧密码为空且新密码也为空，则不执行任何操作，避免不必要的 flash 消息

        elif form_type == 'api_config_change':
            new_api_token = request.form.get('cf_api_token', '').strip()
            new_zone_id = request.form.get('cf_zone_id', '').strip()

            if not new_api_token or not new_zone_id:
                flash("API Token 和 Zone ID 均不能为空！", "error")
            else:
                # 只有当值发生变化时才记录日志和显示成功消息
                token_changed = GLOBAL_CONFIG["CF_API_TOKEN"] != new_api_token
                zone_id_changed = GLOBAL_CONFIG["CF_ZONE_ID"] != new_zone_id

                if token_changed or zone_id_changed:
                    GLOBAL_CONFIG["CF_API_TOKEN"] = new_api_token
                    GLOBAL_CONFIG["CF_ZONE_ID"] = new_zone_id
                    save_global_config() # 保存到 config.ini
                    
                    log_messages = []
                    if token_changed:
                        log_messages.append("API Token 已更新")
                        add_log_entry("Cloudflare API Token 已通过管理员设置更新。", "INFO")
                    if zone_id_changed:
                        log_messages.append("Zone ID 已更新")
                        add_log_entry("Cloudflare Zone ID 已通过管理员设置更新。", "INFO")
                    
                    flash(f"Cloudflare API 设置已成功更新 ({', '.join(log_messages)})！DDNS将使用新配置。", "success")
                    # 触发一次 DDNS 更新检查，以便立即验证新配置（可选）
                    # run_ddns_update_job(manual_trigger=True) 
                else:
                    flash("API 设置未发生变化。", "info")
        
        else:
            flash("无效的表单提交。", "error")

        # 重新渲染页面，保留用户输入或显示错误/成功消息
        # 为 API 表单准备当前配置的掩码 Token
        masked_token = ""
        if GLOBAL_CONFIG["CF_API_TOKEN"]:
            token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
            if token_len > 8:
                 masked_token = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:]
            else:
                 masked_token = "****" # 如果太短，就全掩盖
        
        current_display_config = GLOBAL_CONFIG.copy()
        current_display_config["CF_API_TOKEN"] = masked_token

        return render_template('admin_settings.html', username=session.get('username', '访客'), current_config=current_display_config)

    # GET 请求
    # 为 API 表单准备当前配置的掩码 Token
    masked_token = ""
    if GLOBAL_CONFIG["CF_API_TOKEN"]:
        token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
        if token_len > 8:
                masked_token = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:]
        else:
                masked_token = "****" 
    
    current_display_config = GLOBAL_CONFIG.copy()
    current_display_config["CF_API_TOKEN"] = masked_token

    return render_template('admin_settings.html', username=session.get('username', '访客'), current_config=current_display_config)


# --- 主程序和调度器 ---
if __name__ == '__main__':
    # 将所有初始化逻辑直接放置在 if __name__ == '__main__': 块中
    # 这样可以确保它们在应用启动时（当脚本被直接运行时）只执行一次
    
    # 1. 加载所有配置（包括管理员凭证），确保 ADMIN_ACCOUNT_SET 状态正确
    load_all_config() 
    
    # 2. 执行首次DDNS更新检查，填充初始状态
    run_ddns_update_job() 

    # 3. 设置并启动后台调度器
    scheduler = BackgroundScheduler(daemon=True)
    if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
        scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
        scheduler.start()
        add_log_entry(f"DDNS 自动更新任务已设置，每 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟运行一次。")
    else:
        add_log_entry("DDNS 自动更新间隔设置为0或无效，将不会自动运行。", "WARNING")

    try:
        add_log_entry("启动 Flask Web 服务器...")
        # 生产环境中 debug=False
        flask_app.run(host='0.0.0.0', port=5000, debug=False) 
    except (KeyboardInterrupt, SystemExit):
        # 确保调度器在应用关闭时被正确关闭
        if 'scheduler' in globals() and scheduler.running:
            scheduler.shutdown()
        add_log_entry("DDNS 应用已关闭。")