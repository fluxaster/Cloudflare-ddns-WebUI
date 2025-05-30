import os
import subprocess
import configparser
import re
import json 
import uuid 
import requests
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session 
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
import concurrent.futures # Added for parallelism

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
MAX_PARALLEL_WORKERS = 5 # Configurable number of parallel workers for DDNS tasks

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
ADMIN_ACCOUNT_SET = False 

def load_admin_credentials():
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

def ensure_record_fields(record):
    """确保DDNS记录包含所有必要字段"""
    record.setdefault("id", str(uuid.uuid4()))
    record.setdefault("name", "")
    record.setdefault("type", "A")
    record.setdefault("proxied", False) # Cloudflare proxy status
    record.setdefault("ttl", 120)
    record.setdefault("enabled", True)
    # Origin Rule fields
    record.setdefault("origin_rule_enabled", False)
    record.setdefault("origin_rule_destination_port", None) # 目标内部端口
    record.setdefault("origin_rule_id", None) 
    record.setdefault("origin_rule_description", "") 
    return record

def save_ddns_records():
    records_file_path = 'records.json'
    try:
        # Ensure all records have all fields before saving, especially after updates
        updated_records = [ensure_record_fields(dict(r)) for r in DDNS_RECORDS] 
        with open(records_file_path, 'w', encoding='utf-8') as f:
            json.dump(updated_records, f, indent=4, ensure_ascii=False)
        add_log_entry(f"已成功保存 {len(updated_records)} 条 DDNS 记录到 {records_file_path}。", "INFO")
    except Exception as e:
        add_log_entry(f"保存 DDNS 记录到 {records_file_path} 失败: {e}", "ERROR")


def save_global_config():
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
    new_records_status = []
    old_records_status_map = {rs["id"]: rs for rs in app_status.get("records_status", [])}

    for record_conf_orig in DDNS_RECORDS:
        # Ensure we are working with a full copy from the global DDNS_RECORDS for display logic
        record_conf = ensure_record_fields(dict(record_conf_orig)) 
        record_id = record_conf["id"]
        
        current_record_status = {
            "id": record_id,
            "name": record_conf["name"],
            "type": record_conf["type"],
            "proxied": record_conf["proxied"], 
            "ttl": record_conf["ttl"],
            "enabled": record_conf["enabled"],
            "local_ip": "N/A",  
            "cloudflare_ip": "N/A", 
            "last_updated_cloudflare": "N/A", 
            "message": "待检查...",
            "origin_rule_enabled": record_conf["origin_rule_enabled"],
            "origin_rule_destination_port": record_conf["origin_rule_destination_port"],
            "origin_rule_id": record_conf["origin_rule_id"],
            "origin_rule_status_display": "禁用" 
        }
        
        if record_conf["origin_rule_enabled"] and record_conf["origin_rule_destination_port"]:
            if record_conf["origin_rule_id"]:
                 current_record_status["origin_rule_status_display"] = f"已启用 -> {record_conf['origin_rule_destination_port']} (ID: ...{str(record_conf['origin_rule_id'])[-6:]})"
            else:
                 current_record_status["origin_rule_status_display"] = f"启用中 (待创建/同步) -> {record_conf['origin_rule_destination_port']}"
        elif record_conf["origin_rule_enabled"]:
             current_record_status["origin_rule_status_display"] = "配置不完整"


        if record_id in old_records_status_map:
            old_status = old_records_status_map[record_id]
            # Preserve status from previous run if type hasn't changed and it's not a placeholder message
            if old_status.get("type") == record_conf["type"] and old_status.get("message") not in ["待检查...", "此记录已禁用。", f"类型已更改为 {record_conf['type']}，待检查..."]:
                current_record_status["local_ip"] = old_status.get("local_ip", "N/A")
                current_record_status["cloudflare_ip"] = old_status.get("cloudflare_ip", "N/A")
                current_record_status["last_updated_cloudflare"] = old_status.get("last_updated_cloudflare", "N/A")
                current_record_status["message"] = old_status.get("message", "待检查...")
            elif old_status.get("type") != record_conf["type"]:
                current_record_status["message"] = f"类型已更改为 {record_conf['type']}，待检查..."
        
        if not record_conf["enabled"]:
            current_record_status["message"] = "此记录已禁用。"
        # If message was "此记录已禁用." but record is now enabled, reset message.
        elif current_record_status["message"] == "此记录已禁用." and record_conf["enabled"]: 
             current_record_status["message"] = "已启用，待检查..."


        new_records_status.append(current_record_status)
    
    app_status["records_status"] = new_records_status
    add_log_entry("已同步应用状态中的记录显示信息。", "DEBUG")


def load_all_config():
    global GLOBAL_CONFIG, DDNS_RECORDS

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

    records_file_path = 'records.json'
    temp_records = []
    if os.path.exists(records_file_path):
        try:
            with open(records_file_path, 'r', encoding='utf-8') as f:
                loaded_records = json.load(f)
            
            needs_save_due_to_schema_change = False
            for record_data in loaded_records:
                if isinstance(record_data, dict):
                    # Check for and remove the old 'origin_rule_cloudflare_port' if it exists
                    if "origin_rule_cloudflare_port" in record_data:
                        del record_data["origin_rule_cloudflare_port"]
                        needs_save_due_to_schema_change = True
                    
                    # Ensure all other fields are present
                    processed_record = ensure_record_fields(dict(record_data))
                    temp_records.append(processed_record)
                else:
                    add_log_entry(f"发现非字典类型的记录数据: {record_data}，已跳过。", "WARNING")

            DDNS_RECORDS = temp_records 
            
            if needs_save_due_to_schema_change:
                add_log_entry("检测到旧的 'origin_rule_cloudflare_port' 字段，已移除并准备重新保存 records.json。", "INFO")
                save_ddns_records() # Save back if schema changed

            add_log_entry(f"已成功从 {records_file_path} 加载和处理 {len(DDNS_RECORDS)} 条 DDNS 记录。", "INFO")
        except json.JSONDecodeError as e:
            add_log_entry(f"解析 {records_file_path} 出错: {e}。请检查JSON格式。", "ERROR")
            DDNS_RECORDS = []
        except Exception as e:
            add_log_entry(f"读取 {records_file_path} 时发生未知错误: {e}", "ERROR")
            DDNS_RECORDS = []
    else:
        add_log_entry(f"records.json 文件未找到。将以空记录列表启动。", "WARNING")
        DDNS_RECORDS = []

    load_admin_credentials()

    if not GLOBAL_CONFIG["CF_API_TOKEN"] or not GLOBAL_CONFIG["CF_ZONE_ID"]:
        add_log_entry("警告: Cloudflare API Token 或 Zone ID 未能成功加载。DDNS 功能将无法正常工作。", "ERROR")
        GLOBAL_CONFIG["CF_API_TOKEN"] = ""
        GLOBAL_CONFIG["CF_ZONE_ID"] = ""

    add_log_entry(f"最终加载的 Cloudflare API Token (部分显示): {GLOBAL_CONFIG['CF_API_TOKEN'][:8]}...", "DEBUG")
    add_log_entry(f"最终加载的 Cloudflare Zone ID: {GLOBAL_CONFIG['CF_ZONE_ID']}", "DEBUG")
    _sync_app_status_records_display() 


# --- DDNS 核心功能 ---
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
        "https://api.ipify.org?format=json", "https://ipv4.icanhazip.com/",
        "http://whatismyip.akamai.com/", "http://ipinfo.io/ip"
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
                except json.JSONDecodeError: ipv4 = None
            else: ipv4 = content
            if ipv4 and re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ipv4):
                add_log_entry(f"成功获取到公网 IPv4 地址: {ipv4} (来自 {url})", "INFO")
                return ipv4
            else: add_log_entry(f"从 {url} 获取到的内容 '{content}' 不是有效的 IPv4 地址。", "WARNING")
        except requests.exceptions.RequestException as e: add_log_entry(f"从 {url} 获取 IPv4 失败: {e}", "WARNING")
        except Exception as e: add_log_entry(f"获取 IPv4 时发生未知错误: {e}", "WARNING")
    add_log_entry("未能获取到有效的公网 IPv4 地址。", "ERROR")
    return None

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"

def _cf_api_request(method, endpoint, data=None, params=None):
    if not GLOBAL_CONFIG['CF_API_TOKEN'] or not GLOBAL_CONFIG['CF_ZONE_ID']:
        add_log_entry("Cloudflare API Token 或 Zone ID 未配置，无法执行API请求。", "ERROR")
        return None
    headers = {
        "Authorization": f"Bearer {GLOBAL_CONFIG['CF_API_TOKEN']}",
        "Content-Type": "application/json"
    }
    url = f"{CLOUDFLARE_API_BASE_URL}{endpoint}"
    try:
        response = requests.request(method, url, headers=headers, json=data, params=params, timeout=20) 
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_message = f"Cloudflare API 请求失败 ({method} {url}): {e}"
        detailed_error = ""
        if hasattr(e, 'response') and e.response is not None:
            try: 
                detailed_error = e.response.json()
                error_message += f" - API 错误详情: {detailed_error}"
            except ValueError: 
                detailed_error = e.response.text
                error_message += f" - API 错误详情 (非JSON): {detailed_error}"
        add_log_entry(error_message, "ERROR")
        # Attempt to return the error details for more context if needed
        if detailed_error:
             # Create a mock error response structure if needed by caller
            return {"success": False, "errors": detailed_error if isinstance(detailed_error, list) else [{"message": str(detailed_error)}]}
        return None


def _get_cloudflare_dns_record(record_name, record_type):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records"
    params = {"type": record_type, "name": record_name}
    data = _cf_api_request("GET", endpoint, params=params)
    if data and data.get("success"):
        if data["result"]:
            record = data["result"][0]
            add_log_entry(f"Cloudflare 记录 '{record_name}' ({record_type}) 当前 IP: {record['content']}, ID: {record['id']}, Proxied: {record.get('proxied', False)}", "DEBUG")
            return record 
        else:
            add_log_entry(f"在 Cloudflare 上未找到名为 '{record_name}' 的 {record_type} 记录。", "INFO") 
            return None 
    else:
        add_log_entry(f"从 Cloudflare 获取 DNS 记录 '{record_name}' ({record_type}) 失败。", "ERROR")
        return None 

def _delete_cloudflare_dns_record(record_cf_id):
    if not record_cf_id:
        add_log_entry("尝试删除 Cloudflare DNS 记录，但未提供记录 ID。", "ERROR")
        return False
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records/{record_cf_id}"
    add_log_entry(f"正在删除 Cloudflare DNS 记录 ID: {record_cf_id}...", "DEBUG")
    api_response = _cf_api_request("DELETE", endpoint)
    if api_response and api_response.get("success"):
        add_log_entry(f"成功删除 Cloudflare DNS 记录 ID: {record_cf_id}。", "INFO")
        return True
    else:
        add_log_entry(f"删除 Cloudflare DNS 记录 ID: {record_cf_id} 失败。", "ERROR")
        if api_response and "errors" in api_response:
            for error in api_response.get("errors", []):
                add_log_entry(f"CF API Error: Code {error.get('code')} - {error.get('message')}", "ERROR")
        return False

def _update_cloudflare_dns_record(record_id, record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records/{record_id}"
    payload = {"type": record_type, "name": record_name, "content": current_ip, "ttl": ttl, "proxied": proxied}
    add_log_entry(f"正在更新 Cloudflare 记录 '{record_name}' (ID: {record_id}) 指向 '{current_ip}', 代理: {proxied}...", "DEBUG")
    data = _cf_api_request("PUT", endpoint, data=payload)
    if data and data.get("success"):
        add_log_entry(f"成功更新 Cloudflare 记录 '{record_name}' 为 '{current_ip}', 代理: {proxied}。", "INFO")
        return True
    else:
        add_log_entry(f"更新 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

def _create_cloudflare_dns_record(record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records"
    payload = {"type": record_type, "name": record_name, "content": current_ip, "ttl": ttl, "proxied": proxied}
    add_log_entry(f"正在创建新的 Cloudflare 记录 '{record_name}' ({record_type}) 指向 '{current_ip}', 代理: {proxied}...", "DEBUG")
    data = _cf_api_request("POST", endpoint, data=payload)
    if data and data.get("success"):
        add_log_entry(f"成功创建 Cloudflare 记录 '{record_name}' 指向 '{current_ip}', 代理: {proxied}。", "INFO")
        # Return the created record's ID if needed by caller, though not used currently
        return data.get("result", {}).get("id") if data.get("result") else True
    else:
        add_log_entry(f"创建 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

# --- Cloudflare Origin Rules Functions ---
ORIGIN_RULESET_PHASE = "http_request_origin"

def _get_origin_ruleset():
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/rulesets/phases/{ORIGIN_RULESET_PHASE}/entrypoint"
    response = _cf_api_request("GET", endpoint)
    if response and response.get("success") and response.get("result"):
        add_log_entry(f"成功获取 Origin Ruleset (ID: {response['result'].get('id')}, {len(response['result'].get('rules',[]))} rules).", "DEBUG")
        return response["result"] 
    add_log_entry("获取 Origin Ruleset 失败或为空。", "ERROR" if response and not response.get("success") else "WARNING")
    return None 

def _update_origin_ruleset(rules_list, ruleset_description="DDNS Managed Origin Rules"):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/rulesets/phases/{ORIGIN_RULESET_PHASE}/entrypoint"
    payload = {
        "description": ruleset_description, 
        "rules": rules_list
    }
    add_log_entry(f"准备更新 Origin Ruleset，包含 {len(rules_list)} 条规则。", "DEBUG")
    response = _cf_api_request("PUT", endpoint, data=payload)
    if response and response.get("success"):
        add_log_entry("成功更新 Origin Ruleset。", "INFO")
        return response # Return the full response object which includes result
    add_log_entry("更新 Origin Ruleset 失败。", "ERROR")
    return None

def _generate_origin_rule_description(record_name, dest_port, local_record_id):
    short_local_id = str(local_record_id).split('-')[0] 
    return f"ddns_fwd_{record_name}_to{dest_port}_id{short_local_id}" 

# --- BATCH ORIGIN RULE MANAGEMENT ---
def batch_manage_origin_rules(local_records_with_intent):
    """
    Manages Cloudflare Origin Rules in a batch.
    Fetches current ruleset, calculates changes based on local_records_with_intent,
    and applies them with a single API call if changes are needed.
    Returns a tuple: (list_of_updated_local_records, cf_update_attempted_and_succeeded_boolean_or_none)
    The boolean is True if CF update was successful, False if attempted but failed,
    None if a critical pre-flight error occurred (e.g., couldn't get initial ruleset).
    """
    add_log_entry("--- 开始批量 Origin Rule 管理 ---", "INFO")

    if not GLOBAL_CONFIG['CF_API_TOKEN'] or not GLOBAL_CONFIG['CF_ZONE_ID']:
        add_log_entry("Origin Rule 管理: Cloudflare API Token 或 Zone ID 未配置。", "ERROR")
        return local_records_with_intent, None

    current_ruleset_data = _get_origin_ruleset()
    if current_ruleset_data is None:
        add_log_entry("Origin Rule 管理: 获取当前规则集失败。无法继续。", "ERROR")
        # Mark relevant local records as failed for origin rule part
        for rec in local_records_with_intent:
            if rec.get("origin_rule_enabled"):
                rec["origin_rule_id"] = None 
        return local_records_with_intent, None

    current_cf_rules = current_ruleset_data.get("rules", [])
    cf_ruleset_description = current_ruleset_data.get("description", "DDNS Managed Origin Rules")

    # Map existing CF rules for quick lookup
    cf_rules_by_id = {rule["id"]: rule for rule in current_cf_rules if "id" in rule}
    cf_rules_by_desc = {rule["description"]: rule for rule in current_cf_rules if "description" in rule}

    desired_cf_rules_list = [] # This will be the new list of rules to PUT to Cloudflare
    updated_local_records_list = [] # To store final state of local records after this process
    
    any_change_to_cf_ruleset_needed = False # Flag to track if CF PUT is necessary
    any_change_to_local_data = False # Flag if local origin_rule_id/desc changed

    # Pass 1: Process our local records to determine the desired state for managed rules
    active_managed_rule_identifiers_on_cf = set() # Store IDs/descs of CF rules we are actively managing (updating or creating)

    for temp_record_config in local_records_with_intent:
        local_record = dict(temp_record_config) # Work with a copy
        record_name = local_record["name"]
        should_be_enabled = local_record["origin_rule_enabled"]
        dest_port = local_record.get("origin_rule_destination_port")
        # Description is pre-generated if rule is valid & enabled in process_single_record_dns_part
        expected_description = local_record.get("origin_rule_description", "")
        original_local_rule_id = local_record.get("origin_rule_id")
        
        cf_counterpart_rule = None
        if original_local_rule_id and original_local_rule_id in cf_rules_by_id:
            cf_counterpart_rule = cf_rules_by_id[original_local_rule_id]
        elif expected_description and expected_description in cf_rules_by_desc: # Find by description if ID is missing or stale
            cf_counterpart_rule = cf_rules_by_desc[expected_description]
            if cf_counterpart_rule and original_local_rule_id != cf_counterpart_rule["id"]:
                add_log_entry(f"Origin Rule for {record_name} (Desc: {expected_description}): Local ID {original_local_rule_id} was stale or missing, updated to CF ID {cf_counterpart_rule['id']}.", "INFO")
                local_record["origin_rule_id"] = cf_counterpart_rule["id"]
                any_change_to_local_data = True
        
        if cf_counterpart_rule:
            active_managed_rule_identifiers_on_cf.add(cf_counterpart_rule["id"])
            if "description" in cf_counterpart_rule:
                 active_managed_rule_identifiers_on_cf.add(cf_counterpart_rule["description"])


        if should_be_enabled:
            if not record_name or not dest_port or not expected_description:
                add_log_entry(f"Origin Rule for {record_name}: 配置不完整。将禁用并尝试从CF移除规则。", "WARNING")
                local_record["origin_rule_enabled"] = False # Disable locally
                local_record["origin_rule_id"] = None
                any_change_to_local_data = True # local state changed
                if cf_counterpart_rule: # If it existed on CF, it will be marked for removal
                    any_change_to_cf_ruleset_needed = True
            else:
                # Define the rule as it should be on Cloudflare
                rule_definition = {
                    "action": "route",
                    "action_parameters": {"origin": {"port": int(dest_port)}},
                    "expression": f'(http.host eq "{record_name}")',
                    "description": expected_description,
                    "enabled": True
                }
                if cf_counterpart_rule: # We are updating an existing CF rule
                    rule_definition["id"] = cf_counterpart_rule["id"] # Must include ID for update
                    # Check if actual changes are needed compared to cf_counterpart_rule
                    cf_action_params = cf_counterpart_rule.get("action_parameters", {}).get("origin", {})
                    if (cf_counterpart_rule.get("action") != rule_definition["action"] or
                        cf_action_params.get("port") != int(dest_port) or
                        cf_counterpart_rule.get("expression") != rule_definition["expression"] or
                        cf_counterpart_rule.get("description") != rule_definition["description"] or # desc can change if record name changes
                        not cf_counterpart_rule.get("enabled")):
                        add_log_entry(f"Origin Rule (ID: {cf_counterpart_rule['id']}) for {record_name} definition changed. Staging update.", "INFO")
                        desired_cf_rules_list.append(rule_definition)
                        any_change_to_cf_ruleset_needed = True
                    else: # No change to this rule
                        desired_cf_rules_list.append(cf_counterpart_rule) # Add existing CF rule as is
                else: # We are creating a new CF rule
                    add_log_entry(f"Staging new Origin Rule for {record_name} (Desc: {expected_description}).", "INFO")
                    desired_cf_rules_list.append(rule_definition) # No ID, CF will assign
                    any_change_to_cf_ruleset_needed = True
        
        elif not should_be_enabled and cf_counterpart_rule: # Rule is disabled locally and exists on CF
            add_log_entry(f"Origin Rule (ID: {cf_counterpart_rule['id']}) for {record_name} is disabled locally. Staging for removal from CF.", "INFO")
            any_change_to_cf_ruleset_needed = True # Its removal is a change
            if local_record.get("origin_rule_id"): # Clear local ID if it was set
                local_record["origin_rule_id"] = None
                any_change_to_local_data = True
        
        updated_local_records_list.append(local_record)

    # Pass 2: Add back any unmanaged rules from current_cf_rules
    for cf_rule in current_cf_rules:
        cf_id = cf_rule.get("id")
        cf_desc = cf_rule.get("description", "")

        # If this cf_rule's ID or description is in active_managed_rule_identifiers_on_cf,
        # it means we've already processed it (either kept, updated, or decided to create it if it was just by desc).
        # Its desired state is already in desired_cf_rules_list if it's active.
        # If it was managed and then deleted, it's correctly omitted from desired_cf_rules_list.
        
        is_already_part_of_desired_managed_rules = False
        for desired_rule in desired_cf_rules_list:
            if desired_rule.get("id") == cf_id and cf_id is not None: # Matched by ID
                is_already_part_of_desired_managed_rules = True
                break
        
        if not is_already_part_of_desired_managed_rules and not (cf_id in active_managed_rule_identifiers_on_cf or cf_desc in active_managed_rule_identifiers_on_cf) :
             # This rule from CF was not identified as one of ours by ID or by expected description.
             # We consider it an unmanaged rule and preserve it.
            add_log_entry(f"Preserving unmanaged Origin Rule from CF (ID: {cf_id}, Desc: {cf_desc}).", "DEBUG")
            desired_cf_rules_list.append(cf_rule)


    # If no changes were flagged for CF and no local data changed that needs saving, exit early.
    if not any_change_to_cf_ruleset_needed and not any_change_to_local_data:
        add_log_entry("Origin Rule 管理: 未检测到 Cloudflare 规则集或本地记录的 Origin Rule 相关字段需要更改。", "INFO")
        add_log_entry("--- 结束批量 Origin Rule 管理 (无更改) ---", "INFO")
        return updated_local_records_list, False # False = CF not updated

    if not any_change_to_cf_ruleset_needed and any_change_to_local_data:
        add_log_entry("Origin Rule 管理: Cloudflare 规则集无需更改，但本地记录信息已更新 (例如，ID同步)。", "INFO")
        add_log_entry("--- 结束批量 Origin Rule 管理 (本地数据更新) ---", "INFO")
        return updated_local_records_list, False # CF not updated, but caller should save DDNS_RECORDS

    add_log_entry(f"Origin Rule 管理: Cloudflare 规则集将更新为包含 {len(desired_cf_rules_list)} 条规则。", "INFO")
    cf_response = _update_origin_ruleset(desired_cf_rules_list, cf_ruleset_description)

    if cf_response and cf_response.get("success"):
        add_log_entry("Origin Rule 管理: Cloudflare 规则集成功更新。", "INFO")
        # Update local records with new/confirmed IDs from the CF response
        updated_cf_rules_map_by_desc = {
            rule["description"]: rule 
            for rule in cf_response.get("result", {}).get("rules", []) 
            if "description" in rule
        }

        final_local_records_after_cf_sync = []
        for local_rec in updated_local_records_list: # These are records after Pass 1
            record_copy = dict(local_rec)
            if record_copy.get("origin_rule_enabled") and record_copy.get("origin_rule_description"):
                desc_to_find = record_copy["origin_rule_description"]
                if desc_to_find in updated_cf_rules_map_by_desc:
                    new_cf_id = updated_cf_rules_map_by_desc[desc_to_find].get("id")
                    if record_copy.get("origin_rule_id") != new_cf_id:
                        add_log_entry(f"Origin Rule for {record_copy['name']} (Desc: {desc_to_find}): Local ID set/updated to {new_cf_id} post-CF sync.", "DEBUG")
                        record_copy["origin_rule_id"] = new_cf_id
                        any_change_to_local_data = True # Ensure save if ID changed here
                else: # Rule was meant to be active, but not found in CF response by its desc
                    add_log_entry(f"Origin Rule for {record_copy['name']} (Desc: {desc_to_find}): 未能在更新后的规则集中通过描述找到。ID可能丢失或规则创建失败。", "WARNING")
                    record_copy["origin_rule_id"] = None 
            elif not record_copy.get("origin_rule_enabled"): # Ensure ID is None if rule is disabled
                if record_copy.get("origin_rule_id") is not None:
                    record_copy["origin_rule_id"] = None
                    any_change_to_local_data = True
            final_local_records_after_cf_sync.append(record_copy)
        
        add_log_entry("--- 结束批量 Origin Rule 管理 (成功) ---", "INFO")
        return final_local_records_after_cf_sync, True # True = CF updated successfully
    else:
        add_log_entry("Origin Rule 管理: Cloudflare 规则集更新失败。", "ERROR")
        # If CF update failed, local records reflect intent. Mark their IDs as uncertain.
        for rec in updated_local_records_list:
            if rec.get("origin_rule_enabled"):
                rec["origin_rule_id"] = None # Mark as unconfirmed on CF
        add_log_entry("--- 结束批量 Origin Rule 管理 (CF更新失败) ---", "INFO")
        return updated_local_records_list, False # False = CF update failed

# This function is run by each thread in the ThreadPoolExecutor
def _process_single_record_dns_part(record_conf_orig, current_public_ipv4, current_public_ipv6):
    """
    Processes DNS update for a single record and prepares its origin rule intent.
    This function is designed to be run in a separate thread.
    It does NOT interact with the shared Cloudflare Origin Ruleset directly.
    Returns a tuple: (record_status_dict, modified_record_config_dict)
    """
    record_conf = ensure_record_fields(dict(record_conf_orig)) # Work on a copy

    # Initialize status for this record
    record_status = {
        "id": record_conf["id"], "name": record_conf["name"], "type": record_conf["type"],
        "proxied": record_conf["proxied"], "ttl": record_conf["ttl"], "enabled": record_conf["enabled"],
        "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", "message": "",
        "origin_rule_enabled": record_conf["origin_rule_enabled"],
        "origin_rule_destination_port": record_conf["origin_rule_destination_port"],
        "origin_rule_id": record_conf["origin_rule_id"], # Will be updated by batch_manage_origin_rules
        "origin_rule_status_display": "待处理" 
    }

    if not record_conf["enabled"]:
        record_status["message"] = "此记录已禁用。"
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 已禁用，跳过更新。", "INFO")
        return record_status, record_conf

    target_ip = None
    ip_type_for_log = ""
    if record_conf["type"] == "AAAA":
        ip_type_for_log = "IPv6"
        if GLOBAL_CONFIG["ENABLE_IPV6_DDNS"]:
            target_ip = current_public_ipv6
            record_status["local_ip"] = target_ip if target_ip else "获取失败"
        else:
            record_status["message"] = "IPv6 DDNS 已全局禁用。"
    elif record_conf["type"] == "A":
        ip_type_for_log = "IPv4"
        if GLOBAL_CONFIG["ENABLE_IPV4_DDNS"]:
            target_ip = current_public_ipv4
            record_status["local_ip"] = target_ip if target_ip else "获取失败"
        else:
            record_status["message"] = "IPv4 DDNS 已全局禁用。"
    else:
        record_status["message"] = f"不支持的记录类型: {record_conf['type']}"
    
    if record_status["message"]: 
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}): {record_status['message']}", "INFO")
        return record_status, record_conf

    if not target_ip:
        record_status["message"] = f"未能获取当前公网 {ip_type_for_log} 地址。"
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 未能获取目标IP，跳过更新。", "ERROR")
        return record_status, record_conf

    add_log_entry(f"--- 并行处理 DNS 记录: {record_conf['name']} ({record_conf['type']}) ---", "DEBUG")
    
    cf_dns_full_record = _get_cloudflare_dns_record(record_conf["name"], record_conf["type"])
    
    cf_dns_record_id = None
    cloudflare_ip_on_cf = None
    cf_proxied_status_on_cf = None

    if cf_dns_full_record:
        cf_dns_record_id = cf_dns_full_record.get("id")
        cloudflare_ip_on_cf = cf_dns_full_record.get("content")
        cf_proxied_status_on_cf = cf_dns_full_record.get("proxied", False)
    
    record_status["cloudflare_ip"] = cloudflare_ip_on_cf if cloudflare_ip_on_cf else "未找到/失败"

    ip_needs_update = (target_ip != cloudflare_ip_on_cf)
    # Use desired proxied status from local config for comparison
    proxy_needs_update = (record_conf["proxied"] != cf_proxied_status_on_cf if cf_dns_full_record else False) 

    if cf_dns_record_id: # Record exists on Cloudflare
        if not ip_needs_update and not proxy_needs_update:
            record_status["message"] = f"DNS IP ({target_ip}) 及代理状态 ({'启用' if record_conf['proxied'] else '禁用'}) 未更改。"
        else:
            log_msg_parts = []
            if ip_needs_update: log_msg_parts.append(f"IP 地址需更新 (本机: {target_ip}, Cloudflare: {cloudflare_ip_on_cf})")
            if proxy_needs_update: log_msg_parts.append(f"代理状态需更新 (期望: {record_conf['proxied']}, Cloudflare: {cf_proxied_status_on_cf})")
            add_log_entry(f"记录 '{record_conf['name']}': {'; '.join(log_msg_parts)}。", "INFO")

            if _update_cloudflare_dns_record(cf_dns_record_id, record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"]):
                record_status["message"] = f"DNS 更新成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
                record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                record_status["message"] = f"DNS 更新失败。"
    else: # Record does not exist on Cloudflare
        if cloudflare_ip_on_cf is None: # Explicitly means not found from successful API call, rather than API error during fetch
            add_log_entry(f"DNS 记录 '{record_conf['name']}' ({record_conf['type']}) 不存在，尝试创建。", "INFO")
            created_record_id = _create_cloudflare_dns_record(record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"])
            if created_record_id: # Can be True or an ID string
                record_status["message"] = f"DNS 记录创建成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
                record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Note: created_record_id from _create_cloudflare_dns_record isn't stored in local record_conf here.
                # DNS record IDs are not currently tracked locally unlike origin_rule_id.
            else:
                record_status["message"] = f"DNS 记录创建失败。"
        else: # API call to get record failed
             record_status["message"] = "获取 Cloudflare DNS 记录信息失败。"
    
    # Prepare Origin Rule Description Intent (used by batch_manage_origin_rules)
    # This must be done *after* potential record name changes if editing is allowed during this flow (not here)
    if record_conf["origin_rule_enabled"] and record_conf["name"] and record_conf.get("origin_rule_destination_port"):
        record_conf["origin_rule_description"] = _generate_origin_rule_description(
            record_conf["name"], 
            record_conf["origin_rule_destination_port"], 
            record_conf["id"]
        )
    else:
        record_conf["origin_rule_description"] = "" # Ensure it's reset

    add_log_entry(f"--- 并行处理 DNS 记录 {record_conf['name']} ({record_conf['type']}) 完成 ---", "DEBUG")
    return record_status, record_conf


def run_ddns_update_job(manual_trigger=False):
    if app_status["is_running_update"] and not manual_trigger:
        add_log_entry("DDNS 更新任务已在运行中，跳过此次调度。", "DEBUG")
        return

    app_status["is_running_update"] = True
    app_status["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    app_status["status_message"] = "DDNS 更新任务正在运行..."
    add_log_entry("--- 开始 DDNS 更新检查 ---")

    if not GLOBAL_CONFIG["CF_API_TOKEN"] or not GLOBAL_CONFIG["CF_ZONE_ID"]:
        app_status["status_message"] = "错误: Cloudflare API Token 或 Zone ID 未配置。"
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
    
    current_public_ipv6 = None
    if GLOBAL_CONFIG["ENABLE_IPV6_DDNS"]:
        current_public_ipv6 = get_stable_ipv6_windows()
        app_status["current_ipv6"] = current_public_ipv6 if current_public_ipv6 else "获取失败"
    else:
        app_status["current_ipv6"] = "已禁用 (全局)"
    
    if not DDNS_RECORDS:
        app_status["status_message"] = "未配置任何 DDNS 记录。"
        add_log_entry(app_status["status_message"], "WARNING")
        app_status["is_running_update"] = False
        _sync_app_status_records_display() 
        return

    # --- Parallel DNS Processing ---
    # Stores tuples of (index, record_status, modified_record_conf)
    # Initialize with None to detect if a thread failed to return for an index
    processed_dns_data_futures = [None] * len(DDNS_RECORDS) 
    
    # Create a list of copies of DDNS_RECORDS to pass to threads, as ensure_record_fields
    # might be called again inside, and we want to make sure each thread gets a clean copy from the start of the job.
    records_to_process_in_parallel = [dict(r) for r in DDNS_RECORDS]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
        future_to_index = {}
        for i, record_conf_for_thread in enumerate(records_to_process_in_parallel):
            future = executor.submit(_process_single_record_dns_part, record_conf_for_thread, current_public_ipv4, current_public_ipv6)
            future_to_index[future] = i
            
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                record_status_result, modified_record_conf_result = future.result()
                processed_dns_data_futures[index] = (record_status_result, modified_record_conf_result)
            except Exception as e:
                add_log_entry(f"并行处理记录 {records_to_process_in_parallel[index].get('name', 'Unknown')} 时发生严重错误: {e}", "ERROR")
                # Create a fallback error status for this record
                original_record_conf = ensure_record_fields(dict(records_to_process_in_parallel[index]))
                error_status = {
                    "id": original_record_conf["id"], "name": original_record_conf["name"], 
                    "type": original_record_conf["type"], "proxied": original_record_conf["proxied"],
                    "ttl": original_record_conf["ttl"], "enabled": original_record_conf["enabled"],
                    "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", 
                    "message": "并行DNS处理期间发生错误。",
                    "origin_rule_enabled": original_record_conf["origin_rule_enabled"],
                    "origin_rule_destination_port": original_record_conf["origin_rule_destination_port"],
                    "origin_rule_id": original_record_conf["origin_rule_id"],
                    "origin_rule_status_display": "错误"
                }
                processed_dns_data_futures[index] = (error_status, original_record_conf) # Store error status and original conf

    # Collate results from DNS processing
    intermediate_records_status = [] # For app_status["records_status"] before origin rule processing
    local_records_with_dns_updates_and_origin_intent = [] # Input for batch_manage_origin_rules

    for i in range(len(records_to_process_in_parallel)):
        if processed_dns_data_futures[i]:
            status_res, conf_res = processed_dns_data_futures[i]
            intermediate_records_status.append(status_res)
            local_records_with_dns_updates_and_origin_intent.append(conf_res)
        else: # Should not happen if fallback error status is created above, but as a safeguard
            add_log_entry(f"记录 {records_to_process_in_parallel[i].get('name', 'Unknown')} 未收到并行处理结果。", "WARNING")
            original_record_conf = ensure_record_fields(dict(records_to_process_in_parallel[i]))
            error_status = {
                "id": original_record_conf["id"], "name": original_record_conf["name"], "type": original_record_conf["type"],
                "proxied": original_record_conf["proxied"], "ttl": original_record_conf["ttl"], "enabled": original_record_conf["enabled"],
                "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", 
                "message": "未收到并行处理结果。",
                "origin_rule_enabled": original_record_conf["origin_rule_enabled"],
                "origin_rule_destination_port": original_record_conf["origin_rule_destination_port"],
                "origin_rule_id": original_record_conf["origin_rule_id"],
                "origin_rule_status_display": "错误"
            }
            intermediate_records_status.append(error_status)
            local_records_with_dns_updates_and_origin_intent.append(original_record_conf)

    app_status["records_status"] = intermediate_records_status # Update with DNS processing status

    # --- Sequential Batch Origin Rule Management ---
    final_ddns_records_after_origin_rules, cf_origin_rules_put_success = batch_manage_origin_rules(
        local_records_with_dns_updates_and_origin_intent
    )
    
    # Update the global DDNS_RECORDS list with the final state after all operations
    DDNS_RECORDS[:] = final_ddns_records_after_origin_rules

    # Determine if the local DDNS_RECORDS.json file needs saving
    needs_records_save = False
    # Check if origin rule related fields changed in any record compared to its state *before* batch_manage_origin_rules
    for i_idx, record_before_origin_batch in enumerate(local_records_with_dns_updates_and_origin_intent):
        record_after_origin_batch = final_ddns_records_after_origin_rules[i_idx]
        if (record_before_origin_batch.get("origin_rule_id") != record_after_origin_batch.get("origin_rule_id") or
            record_before_origin_batch.get("origin_rule_description") != record_after_origin_batch.get("origin_rule_description") or
            record_before_origin_batch.get("origin_rule_enabled") != record_after_origin_batch.get("origin_rule_enabled")):
            needs_records_save = True
            break
    
    if cf_origin_rules_put_success: # True means CF was updated, new IDs could be assigned or changes confirmed
        needs_records_save = True
    
    if cf_origin_rules_put_success is None: # Critical failure during origin rule batch (e.g. couldn't get ruleset)
        add_log_entry("由于 Origin Rule 管理器发生严重故障，记录文件可能不会保存最新的 Origin Rule ID。", "ERROR")
        # In this case, needs_records_save might still be true if local_records_with_dns_updates_and_origin_intent
        # had changes to origin_rule_enabled that batch_manage_origin_rules persisted before returning None.

    if needs_records_save:
        add_log_entry("检测到记录的 Origin Rule 相关信息已更改，将保存 DDNS 记录文件。", "INFO")
        save_ddns_records()

    # Sync app_status["records_status"] one last time with the absolute final state from DDNS_RECORDS
    _sync_app_status_records_display()

    app_status["status_message"] = "DDNS 更新检查完成。"
    add_log_entry("--- DDNS 更新检查结束 ---")
    app_status["is_running_update"] = False


# --- Flask Web 应用 ---
flask_app = Flask(__name__)
flask_app.secret_key = os.urandom(24) 

@flask_app.before_request
def check_authentication():
    if request.endpoint in ['setup_admin', 'login', 'static']:
        return None
    if not ADMIN_ACCOUNT_SET:
        flash("请先设置管理员账户。", "warning")
        return redirect(url_for('setup_admin'))
    if 'logged_in' not in session:
        flash("请先登录以访问此页面。", "warning")
        return redirect(url_for('login'))
    return None

@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session: return redirect(url_for('index')) 
    admin_creds = load_admin_credentials()
    if not ADMIN_ACCOUNT_SET: return redirect(url_for('setup_admin')) 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == admin_creds["username"] and check_password_hash(admin_creds["password_hash"], password):
            session['logged_in'] = True
            session['username'] = username
            flash(f"欢迎回来！{username}！", "success")
            add_log_entry(f"用户 '{username}' 成功登录。", "INFO")
            return redirect(url_for('index'))
        else:
            flash("用户名或密码不正确。", "error")
            add_log_entry(f"用户尝试登录失败，用户名: {username}", "WARNING")
    return render_template('login.html')

@flask_app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash("您已成功登出。", "info")
    add_log_entry("用户已登出。", "INFO")
    return redirect(url_for('login'))

@flask_app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    if ADMIN_ACCOUNT_SET and 'logged_in' not in session : # If set, but not logged in, redirect to login
        if request.method == 'GET': # Allow setup page if directly navigated to and admin not set
             flash("管理员账户已设置，请登录。", "info")
        return redirect(url_for('login'))
    if ADMIN_ACCOUNT_SET and 'logged_in' in session: # If set and logged in, no need to setup
        flash("管理员账户已设置。", "info")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if not username or not password or not confirm_password:
            flash("用户名和密码都不能为空！", "error")
        elif password != confirm_password: flash("两次输入的密码不一致！", "error")
        elif len(password) < 6: flash("密码长度至少为6个字符。", "error")
        else:
            hashed_password = generate_password_hash(password)
            if save_admin_credentials(username, hashed_password):
                flash("管理员账户设置成功！请登录。", "success")
                add_log_entry(f"管理员账户 '{username}' 首次设置成功。", "INFO")
                return redirect(url_for('login'))
            else:
                flash("保存管理员账户时发生错误。", "error")
                add_log_entry("保存管理员账户失败。", "ERROR")
    return render_template('setup_admin.html')


@flask_app.route('/')
def index():
    # Ensure status is fresh if a job just ran or on first load
    # _sync_app_status_records_display() # Usually handled by job end or specific views
    status_snapshot = {key: list(val) if isinstance(val, list) else val for key, val in app_status.items()}
    return render_template('index.html', status=status_snapshot, username=session.get('username', '访客'))

@flask_app.route('/trigger_update', methods=['POST'])
def trigger_update():
    add_log_entry("收到手动更新请求。")
    if app_status["is_running_update"]:
        flash("更新任务已在运行中，请稍候。", "warning")
    else:
        # Run job in a new thread to avoid blocking the request, 
        # although run_ddns_update_job itself is now more internally parallel.
        # For long running tasks triggered by HTTP, it's better practice.
        # However, current BackgroundScheduler also runs it in a thread.
        # For simplicity, direct call is okay if user expects to wait for completion signal.
        # Let's make it non-blocking for the web request immediately.
        
        # Using a simple threading model here for the manual trigger
        # so the web request returns immediately.
        manual_update_thread = threading.Thread(target=run_ddns_update_job, kwargs={'manual_trigger': True})
        manual_update_thread.start()
        flash("DDNS 更新检查已触发！状态将在稍后更新。", "success")
    return redirect(url_for('index'))

@flask_app.route('/status_json')
def status_json(): 
    # Make a deep copy for thread safety if complex objects are involved, though current app_status is mostly basic types or thread-safe list ops
    status_copy = {key: list(val) if isinstance(val, list) else val for key, val in app_status.items()}
    return jsonify(status_copy)


@flask_app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            new_interval_str = request.form.get('interval')
            new_interval = GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] # Default to current
            if new_interval_str and new_interval_str.isdigit():
                parsed_interval = int(new_interval_str)
                if parsed_interval > 0:
                    new_interval = parsed_interval
                else:
                    flash("检查间隔必须是大于0的有效整数！旧值将保留。", "error")
            else:
                 flash("检查间隔格式无效！旧值将保留。", "error")

            GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] = new_interval
            GLOBAL_CONFIG["ENABLE_IPV4_DDNS"] = 'enable_ipv4' in request.form
            GLOBAL_CONFIG["ENABLE_IPV6_DDNS"] = 'enable_ipv6' in request.form
            GLOBAL_CONFIG["DDNS_INTERFACE_NAME"] = request.form.get('interface_name', '').strip()
            save_global_config() 
            
            global scheduler 
            if scheduler.running: 
                scheduler.shutdown(wait=False) # wait=False to allow immediate reinitialization
            
            scheduler = BackgroundScheduler(daemon=True) 
            if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
                scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"], id="ddns_job", replace_existing=True)
                if not scheduler.running: # Ensure scheduler starts if not already
                    scheduler.start()
                add_log_entry(f"DDNS 自动更新任务间隔已更新为 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟并已调度。", "INFO")
            else: 
                add_log_entry("DDNS 自动更新间隔设置为0或无效，任务未调度。", "WARNING")
            
            flash("全局设置已成功更新！", "success")
        except Exception as e:
            add_log_entry(f"保存设置或重置调度器时发生错误: {e}", "ERROR")
            flash(f"保存设置时发生错误: {e}", "error")
        return redirect(url_for('settings'))
    return render_template('settings.html', config=GLOBAL_CONFIG, username=session.get('username', '访客'))

@flask_app.route('/records', methods=['GET'])
def records_management():
    # Refresh display based on current DDNS_RECORDS state, especially if coming from a form.
    # The periodic status_json update will handle live updates.
    _sync_app_status_records_display() 
    return render_template('records_management.html', records=app_status["records_status"], username=session.get('username', '访客'))

@flask_app.route('/records/add', methods=['GET', 'POST'])
def add_record():
    if request.method == 'POST':
        record_name = request.form['name'].strip()
        record_type = request.form['type'].strip().upper()

        # Validation
        if not record_name or not record_type:
            flash("记录名和类型不能为空！", "error")
            return render_template('record_form.html', record=request.form, form_title="添加新记录", username=session.get('username', '访客'))
        if record_type not in ["A", "AAAA"]:
            flash("记录类型只能是 A 或 AAAA！", "error")
            return render_template('record_form.html', record=request.form, form_title="添加新记录", username=session.get('username', '访客'))
        if any(r['name'].lower() == record_name.lower() and r['type'] == record_type for r in DDNS_RECORDS):
            flash(f"已存在同名同类型的记录: '{record_name}' ({record_type})。", "error")
            return render_template('record_form.html', record=request.form, form_title="添加新记录", username=session.get('username', '访客'))

        new_record_data = {
            "name": record_name, "type": record_type,
            "proxied": 'proxied' in request.form,
            "ttl": int(request.form.get('ttl', 120)),
            "enabled": 'enabled' in request.form, # Default to enabled if not submitted is fine via ensure_record_fields
            "origin_rule_enabled": 'origin_rule_enabled' in request.form,
            "origin_rule_destination_port": request.form.get('origin_rule_destination_port'),
        }

        # Validate origin rule port if enabled
        if new_record_data["origin_rule_enabled"]:
            dest_port_str = new_record_data["origin_rule_destination_port"]
            if not (dest_port_str and dest_port_str.isdigit() and 1 <= int(dest_port_str) <= 65535): 
                flash("启用端口转发时，目标内部端口必须是1-65535之间的有效数字。", "error")
                return render_template('record_form.html', record=new_record_data, form_title="添加新记录", username=session.get('username', '访客'))
            new_record_data["origin_rule_destination_port"] = int(dest_port_str)
        else: 
            new_record_data["origin_rule_destination_port"] = None # Ensure it's None if not enabled

        new_record_filled = ensure_record_fields(new_record_data) 
        
        # Generate description if origin rule is enabled and valid
        if new_record_filled["origin_rule_enabled"] and new_record_filled["name"] and new_record_filled["origin_rule_destination_port"]:
            new_record_filled["origin_rule_description"] = _generate_origin_rule_description(
                new_record_filled["name"], 
                new_record_filled["origin_rule_destination_port"], 
                new_record_filled["id"]
            )
        
        # Temporarily add to DDNS_RECORDS to be picked up by a batch operation.
        # The actual CF rule creation will happen in the next run_ddns_update_job or manual trigger.
        DDNS_RECORDS.append(new_record_filled)
        save_ddns_records() 
        _sync_app_status_records_display() 
        flash(f"记录 '{new_record_filled['name']}' 已成功添加！更改将在下次DDNS检查时同步到Cloudflare。", "success")
        # Optionally, trigger an update job here if immediate effect is desired.
        # threading.Thread(target=run_ddns_update_job, kwargs={'manual_trigger': True}).start()
        return redirect(url_for('records_management')) 
    
    return render_template('record_form.html', record=ensure_record_fields({}), form_title="添加新记录", username=session.get('username', '访客'))

@flask_app.route('/records/edit/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    record_to_edit_orig = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
    if not record_to_edit_orig:
        flash("未找到指定记录！", "error")
        return redirect(url_for('records_management'))
    
    record_to_edit = ensure_record_fields(dict(record_to_edit_orig)) # Work with a full copy

    if request.method == 'POST':
        original_name = record_to_edit['name']
        new_record_name = request.form['name'].strip()
        # Type is not editable, keep original
        new_record_type = record_to_edit['type'] 

        if not new_record_name:
            flash("记录名不能为空！", "error")
            # Pass back current form values for re-population
            form_data_on_error = dict(record_to_edit) # Start with existing DB state
            form_data_on_error.update(request.form.to_dict()) # Overlay with submitted form data
            form_data_on_error['proxied'] = 'proxied' in request.form # Ensure bools
            form_data_on_error['enabled'] = 'enabled' in request.form
            form_data_on_error['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
            return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))


        if new_record_name.lower() != original_name.lower() and \
           any(r['id'] != record_id and r['name'].lower() == new_record_name.lower() and r['type'] == new_record_type for r in DDNS_RECORDS):
            flash(f"不能修改为已存在的记录名和类型组合: '{new_record_name}' ({new_record_type})。", "error")
            form_data_on_error = dict(record_to_edit)
            form_data_on_error.update(request.form.to_dict())
            form_data_on_error['proxied'] = 'proxied' in request.form
            form_data_on_error['enabled'] = 'enabled' in request.form
            form_data_on_error['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
            return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))

        # Update fields
        record_to_edit['name'] = new_record_name
        record_to_edit['proxied'] = 'proxied' in request.form
        record_to_edit['ttl'] = int(request.form.get('ttl', 120))
        record_to_edit['enabled'] = 'enabled' in request.form
        
        record_to_edit['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
        dest_port_str = request.form.get('origin_rule_destination_port')

        if record_to_edit['origin_rule_enabled']:
            if not (dest_port_str and dest_port_str.isdigit() and 1 <= int(dest_port_str) <= 65535): 
                flash("启用端口转发时，目标内部端口必须是1-65535之间的有效数字。", "error")
                current_form_state = dict(record_to_edit) 
                current_form_state.update(request.form.to_dict()) 
                return render_template('record_form.html', record=current_form_state, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))
            record_to_edit['origin_rule_destination_port'] = int(dest_port_str)
        else: 
            record_to_edit['origin_rule_destination_port'] = None
            record_to_edit['origin_rule_id'] = None # Clear ID if rule disabled

        # Update or clear origin rule description based on new state
        if record_to_edit["origin_rule_enabled"] and record_to_edit["name"] and record_to_edit["origin_rule_destination_port"]:
            record_to_edit["origin_rule_description"] = _generate_origin_rule_description(
                record_to_edit["name"], 
                record_to_edit["origin_rule_destination_port"], 
                record_to_edit["id"]
            )
        else:
            record_to_edit["origin_rule_description"] = ""


        # Find the index and update in DDNS_RECORDS
        found_index = -1
        for i, r_loop_var in enumerate(DDNS_RECORDS): 
            if r_loop_var["id"] == record_id:
                DDNS_RECORDS[i] = record_to_edit # Update with all changes
                found_index = i
                break
        
        if found_index != -1:
            save_ddns_records() 
            _sync_app_status_records_display()
            flash(f"记录 '{record_to_edit['name']}' 已成功更新！更改将在下次DDNS检查时完全同步到Cloudflare。", "success")
            # Optionally trigger an update job here
            # threading.Thread(target=run_ddns_update_job, kwargs={'manual_trigger': True}).start()
        else:
            flash("更新记录时发生内部错误，未找到记录的索引。", "error") # Should not happen normally

        return redirect(url_for('records_management'))
    
    return render_template('record_form.html', record=record_to_edit, form_title=f"编辑记录: {record_to_edit['name']}", username=session.get('username', '访客'))


@flask_app.route('/records/delete/<record_id>', methods=['POST'])
def delete_record(record_id):
    global DDNS_RECORDS
    record_to_delete_local = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)

    if not record_to_delete_local:
        flash("未找到要删除的本地记录。", "error")
        return redirect(url_for('records_management'))

    record_name = record_to_delete_local['name']
    # Type is not strictly needed for deletion intent here, but good for logging
    # record_type = record_to_delete_local['type'] 
    
    # Mark the record for deletion by disabling its origin rule and DNS updates.
    # The actual CF deletion will happen in the next run_ddns_update_job.
    record_to_delete_local['enabled'] = False # Disable DDNS updates for this record
    record_to_delete_local['origin_rule_enabled'] = False # Mark origin rule for deletion
    record_to_delete_local['origin_rule_id'] = None # Clear ID
    record_to_delete_local['origin_rule_description'] = "" # Clear description

    # Find index and update in main list
    deleted_from_local_list = False
    try:
        # Instead of directly removing, we mark it. The batch job will handle CF deletion.
        # For immediate "removal" from view and config, remove from DDNS_RECORDS list.
        # The run_ddns_update_job will then see it's gone from local config
        # and if batch_manage_origin_rules is smart, it will remove orphaned CF rules.
        # And _delete_cloudflare_dns_record needs to be called for the DNS part.
        # This requires a more direct deletion approach for immediate effect.

        # For immediate effect:
        # 1. Delete Origin Rule from CF
        # 2. Delete DNS Record from CF
        # 3. Delete from local DDNS_RECORDS list

        temp_record_for_origin_deletion = dict(record_to_delete_local)
        temp_record_for_origin_deletion["origin_rule_enabled"] = False # Signal deletion
        
        # Use batch_manage_origin_rules by temporarily setting this one record's intent
        # This is a bit heavy for single deletion. A targeted deletion for origin rule is better.
        # Let's simplify: the next full run_ddns_update_job will handle cleanup.
        # For now, just remove locally.
        # This means the record might linger on Cloudflare until the next update job.
        # For a cleaner immediate delete, we'd call CF APIs here.

        # More robust immediate deletion (simplified from batch):
        origin_rule_deleted_ok = True
        if record_to_delete_local.get("origin_rule_id") or record_to_delete_local.get("origin_rule_description"): # If it might have a rule
            ruleset = _get_origin_ruleset()
            if ruleset:
                current_rules = ruleset.get("rules", [])
                rule_id_to_remove = record_to_delete_local.get("origin_rule_id")
                rule_desc_to_remove = record_to_delete_local.get("origin_rule_description")
                
                filtered_rules = []
                changed_ruleset = False
                for r in current_rules:
                    if r.get("id") == rule_id_to_remove and rule_id_to_remove:
                        changed_ruleset = True
                        add_log_entry(f"记录 {record_name}: 准备从CF删除Origin Rule ID {rule_id_to_remove}", "INFO")
                        continue
                    if r.get("description") == rule_desc_to_remove and rule_desc_to_remove and not rule_id_to_remove: # If ID was unknown, try by desc
                        changed_ruleset = True
                        add_log_entry(f"记录 {record_name}: 准备从CF删除Origin Rule Desc {rule_desc_to_remove}", "INFO")
                        continue
                    filtered_rules.append(r)
                
                if changed_ruleset:
                    if not (_update_origin_ruleset(filtered_rules, ruleset.get("description")) and _update_origin_ruleset(filtered_rules, ruleset.get("description")).get("success")):
                        origin_rule_deleted_ok = False
                        flash(f"从 Cloudflare 删除记录 '{record_name}' 的 Origin Rule 失败。", "error")
            else: # Failed to get ruleset
                origin_rule_deleted_ok = False
                flash(f"获取 Origin Ruleset 失败，无法为 '{record_name}' 删除 Origin Rule。", "error")
        
        dns_deleted_ok = True
        if origin_rule_deleted_ok: # Only proceed if origin rule part was okay
            cf_dns_info = _get_cloudflare_dns_record(record_to_delete_local['name'], record_to_delete_local['type'])
            if cf_dns_info and cf_dns_info.get("id"):
                if not _delete_cloudflare_dns_record(cf_dns_info.get("id")):
                    dns_deleted_ok = False
                    flash(f"从 Cloudflare 删除 DNS 记录 '{record_name}' 失败。", "error")
            elif cf_dns_info is None and (_cf_api_request("GET", f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records", params={"type": record_to_delete_local['type'], "name": record_to_delete_local['name']}) is not None): 
                 add_log_entry(f"DNS 记录 '{record_name}' 在 Cloudflare 上未找到，无需删除。", "INFO")
            # If cf_dns_info is None AND the api request also would be None, it means API token is bad, so we can't tell. Error already logged by _get_cloudflare_dns_record

        if origin_rule_deleted_ok and dns_deleted_ok:
            DDNS_RECORDS = [r for r in DDNS_RECORDS if r.get("id") != record_id]
            deleted_from_local_list = True
            save_ddns_records()
            _sync_app_status_records_display()
            flash(f"记录 '{record_name}' 已成功从本地和 Cloudflare 删除。", "success")
        else:
             flash(f"记录 '{record_name}' 未能完全从 Cloudflare 删除，本地记录未移除。请检查日志。", "error")
             _sync_app_status_records_display() # Refresh to show current state if deletion failed partially

    except Exception as e:
        add_log_entry(f"删除记录 '{record_name}' 时发生意外错误: {e}", "ERROR")
        flash(f"删除记录时发生意外错误: {e}", "error")
        _sync_app_status_records_display()

    return redirect(url_for('records_management'))


@flask_app.route('/records/toggle/<record_id>', methods=['POST'])
def toggle_record(record_id):
    record_to_toggle = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
    if record_to_toggle:
        record_to_toggle['enabled'] = not record_to_toggle['enabled']
        if not record_to_toggle['enabled']: # If disabling DDNS, also consider disabling origin rule logic for this record
            record_to_toggle['origin_rule_enabled'] = False 
            record_to_toggle['origin_rule_id'] = None # Will be cleaned up by next batch job
            record_to_toggle['origin_rule_description'] = ""
        save_ddns_records() 
        _sync_app_status_records_display()
        flash(f"记录 '{record_to_toggle['name']}' DDNS 更新已{'启用' if record_to_toggle['enabled'] else '禁用'}。", "success")
        # Optionally trigger an update job here
        # threading.Thread(target=run_ddns_update_job, kwargs={'manual_trigger': True}).start()
    else:
        flash("未找到指定记录以切换状态。", "error")
    return redirect(url_for('records_management')) 

@flask_app.route('/records/batch_delete', methods=['POST'])
def batch_delete_records():
    global DDNS_RECORDS
    data = request.get_json()
    record_ids_to_delete = data.get('record_ids', [])
    if not record_ids_to_delete:
        return jsonify(success=False, message="未提供任何记录ID。"), 400

    add_log_entry(f"收到批量删除请求，涉及本地记录IDs: {record_ids_to_delete}", "INFO")
    
    successfully_removed_local_ids = set()
    overall_success_count = 0
    overall_failure_count = 0
    messages = []

    # For batch Origin Rule deletion, we can adapt parts of batch_manage_origin_rules
    # Step 1: Collect all records to be deleted and their origin rule info
    records_being_deleted_with_origin_info = []
    temp_active_ddns_records = [] # Records not being deleted
    
    for r_id in record_ids_to_delete:
        rec = next((dr for dr in DDNS_RECORDS if dr.get("id") == r_id), None)
        if rec:
            records_being_deleted_with_origin_info.append(dict(rec)) # store copy
    
    # Create a temporary list of DDNS records as if the selected ones are already disabled for origin rules
    # This list will be passed to batch_manage_origin_rules to calculate the new ruleset
    temp_ddns_records_for_origin_batch = []
    for rec_orig in DDNS_RECORDS:
        rec = dict(rec_orig)
        if rec["id"] in record_ids_to_delete:
            rec["origin_rule_enabled"] = False # Signal disable/delete for batch processing
            rec["origin_rule_id"] = None # Clear ID as it's being deleted
            rec["origin_rule_description"] = ""
        temp_ddns_records_for_origin_batch.append(rec)

    # Step 2: Call batch_manage_origin_rules to update the CF ruleset
    # This will effectively remove origin rules for records marked as origin_rule_enabled=False
    updated_records_after_origin_batch, cf_origin_rules_put_success = batch_manage_origin_rules(temp_ddns_records_for_origin_batch)

    if cf_origin_rules_put_success is None:
        messages.append("批量删除Origin Rules失败: 无法获取当前Cloudflare规则集。")
        overall_failure_count = len(record_ids_to_delete) # Mark all as failed for origin part
    elif not cf_origin_rules_put_success:
        messages.append("批量删除Origin Rules失败: 更新Cloudflare规则集时出错。")
        overall_failure_count = len(record_ids_to_delete) # Mark all as failed for origin part

    # Step 3: Delete DNS records from CF individually for those whose origin rules were handled (or attempted)
    for r_info in records_being_deleted_with_origin_info:
        record_name = r_info['name']
        record_type = r_info['type']
        record_id = r_info['id']

        dns_deleted_ok = True
        if cf_origin_rules_put_success is not None: # Only attempt DNS if origin pre-check didn't fail critically
            cf_dns_info = _get_cloudflare_dns_record(record_name, record_type)
            if cf_dns_info and cf_dns_info.get("id"):
                if not _delete_cloudflare_dns_record(cf_dns_info.get("id")):
                    dns_deleted_ok = False
                    messages.append(f"记录 {record_name}: Cloudflare DNS 记录删除失败。")
            elif cf_dns_info is None and (_cf_api_request("GET", f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records", params={"type": r_info['type'], "name": r_info['name']}) is not None):
                 messages.append(f"记录 {record_name}: Cloudflare DNS 记录未找到，无需删除。")
            # else: API token might be bad, _get_cloudflare_dns_record already logged. Consider as DNS delete failure.
            # This logic branch means that if _get_cloudflare_dns_record returns None due to API issue, dns_deleted_ok remains True.
            # which might be misleading. If get fails, delete should be considered failed.
            if cf_dns_info is None and _cf_api_request("GET", f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records", params={"type": r_info['type'], "name": r_info['name']}) is None:
                dns_deleted_ok = False # Treat as failure if we can't even check
                messages.append(f"记录 {record_name}: 无法确认或删除 Cloudflare DNS 记录 (API问题?).")


        if (cf_origin_rules_put_success is not None and cf_origin_rules_put_success) and dns_deleted_ok : # Origin rules updated AND DNS deleted
            successfully_removed_local_ids.add(record_id)
            overall_success_count += 1
            messages.append(f"记录 {record_name}: 已成功从Cloudflare删除。")
        elif cf_origin_rules_put_success is None or not cf_origin_rules_put_success: 
            # Origin rule part failed, so we count it as overall failure for this record.
            overall_failure_count +=1 
            # messages for origin failure already added
            if not dns_deleted_ok and (cf_origin_rules_put_success is not None and cf_origin_rules_put_success): # if origin was ok but DNS failed
                 messages.append(f"记录 {record_name}: Origin Rule可能已处理，但DNS删除失败。")

        elif not dns_deleted_ok : # Origin was ok, but DNS delete failed
            overall_failure_count +=1
            # message for DNS failure already added

    # Step 4: Update local DDNS_RECORDS list
    if successfully_removed_local_ids:
        DDNS_RECORDS = [r for r in DDNS_RECORDS if r.get("id") not in successfully_removed_local_ids]
        save_ddns_records() # Save the main list
    
    # If origin rules were updated successfully, DDNS_RECORDS should reflect the state *after* that batch operation,
    # but with the successfully_removed_local_ids additionally removed.
    if cf_origin_rules_put_success:
        # Filter out the deleted ones from the result of batch_manage_origin_rules
        DDNS_RECORDS = [r for r in updated_records_after_origin_batch if r.get("id") not in successfully_removed_local_ids]
        save_ddns_records()


    _sync_app_status_records_display()
    final_message = f"批量删除完成。成功从CF移除并从本地删除: {overall_success_count}。部分或完全失败: {overall_failure_count}。详情: {' '.join(messages)}"
    add_log_entry(final_message, "INFO")
    return jsonify(success=overall_failure_count == 0, message=final_message)


@flask_app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings():
    admin_creds = load_admin_credentials() 
    if not admin_creds: 
        flash("管理员账户信息缺失。", "error")
        return redirect(url_for('index')) # Or login if appropriate
        
    current_display_config = GLOBAL_CONFIG.copy()
    if GLOBAL_CONFIG["CF_API_TOKEN"]:
        token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
        current_display_config["CF_API_TOKEN"] = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:] if token_len > 8 else "****"
    else:
        current_display_config["CF_API_TOKEN"] = ""


    if request.method == 'POST':
        form_type = request.form.get('form_type')
        action_taken = False
        if form_type == 'password_change':
            old_password = request.form.get('old_password', '').strip()
            new_password = request.form.get('new_password', '').strip()
            confirm_new_password = request.form.get('confirm_new_password', '').strip()

            if not old_password and (new_password or confirm_new_password): 
                flash("如需修改密码，请输入当前密码。", "error")
            elif old_password: # Only proceed if old_password is provided
                if not check_password_hash(admin_creds["password_hash"], old_password): 
                    flash("当前密码不正确。", "error")
                elif not new_password and not confirm_new_password: 
                    flash("未输入新密码，密码未更改。", "info") # No change intended
                elif not new_password or not confirm_new_password: 
                    flash("新密码和确认密码均不能为空。", "error")
                elif new_password != confirm_new_password: 
                    flash("新密码和确认密码不一致。", "error")
                elif len(new_password) < 6: 
                    flash("新密码长度至少为6个字符。", "error")
                else:
                    new_hashed_password = generate_password_hash(new_password)
                    if save_admin_credentials(admin_creds["username"], new_hashed_password):
                        flash("管理员密码已成功修改！请重新登录。", "success")
                        session.pop('logged_in', None); session.pop('username', None)
                        action_taken = True 
                        return redirect(url_for('login'))
                    else: 
                        flash("修改密码时发生错误。", "error")
        elif form_type == 'api_config_change':
            new_api_token_form = request.form.get('cf_api_token', '').strip()
            new_zone_id_form = request.form.get('cf_zone_id', '').strip()

            # Determine actual new token: if input is '****' or masked value, keep old one unless it's genuinely '****'
            actual_new_api_token = ""
            if new_api_token_form == current_display_config["CF_API_TOKEN"] and GLOBAL_CONFIG["CF_API_TOKEN"]: # User didn't change the masked value
                actual_new_api_token = GLOBAL_CONFIG["CF_API_TOKEN"]
            else: # User typed something new (or cleared it)
                actual_new_api_token = new_api_token_form


            if not actual_new_api_token or not new_zone_id_form: 
                flash("API Token 和 Zone ID 均不能为空！", "error")
            else:
                token_changed = GLOBAL_CONFIG["CF_API_TOKEN"] != actual_new_api_token
                zone_id_changed = GLOBAL_CONFIG["CF_ZONE_ID"] != new_zone_id_form
                
                if token_changed or zone_id_changed:
                    GLOBAL_CONFIG["CF_API_TOKEN"] = actual_new_api_token
                    GLOBAL_CONFIG["CF_ZONE_ID"] = new_zone_id_form
                    save_global_config()
                    log_msgs = []
                    if token_changed: log_msgs.append("API Token 已更新"); add_log_entry("CF API Token 已更新。", "INFO")
                    if zone_id_changed: log_msgs.append("Zone ID 已更新"); add_log_entry("CF Zone ID 已更新。", "INFO")
                    flash(f"Cloudflare API 设置已成功更新 ({', '.join(log_msgs)})！", "success")
                    action_taken = True
                     # Re-mask for display after successful update
                    if GLOBAL_CONFIG["CF_API_TOKEN"]:
                        token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
                        current_display_config["CF_API_TOKEN"] = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:] if token_len > 8 else "****"
                    else:
                        current_display_config["CF_API_TOKEN"] = ""
                    current_display_config["CF_ZONE_ID"] = GLOBAL_CONFIG["CF_ZONE_ID"]

                else: 
                    flash("API 设置未发生变化。", "info")
        else: 
            flash("无效的表单提交。", "error")
        
        if action_taken: # If an action resulted in a redirect or significant change, refresh might be good.
            return redirect(url_for('admin_settings')) # Redirect to GET to show fresh state and clear POST
            
    # For GET request or if POST didn't redirect
    return render_template('admin_settings.html', username=session.get('username'), current_config=current_display_config)


# --- 主程序和调度器 ---
# Declare scheduler globally to be accessible by settings route
scheduler = BackgroundScheduler(daemon=True)
import threading # For manual trigger thread

if __name__ == '__main__':
    load_all_config() 
    # Initial run on startup
    initial_run_thread = threading.Thread(target=run_ddns_update_job) # Run in a thread to not block startup too long
    initial_run_thread.start()
    
    if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
        scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"], id="ddns_job", replace_existing=True)
        scheduler.start()
        add_log_entry(f"DDNS 自动更新任务已设置，每 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟运行一次。")
    else:
        add_log_entry("DDNS 自动更新间隔设置为0或无效，任务未调度。", "WARNING")
    
    try:
        add_log_entry("启动 Flask Web 服务器...")
        # Use a production-ready WSGI server like gunicorn or waitress instead of flask_app.run for production
        flask_app.run(host='0.0.0.0', port=5000, debug=False) # Listen on all interfaces
    except (KeyboardInterrupt, SystemExit):
        add_log_entry("接收到关闭信号...", "INFO")
    finally:
        if scheduler.running:
            scheduler.shutdown()
            add_log_entry("调度器已关闭。")
        add_log_entry("DDNS 应用已关闭。")