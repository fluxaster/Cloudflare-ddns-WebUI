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
import concurrent.futures
import threading # Added for locks and manual trigger thread

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger(__name__)

# --- 线程锁 ---
GLOBAL_CONFIG_LOCK = threading.Lock()
DDNS_RECORDS_LOCK = threading.Lock()
APP_STATUS_LOCK = threading.Lock()
ADMIN_CREDENTIALS_LOCK = threading.Lock()

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
MAX_PARALLEL_WORKERS = 5

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
    
    # app_status["log_history"] is a list, insert is thread-safe enough for this use case (GIL)
    # If it were more complex, APP_STATUS_LOCK might be used.
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
    with ADMIN_CREDENTIALS_LOCK:
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
        if not os.path.exists(ADMIN_CREDENTIALS_FILE): # Only log not set if file truly doesn't exist
             add_log_entry("管理员账户未设置。", "WARNING")
        else: # Log failure if file exists but couldn't load
             add_log_entry("管理员账户加载失败。", "WARNING")

        return None

def save_admin_credentials(username, password_hash):
    global ADMIN_ACCOUNT_SET
    with ADMIN_CREDENTIALS_LOCK:
        try:
            with open(ADMIN_CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"username": username, "password_hash": password_hash}, f, indent=4, ensure_ascii=False)
            add_log_entry("管理员账户已成功保存。", "INFO")
            ADMIN_ACCOUNT_SET = True
            return True
        except Exception as e:
            add_log_entry(f"保存管理员凭证失败: {e}", "ERROR")
            return False

# --- 配置加载与保存函数 ---

def ensure_record_fields(record):
    record.setdefault("id", str(uuid.uuid4()))
    record.setdefault("name", "")
    record.setdefault("type", "A")
    record.setdefault("proxied", False)
    record.setdefault("ttl", 120)
    record.setdefault("enabled", True)
    record.setdefault("origin_rule_enabled", False)
    record.setdefault("origin_rule_destination_port", None)
    record.setdefault("origin_rule_id", None)
    record.setdefault("origin_rule_description", "")
    return record

def save_ddns_records():
    records_file_path = 'records.json'
    with DDNS_RECORDS_LOCK:
        # Create a list of records to save from the current DDNS_RECORDS state
        records_to_save = [ensure_record_fields(dict(r)) for r in DDNS_RECORDS]
    try:
        with open(records_file_path, 'w', encoding='utf-8') as f:
            json.dump(records_to_save, f, indent=4, ensure_ascii=False)
        add_log_entry(f"已成功保存 {len(records_to_save)} 条 DDNS 记录到 {records_file_path}。", "INFO")
    except Exception as e:
        add_log_entry(f"保存 DDNS 记录到 {records_file_path} 失败: {e}", "ERROR")


def save_global_config():
    config_file_path = 'config.ini'
    cfg = configparser.ConfigParser()
    
    with GLOBAL_CONFIG_LOCK: # Read GLOBAL_CONFIG under lock
        current_global_config_copy = GLOBAL_CONFIG.copy()

    if os.path.exists(config_file_path):
        try:
            cfg.read(config_file_path, encoding='utf-8')
        except Exception as e:
            add_log_entry(f"读取 config.ini 以更新时出错 (可能编码问题): {e}", "WARNING")

    if 'Cloudflare' not in cfg: cfg['Cloudflare'] = {}
    if 'DDNS' not in cfg: cfg['DDNS'] = {}

    cfg['Cloudflare']['ApiToken'] = current_global_config_copy["CF_API_TOKEN"]
    cfg['Cloudflare']['ZoneId'] = current_global_config_copy["CF_ZONE_ID"]
    cfg['DDNS']['CheckIntervalMinutes'] = str(current_global_config_copy["DDNS_CHECK_INTERVAL_MINUTES"])
    cfg['DDNS']['EnableIPv4DDNS'] = str(current_global_config_copy["ENABLE_IPV4_DDNS"])
    cfg['DDNS']['EnableIPv6DDNS'] = str(current_global_config_copy["ENABLE_IPV6_DDNS"])
    cfg['DDNS']['InterfaceName'] = current_global_config_copy["DDNS_INTERFACE_NAME"]

    try:
        with open(config_file_path, 'w', encoding='utf-8') as f:
            cfg.write(f)
        add_log_entry(f"已成功保存全局配置到 {config_file_path}。", "INFO")
    except Exception as e:
        add_log_entry(f"保存全局配置到 {config_file_path} 失败: {e}", "ERROR")

def _sync_app_status_records_display():
    new_records_status = []
    
    with DDNS_RECORDS_LOCK: # Read DDNS_RECORDS under lock
        # Make a deep copy to work with outside the lock if processing is long,
        # or keep processing short and do it inside the lock for simplicity.
        # Here, copying and then processing is safer.
        current_ddns_records_copy = [ensure_record_fields(dict(r)) for r in DDNS_RECORDS]

    with APP_STATUS_LOCK: # Lock for reading old app_status["records_status"]
        old_records_status_map = {rs["id"]: rs for rs in app_status.get("records_status", [])}

    for record_conf in current_ddns_records_copy: # Iterate over the copy
        record_id = record_conf["id"]
        current_record_status = {
            "id": record_id, "name": record_conf["name"], "type": record_conf["type"],
            "proxied": record_conf["proxied"], "ttl": record_conf["ttl"], "enabled": record_conf["enabled"],
            "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", "message": "待检查...",
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
            if old_status.get("type") == record_conf["type"] and old_status.get("message") not in ["待检查...", "此记录已禁用。", f"类型已更改为 {record_conf['type']}，待检查..."]:
                current_record_status["local_ip"] = old_status.get("local_ip", "N/A")
                current_record_status["cloudflare_ip"] = old_status.get("cloudflare_ip", "N/A")
                current_record_status["last_updated_cloudflare"] = old_status.get("last_updated_cloudflare", "N/A")
                current_record_status["message"] = old_status.get("message", "待检查...")
            elif old_status.get("type") != record_conf["type"]:
                current_record_status["message"] = f"类型已更改为 {record_conf['type']}，待检查..."
        
        if not record_conf["enabled"]:
            current_record_status["message"] = "此记录已禁用。"
        elif current_record_status["message"] == "此记录已禁用." and record_conf["enabled"]:
             current_record_status["message"] = "已启用，待检查..."
        new_records_status.append(current_record_status)
    
    with APP_STATUS_LOCK: # Lock for writing to app_status["records_status"]
        app_status["records_status"] = new_records_status
    add_log_entry("已同步应用状态中的记录显示信息。", "DEBUG")


def load_all_config():
    # Temporary local vars to hold config read from files
    local_global_config = GLOBAL_CONFIG.copy() # Start with defaults
    local_ddns_records = []

    config = configparser.ConfigParser()
    config_file_path = 'config.ini'
    if os.path.exists(config_file_path):
        try:
            config.read(config_file_path, encoding='utf-8')
            if 'Cloudflare' in config:
                local_global_config["CF_API_TOKEN"] = config.get('Cloudflare', 'ApiToken', fallback=local_global_config["CF_API_TOKEN"])
                local_global_config["CF_ZONE_ID"] = config.get('Cloudflare', 'ZoneId', fallback=local_global_config["CF_ZONE_ID"])
            if 'DDNS' in config:
                local_global_config["DDNS_CHECK_INTERVAL_MINUTES"] = config.getint('DDNS', 'CheckIntervalMinutes', fallback=local_global_config["DDNS_CHECK_INTERVAL_MINUTES"])
                local_global_config["ENABLE_IPV4_DDNS"] = config.getboolean('DDNS', 'EnableIPv4DDNS', fallback=local_global_config["ENABLE_IPV4_DDNS"])
                local_global_config["ENABLE_IPV6_DDNS"] = config.getboolean('DDNS', 'EnableIPv6DDNS', fallback=local_global_config["ENABLE_IPV6_DDNS"])
                local_global_config["DDNS_INTERFACE_NAME"] = config.get('DDNS', 'InterfaceName', fallback=local_global_config["DDNS_INTERFACE_NAME"])
            add_log_entry("已从 config.ini 加载配置到临时存储。", "INFO")
        except Exception as e:
            add_log_entry(f"读取 config.ini 出错: {e}", "ERROR")
    else:
        add_log_entry("config.ini 文件未找到。将使用默认值。", "WARNING")

    with GLOBAL_CONFIG_LOCK: # Update actual GLOBAL_CONFIG
        GLOBAL_CONFIG.update(local_global_config)

    records_file_path = 'records.json'
    needs_save_due_to_schema_change = False
    if os.path.exists(records_file_path):
        try:
            with open(records_file_path, 'r', encoding='utf-8') as f:
                loaded_records_from_file = json.load(f)
            
            for record_data in loaded_records_from_file:
                if isinstance(record_data, dict):
                    if "origin_rule_cloudflare_port" in record_data:
                        del record_data["origin_rule_cloudflare_port"]
                        needs_save_due_to_schema_change = True
                    processed_record = ensure_record_fields(dict(record_data))
                    local_ddns_records.append(processed_record)
                else:
                    add_log_entry(f"发现非字典类型的记录数据: {record_data}，已跳过。", "WARNING")
            add_log_entry(f"已成功从 {records_file_path} 加载和处理 {len(local_ddns_records)} 条 DDNS 记录到临时存储。", "INFO")
        except json.JSONDecodeError as e:
            add_log_entry(f"解析 {records_file_path} 出错: {e}。请检查JSON格式。", "ERROR")
        except Exception as e:
            add_log_entry(f"读取 {records_file_path} 时发生未知错误: {e}", "ERROR")
    else:
        add_log_entry(f"records.json 文件未找到。将以空记录列表启动。", "WARNING")
    
    with DDNS_RECORDS_LOCK: # Update actual DDNS_RECORDS
        DDNS_RECORDS[:] = local_ddns_records

    if needs_save_due_to_schema_change:
        add_log_entry("检测到旧的 'origin_rule_cloudflare_port' 字段，已移除并准备重新保存 records.json。", "INFO")
        save_ddns_records() # This will acquire DDNS_RECORDS_LOCK internally

    load_admin_credentials() # Handles its own lock

    with GLOBAL_CONFIG_LOCK: # Read for logging and final checks
        if not GLOBAL_CONFIG["CF_API_TOKEN"] or not GLOBAL_CONFIG["CF_ZONE_ID"]:
            add_log_entry("警告: Cloudflare API Token 或 Zone ID 未能成功加载。DDNS 功能将无法正常工作。", "ERROR")
            # Do not clear them here if they were partially set, let user fix via UI.
        add_log_entry(f"最终加载的 Cloudflare API Token (部分显示): {GLOBAL_CONFIG['CF_API_TOKEN'][:8]}...", "DEBUG")
        add_log_entry(f"最终加载的 Cloudflare Zone ID: {GLOBAL_CONFIG['CF_ZONE_ID']}", "DEBUG")

    _sync_app_status_records_display() # Handles its own locks


# --- DDNS 核心功能 ---
def get_stable_ipv6_windows(interface_name_from_config): # Pass interface name
    script_path = os.path.join(os.path.dirname(__file__), "get_ipv6.ps1")
    if not os.path.exists(script_path):
        add_log_entry("错误: get_ipv6.ps1 脚本未找到!", "ERROR")
        return None
    command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path]
    # If your script accepts an interface name argument:
    # if interface_name_from_config:
    #    command.extend(["-InterfaceName", interface_name_from_config]) # Example
    #    add_log_entry(f"将使用配置的网络接口名: {interface_name_from_config} 调用脚本。", "DEBUG")

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

def _cf_api_request(method, endpoint, api_token, data=None, params=None): # Added api_token
    if not api_token : # Zone ID is part of endpoint usually, token is essential
        # This check is now more for completeness, as higher levels should ensure token is present
        add_log_entry("Cloudflare API Token 未提供给 _cf_api_request。", "ERROR")
        return {"success": False, "errors": [{"message": "API Token not provided to request function."}]}

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    url = f"{CLOUDFLARE_API_BASE_URL}{endpoint}"
    try:
        response = requests.request(method, url, headers=headers, json=data, params=params, timeout=20)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_message = f"Cloudflare API 请求失败 ({method} {url}): {e}"
        detailed_error_content = ""
        if hasattr(e, 'response') and e.response is not None:
            try:
                detailed_error_content = e.response.json()
                error_message += f" - API 错误详情: {detailed_error_content}"
            except ValueError:
                detailed_error_content = e.response.text
                error_message += f" - API 错误详情 (非JSON): {detailed_error_content}"
        add_log_entry(error_message, "ERROR")
        
        # Construct a consistent error response
        errors_list = []
        if isinstance(detailed_error_content, dict) and "errors" in detailed_error_content:
            errors_list = detailed_error_content["errors"]
        elif isinstance(detailed_error_content, list): # if error content itself is a list of errors
             errors_list = detailed_error_content
        elif detailed_error_content: # string or other non-empty
            errors_list = [{"message": str(detailed_error_content)}]
        else:
            errors_list = [{"message": str(e)}] # Fallback to the exception string
        return {"success": False, "errors": errors_list}


def _get_cloudflare_dns_record(zone_id, api_token, record_name, record_type):
    endpoint = f"/zones/{zone_id}/dns_records"
    params = {"type": record_type, "name": record_name}
    data = _cf_api_request("GET", endpoint, api_token, params=params)
    if data and data.get("success"):
        if data["result"]: # result is a list of records
            record = data["result"][0]
            add_log_entry(f"Cloudflare 记录 '{record_name}' ({record_type}) 当前 IP: {record['content']}, ID: {record['id']}, Proxied: {record.get('proxied', False)}", "DEBUG")
            return record # Return the first record found
        else:
            add_log_entry(f"在 Cloudflare 上未找到名为 '{record_name}' 的 {record_type} 记录。", "INFO")
            return None # Explicitly None if not found but API call was successful
    else:
        # Error already logged by _cf_api_request
        add_log_entry(f"从 Cloudflare 获取 DNS 记录 '{record_name}' ({record_type}) 失败。", "ERROR")
        return {"error_response": data} # Indicate failure by returning the error response for context

def _delete_cloudflare_dns_record(zone_id, api_token, record_cf_id):
    if not record_cf_id:
        add_log_entry("尝试删除 Cloudflare DNS 记录，但未提供记录 ID。", "ERROR")
        return False
    endpoint = f"/zones/{zone_id}/dns_records/{record_cf_id}"
    add_log_entry(f"正在删除 Cloudflare DNS 记录 ID: {record_cf_id}...", "DEBUG")
    api_response = _cf_api_request("DELETE", endpoint, api_token)
    if api_response and api_response.get("success"):
        add_log_entry(f"成功删除 Cloudflare DNS 记录 ID: {record_cf_id}。", "INFO")
        return True
    else:
        add_log_entry(f"删除 Cloudflare DNS 记录 ID: {record_cf_id} 失败。", "ERROR")
        # Error details already logged by _cf_api_request
        return False

def _update_cloudflare_dns_record(zone_id, api_token, record_cf_id, record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{zone_id}/dns_records/{record_cf_id}"
    payload = {"type": record_type, "name": record_name, "content": current_ip, "ttl": ttl, "proxied": proxied}
    add_log_entry(f"正在更新 Cloudflare 记录 '{record_name}' (ID: {record_cf_id}) 指向 '{current_ip}', 代理: {proxied}...", "DEBUG")
    data = _cf_api_request("PUT", endpoint, api_token, data=payload)
    if data and data.get("success"):
        add_log_entry(f"成功更新 Cloudflare 记录 '{record_name}' 为 '{current_ip}', 代理: {proxied}。", "INFO")
        return True
    else:
        add_log_entry(f"更新 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

def _create_cloudflare_dns_record(zone_id, api_token, record_name, record_type, current_ip, ttl, proxied):
    endpoint = f"/zones/{zone_id}/dns_records"
    payload = {"type": record_type, "name": record_name, "content": current_ip, "ttl": ttl, "proxied": proxied}
    add_log_entry(f"正在创建新的 Cloudflare 记录 '{record_name}' ({record_type}) 指向 '{current_ip}', 代理: {proxied}...", "DEBUG")
    data = _cf_api_request("POST", endpoint, api_token, data=payload)
    if data and data.get("success"):
        add_log_entry(f"成功创建 Cloudflare 记录 '{record_name}' 指向 '{current_ip}', 代理: {proxied}。", "INFO")
        return data.get("result", {}).get("id") if data.get("result") else True
    else:
        add_log_entry(f"创建 Cloudflare 记录 '{record_name}' 失败。", "ERROR")
        return False

# --- Cloudflare Origin Rules Functions ---
ORIGIN_RULESET_PHASE = "http_request_origin"

def _get_origin_ruleset(zone_id, api_token):
    endpoint = f"/zones/{zone_id}/rulesets/phases/{ORIGIN_RULESET_PHASE}/entrypoint"
    response = _cf_api_request("GET", endpoint, api_token)
    if response and response.get("success") and response.get("result"):
        add_log_entry(f"成功获取 Origin Ruleset (ID: {response['result'].get('id')}, {len(response['result'].get('rules',[]))} rules).", "DEBUG")
        return response["result"]
    add_log_entry("获取 Origin Ruleset 失败或为空。", "ERROR" if response and not response.get("success") else "WARNING")
    return None

def _update_origin_ruleset(zone_id, api_token, rules_list, ruleset_description="DDNS Managed Origin Rules"):
    endpoint = f"/zones/{zone_id}/rulesets/phases/{ORIGIN_RULESET_PHASE}/entrypoint"
    payload = {
        "description": ruleset_description,
        "rules": rules_list
    }
    add_log_entry(f"准备更新 Origin Ruleset，包含 {len(rules_list)} 条规则。", "DEBUG")
    response = _cf_api_request("PUT", endpoint, api_token, data=payload)
    if response and response.get("success"):
        add_log_entry("成功更新 Origin Ruleset。", "INFO")
        return response
    add_log_entry("更新 Origin Ruleset 失败。", "ERROR")
    return None

def _generate_origin_rule_description(record_name, dest_port, local_record_id):
    short_local_id = str(local_record_id).split('-')[0]
    return f"ddns_fwd_{record_name}_to{dest_port}_id{short_local_id}"

# --- BATCH ORIGIN RULE MANAGEMENT ---
def batch_manage_origin_rules(local_records_with_intent, zone_id, api_token):
    add_log_entry("--- 开始批量 Origin Rule 管理 ---", "INFO")

    if not api_token or not zone_id: # Should be pre-checked by caller
        add_log_entry("Origin Rule 管理: Cloudflare API Token 或 Zone ID 未提供。", "ERROR")
        return local_records_with_intent, None

    current_ruleset_data = _get_origin_ruleset(zone_id, api_token)
    if current_ruleset_data is None:
        add_log_entry("Origin Rule 管理: 获取当前规则集失败。无法继续。", "ERROR")
        for rec in local_records_with_intent:
            if rec.get("origin_rule_enabled"):
                rec["origin_rule_id"] = None
        return local_records_with_intent, None # None indicates critical CF failure

    current_cf_rules = current_ruleset_data.get("rules", [])
    cf_ruleset_description = current_ruleset_data.get("description", "DDNS Managed Origin Rules")
    cf_rules_by_id = {rule["id"]: rule for rule in current_cf_rules if "id" in rule}
    cf_rules_by_desc = {rule["description"]: rule for rule in current_cf_rules if "description" in rule}
    desired_cf_rules_list = []
    updated_local_records_list = []
    any_change_to_cf_ruleset_needed = False
    any_change_to_local_data = False
    active_managed_rule_identifiers_on_cf = set()

    for temp_record_config in local_records_with_intent:
        local_record = dict(temp_record_config)
        record_name = local_record["name"]
        should_be_enabled = local_record["origin_rule_enabled"]
        dest_port = local_record.get("origin_rule_destination_port")
        expected_description = local_record.get("origin_rule_description", "")
        original_local_rule_id = local_record.get("origin_rule_id")
        cf_counterpart_rule = None

        if original_local_rule_id and original_local_rule_id in cf_rules_by_id:
            cf_counterpart_rule = cf_rules_by_id[original_local_rule_id]
        elif expected_description and expected_description in cf_rules_by_desc:
            cf_counterpart_rule = cf_rules_by_desc[expected_description]
            if cf_counterpart_rule and original_local_rule_id != cf_counterpart_rule["id"]:
                add_log_entry(f"Origin Rule for {record_name} (Desc: {expected_description}): Local ID {original_local_rule_id} was stale/missing, updated to CF ID {cf_counterpart_rule['id']}.", "INFO")
                local_record["origin_rule_id"] = cf_counterpart_rule["id"]
                any_change_to_local_data = True
        
        if cf_counterpart_rule:
            active_managed_rule_identifiers_on_cf.add(cf_counterpart_rule["id"])
            if "description" in cf_counterpart_rule:
                 active_managed_rule_identifiers_on_cf.add(cf_counterpart_rule["description"])

        if should_be_enabled:
            if not record_name or not dest_port or not expected_description:
                add_log_entry(f"Origin Rule for {record_name}: 配置不完整。将禁用并尝试从CF移除规则。", "WARNING")
                local_record["origin_rule_enabled"] = False
                local_record["origin_rule_id"] = None
                any_change_to_local_data = True
                if cf_counterpart_rule:
                    any_change_to_cf_ruleset_needed = True
            else:
                rule_definition = {
                    "action": "route",
                    "action_parameters": {"origin": {"port": int(dest_port)}},
                    "expression": f'(http.host eq "{record_name}")',
                    "description": expected_description,
                    "enabled": True
                }
                if cf_counterpart_rule:
                    rule_definition["id"] = cf_counterpart_rule["id"]
                    cf_action_params = cf_counterpart_rule.get("action_parameters", {}).get("origin", {})
                    if (cf_counterpart_rule.get("action") != rule_definition["action"] or
                        cf_action_params.get("port") != int(dest_port) or
                        cf_counterpart_rule.get("expression") != rule_definition["expression"] or
                        cf_counterpart_rule.get("description") != rule_definition["description"] or
                        not cf_counterpart_rule.get("enabled")):
                        add_log_entry(f"Origin Rule (ID: {cf_counterpart_rule['id']}) for {record_name} definition changed. Staging update.", "INFO")
                        desired_cf_rules_list.append(rule_definition)
                        any_change_to_cf_ruleset_needed = True
                    else:
                        desired_cf_rules_list.append(cf_counterpart_rule)
                else:
                    add_log_entry(f"Staging new Origin Rule for {record_name} (Desc: {expected_description}).", "INFO")
                    desired_cf_rules_list.append(rule_definition)
                    any_change_to_cf_ruleset_needed = True
        elif not should_be_enabled and cf_counterpart_rule:
            add_log_entry(f"Origin Rule (ID: {cf_counterpart_rule['id']}) for {record_name} is disabled locally. Staging for removal from CF.", "INFO")
            any_change_to_cf_ruleset_needed = True
            if local_record.get("origin_rule_id"):
                local_record["origin_rule_id"] = None
                any_change_to_local_data = True
        updated_local_records_list.append(local_record)

    for cf_rule in current_cf_rules:
        cf_id = cf_rule.get("id")
        cf_desc = cf_rule.get("description", "")
        is_already_part_of_desired_managed_rules = any(
            desired_rule.get("id") == cf_id and cf_id is not None for desired_rule in desired_cf_rules_list
        )
        if not is_already_part_of_desired_managed_rules and not (cf_id in active_managed_rule_identifiers_on_cf or cf_desc in active_managed_rule_identifiers_on_cf):
            add_log_entry(f"Preserving unmanaged Origin Rule from CF (ID: {cf_id}, Desc: {cf_desc}).", "DEBUG")
            desired_cf_rules_list.append(cf_rule)

    if not any_change_to_cf_ruleset_needed and not any_change_to_local_data:
        add_log_entry("Origin Rule 管理: 未检测到 Cloudflare 规则集或本地记录的 Origin Rule 相关字段需要更改。", "INFO")
        add_log_entry("--- 结束批量 Origin Rule 管理 (无更改) ---", "INFO")
        return updated_local_records_list, False # False = CF not updated successfully (because not attempted)

    if not any_change_to_cf_ruleset_needed and any_change_to_local_data:
        add_log_entry("Origin Rule 管理: Cloudflare 规则集无需更改，但本地记录信息已更新 (例如，ID同步)。", "INFO")
        add_log_entry("--- 结束批量 Origin Rule 管理 (本地数据更新) ---", "INFO")
        return updated_local_records_list, False

    add_log_entry(f"Origin Rule 管理: Cloudflare 规则集将更新为包含 {len(desired_cf_rules_list)} 条规则。", "INFO")
    cf_response = _update_origin_ruleset(zone_id, api_token, desired_cf_rules_list, cf_ruleset_description)

    if cf_response and cf_response.get("success"):
        add_log_entry("Origin Rule 管理: Cloudflare 规则集成功更新。", "INFO")
        updated_cf_rules_map_by_desc = {
            rule["description"]: rule
            for rule in cf_response.get("result", {}).get("rules", [])
            if "description" in rule
        }
        final_local_records_after_cf_sync = []
        for local_rec in updated_local_records_list:
            record_copy = dict(local_rec)
            if record_copy.get("origin_rule_enabled") and record_copy.get("origin_rule_description"):
                desc_to_find = record_copy["origin_rule_description"]
                if desc_to_find in updated_cf_rules_map_by_desc:
                    new_cf_id = updated_cf_rules_map_by_desc[desc_to_find].get("id")
                    if record_copy.get("origin_rule_id") != new_cf_id:
                        add_log_entry(f"Origin Rule for {record_copy['name']} (Desc: {desc_to_find}): Local ID set/updated to {new_cf_id} post-CF sync.", "DEBUG")
                        record_copy["origin_rule_id"] = new_cf_id
                else:
                    add_log_entry(f"Origin Rule for {record_copy['name']} (Desc: {desc_to_find}): 未能在更新后的规则集中通过描述找到。ID可能丢失或规则创建失败。", "WARNING")
                    record_copy["origin_rule_id"] = None
            elif not record_copy.get("origin_rule_enabled"):
                if record_copy.get("origin_rule_id") is not None:
                    record_copy["origin_rule_id"] = None
            final_local_records_after_cf_sync.append(record_copy)
        add_log_entry("--- 结束批量 Origin Rule 管理 (成功) ---", "INFO")
        return final_local_records_after_cf_sync, True
    else:
        add_log_entry("Origin Rule 管理: Cloudflare 规则集更新失败。", "ERROR")
        for rec in updated_local_records_list:
            if rec.get("origin_rule_enabled"):
                rec["origin_rule_id"] = None
        add_log_entry("--- 结束批量 Origin Rule 管理 (CF更新失败) ---", "INFO")
        return updated_local_records_list, False


def _process_single_record_dns_part(record_conf_orig, current_public_ipv4, current_public_ipv6, zone_id, api_token, global_enable_ipv4, global_enable_ipv6):
    record_conf = ensure_record_fields(dict(record_conf_orig))
    record_status = {
        "id": record_conf["id"], "name": record_conf["name"], "type": record_conf["type"],
        "proxied": record_conf["proxied"], "ttl": record_conf["ttl"], "enabled": record_conf["enabled"],
        "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", "message": "",
        "origin_rule_enabled": record_conf["origin_rule_enabled"],
        "origin_rule_destination_port": record_conf["origin_rule_destination_port"],
        "origin_rule_id": record_conf["origin_rule_id"],
        "origin_rule_status_display": "待处理"
    }

    if not record_conf["enabled"]:
        record_status["message"] = "此记录已禁用。"
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 已禁用，跳过更新。", "INFO")
        return record_status, record_conf

    target_ip, ip_type_for_log = None, ""
    if record_conf["type"] == "AAAA":
        ip_type_for_log = "IPv6"
        if global_enable_ipv6:
            target_ip = current_public_ipv6
            record_status["local_ip"] = target_ip if target_ip else "获取失败"
        else: record_status["message"] = "IPv6 DDNS 已全局禁用。"
    elif record_conf["type"] == "A":
        ip_type_for_log = "IPv4"
        if global_enable_ipv4:
            target_ip = current_public_ipv4
            record_status["local_ip"] = target_ip if target_ip else "获取失败"
        else: record_status["message"] = "IPv4 DDNS 已全局禁用。"
    else: record_status["message"] = f"不支持的记录类型: {record_conf['type']}"
    
    if record_status["message"]:
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}): {record_status['message']}", "INFO")
        return record_status, record_conf
    if not target_ip:
        record_status["message"] = f"未能获取当前公网 {ip_type_for_log} 地址。"
        add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 未能获取目标IP，跳过更新。", "ERROR")
        return record_status, record_conf

    add_log_entry(f"--- 并行处理 DNS 记录: {record_conf['name']} ({record_conf['type']}) ---", "DEBUG")
    
    cf_dns_full_record_or_error = _get_cloudflare_dns_record(zone_id, api_token, record_conf["name"], record_conf["type"])
    
    cf_dns_record_id, cloudflare_ip_on_cf, cf_proxied_status_on_cf = None, None, None
    api_fetch_failed = False

    if isinstance(cf_dns_full_record_or_error, dict) and "error_response" in cf_dns_full_record_or_error:
        api_fetch_failed = True
        record_status["cloudflare_ip"] = "获取CF记录失败"
    elif cf_dns_full_record_or_error: # Successfully fetched and record exists
        cf_dns_full_record = cf_dns_full_record_or_error
        cf_dns_record_id = cf_dns_full_record.get("id")
        cloudflare_ip_on_cf = cf_dns_full_record.get("content")
        cf_proxied_status_on_cf = cf_dns_full_record.get("proxied", False)
        record_status["cloudflare_ip"] = cloudflare_ip_on_cf
    else: # Successfully fetched, but record does not exist (cf_dns_full_record_or_error is None)
        record_status["cloudflare_ip"] = "未找到"

    if api_fetch_failed:
        record_status["message"] = "获取 Cloudflare DNS 记录信息失败。"
    elif cf_dns_record_id: # Record exists on Cloudflare
        ip_needs_update = (target_ip != cloudflare_ip_on_cf)
        proxy_needs_update = (record_conf["proxied"] != cf_proxied_status_on_cf)
        if not ip_needs_update and not proxy_needs_update:
            record_status["message"] = f"DNS IP ({target_ip}) 及代理状态 ({'启用' if record_conf['proxied'] else '禁用'}) 未更改。"
        else:
            log_msg_parts = []
            if ip_needs_update: log_msg_parts.append(f"IP 地址需更新 (本机: {target_ip}, Cloudflare: {cloudflare_ip_on_cf})")
            if proxy_needs_update: log_msg_parts.append(f"代理状态需更新 (期望: {record_conf['proxied']}, Cloudflare: {cf_proxied_status_on_cf})")
            add_log_entry(f"记录 '{record_conf['name']}': {'; '.join(log_msg_parts)}。", "INFO")
            if _update_cloudflare_dns_record(zone_id, api_token, cf_dns_record_id, record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"]):
                record_status["message"] = f"DNS 更新成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
                record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else: record_status["message"] = f"DNS 更新失败。"
    else: # Record does not exist on Cloudflare (and API fetch was successful)
        add_log_entry(f"DNS 记录 '{record_conf['name']}' ({record_conf['type']}) 不存在，尝试创建。", "INFO")
        created_record_id = _create_cloudflare_dns_record(zone_id, api_token, record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"])
        if created_record_id:
            record_status["message"] = f"DNS 记录创建成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
            record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else: record_status["message"] = f"DNS 记录创建失败。"
    
    if record_conf["origin_rule_enabled"] and record_conf["name"] and record_conf.get("origin_rule_destination_port"):
        record_conf["origin_rule_description"] = _generate_origin_rule_description(record_conf["name"], record_conf["origin_rule_destination_port"], record_conf["id"])
    else: record_conf["origin_rule_description"] = ""

    add_log_entry(f"--- 并行处理 DNS 记录 {record_conf['name']} ({record_conf['type']}) 完成 ---", "DEBUG")
    return record_status, record_conf


def run_ddns_update_job(manual_trigger=False):
    with APP_STATUS_LOCK:
        if app_status["is_running_update"] and not manual_trigger:
            add_log_entry("DDNS 更新任务已在运行中，跳过此次调度。", "DEBUG")
            return
        app_status["is_running_update"] = True
        app_status["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        app_status["status_message"] = "DDNS 更新任务正在运行..."
    add_log_entry("--- 开始 DDNS 更新检查 ---")

    # Read global config under lock
    with GLOBAL_CONFIG_LOCK:
        cf_api_token = GLOBAL_CONFIG["CF_API_TOKEN"]
        cf_zone_id = GLOBAL_CONFIG["CF_ZONE_ID"]
        enable_ipv4_ddns = GLOBAL_CONFIG["ENABLE_IPV4_DDNS"]
        enable_ipv6_ddns = GLOBAL_CONFIG["ENABLE_IPV6_DDNS"]
        ddns_interface_name = GLOBAL_CONFIG["DDNS_INTERFACE_NAME"]

    if not cf_api_token or not cf_zone_id:
        with APP_STATUS_LOCK:
            app_status["status_message"] = "错误: Cloudflare API Token 或 Zone ID 未配置。"
            app_status["is_running_update"] = False
        add_log_entry(app_status["status_message"], "ERROR")
        _sync_app_status_records_display()
        return

    current_public_ipv4, current_public_ipv6 = None, None
    with APP_STATUS_LOCK: # Lock for updating app_status IP fields
        if enable_ipv4_ddns:
            current_public_ipv4 = get_public_ipv4()
            app_status["current_ipv4"] = current_public_ipv4 if current_public_ipv4 else "获取失败"
        else: app_status["current_ipv4"] = "已禁用 (全局)"
        if enable_ipv6_ddns:
            current_public_ipv6 = get_stable_ipv6_windows(ddns_interface_name) # Pass interface name
            app_status["current_ipv6"] = current_public_ipv6 if current_public_ipv6 else "获取失败"
        else: app_status["current_ipv6"] = "已禁用 (全局)"

    with DDNS_RECORDS_LOCK:
        # Create a copy of records to process to avoid holding lock during long parallel operations
        records_to_process_in_parallel = [dict(r) for r in DDNS_RECORDS]

    if not records_to_process_in_parallel:
        with APP_STATUS_LOCK:
            app_status["status_message"] = "未配置任何 DDNS 记录。"
            app_status["is_running_update"] = False
        add_log_entry(app_status["status_message"], "WARNING")
        _sync_app_status_records_display()
        return

    processed_dns_data_futures = [None] * len(records_to_process_in_parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
        future_to_index = {}
        for i, record_conf_for_thread in enumerate(records_to_process_in_parallel):
            future = executor.submit(_process_single_record_dns_part, 
                                     record_conf_for_thread, 
                                     current_public_ipv4, current_public_ipv6,
                                     cf_zone_id, cf_api_token, # Pass necessary global configs
                                     enable_ipv4_ddns, enable_ipv6_ddns)
            future_to_index[future] = i
            
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                record_status_result, modified_record_conf_result = future.result()
                processed_dns_data_futures[index] = (record_status_result, modified_record_conf_result)
            except Exception as e:
                add_log_entry(f"并行处理记录 {records_to_process_in_parallel[index].get('name', 'Unknown')} 时发生严重错误: {e}", "ERROR")
                original_record_conf = ensure_record_fields(dict(records_to_process_in_parallel[index]))
                error_status = {
                    "id": original_record_conf["id"], "name": original_record_conf["name"], "type": original_record_conf["type"],
                    "proxied": original_record_conf["proxied"], "ttl": original_record_conf["ttl"], "enabled": original_record_conf["enabled"],
                    "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", "message": "并行DNS处理期间发生错误。",
                    "origin_rule_enabled": original_record_conf["origin_rule_enabled"],
                    "origin_rule_destination_port": original_record_conf["origin_rule_destination_port"],
                    "origin_rule_id": original_record_conf["origin_rule_id"], "origin_rule_status_display": "错误"
                }
                processed_dns_data_futures[index] = (error_status, original_record_conf)

    intermediate_records_status, local_records_with_dns_updates_and_origin_intent = [], []
    for i in range(len(records_to_process_in_parallel)):
        if processed_dns_data_futures[i]:
            status_res, conf_res = processed_dns_data_futures[i]
            intermediate_records_status.append(status_res)
            local_records_with_dns_updates_and_origin_intent.append(conf_res)
        else: # Fallback, should ideally not be reached if try-except in loop is robust
            add_log_entry(f"记录 {records_to_process_in_parallel[i].get('name', 'Unknown')} 未收到并行处理结果(严重内部错误)。", "CRITICAL")
            # Construct a minimal error status and use original config
            original_record_conf = ensure_record_fields(dict(records_to_process_in_parallel[i]))
            error_status = {
                "id": original_record_conf["id"], "name": original_record_conf["name"], "type": original_record_conf["type"],
                "message": "未收到并行处理结果(严重内部错误)。", # ... other fields with defaults ...
            }
            intermediate_records_status.append(ensure_record_fields(error_status)) # ensure all fields
            local_records_with_dns_updates_and_origin_intent.append(original_record_conf)


    with APP_STATUS_LOCK: app_status["records_status"] = intermediate_records_status

    final_ddns_records_after_origin_rules, cf_origin_rules_put_success = batch_manage_origin_rules(
        local_records_with_dns_updates_and_origin_intent, cf_zone_id, cf_api_token # Pass zone_id and api_token
    )
    
    needs_records_save = False
    with DDNS_RECORDS_LOCK: # Lock for comparing and updating DDNS_RECORDS
        # Compare original DDNS_RECORDS (or rather, its state before batch_manage) with final_ddns_records_after_origin_rules
        # This is tricky because DDNS_RECORDS itself might have changed if another web request came in.
        # The comparison for needs_records_save should be based on whether `final_ddns_records_after_origin_rules`
        # differs from `local_records_with_dns_updates_and_origin_intent` in origin rule fields.
        for i_idx, record_before_origin_batch in enumerate(local_records_with_dns_updates_and_origin_intent):
            if i_idx < len(final_ddns_records_after_origin_rules): # Ensure index exists
                record_after_origin_batch = final_ddns_records_after_origin_rules[i_idx]
                if (record_before_origin_batch.get("origin_rule_id") != record_after_origin_batch.get("origin_rule_id") or
                    record_before_origin_batch.get("origin_rule_description") != record_after_origin_batch.get("origin_rule_description") or
                    record_before_origin_batch.get("origin_rule_enabled") != record_after_origin_batch.get("origin_rule_enabled")):
                    needs_records_save = True
                    break
            else: # Mismatch in length, indicates a problem, assume save needed
                needs_records_save = True
                add_log_entry("Origin rule processing returned a list of different length than input. Forcing save.", "WARNING")
                break


        if cf_origin_rules_put_success: needs_records_save = True
        if cf_origin_rules_put_success is None:
            add_log_entry("由于 Origin Rule 管理器发生严重故障，记录文件可能不会保存最新的 Origin Rule ID。", "ERROR")
        
        # Update the global DDNS_RECORDS list
        DDNS_RECORDS[:] = final_ddns_records_after_origin_rules

    if needs_records_save:
        add_log_entry("检测到记录的 Origin Rule 相关信息已更改或CF已更新，将保存 DDNS 记录文件。", "INFO")
        save_ddns_records() # This handles its own DDNS_RECORDS_LOCK

    _sync_app_status_records_display() # This handles its own locks

    with APP_STATUS_LOCK:
        app_status["status_message"] = "DDNS 更新检查完成。"
        app_status["is_running_update"] = False
    add_log_entry("--- DDNS 更新检查结束 ---")


# --- Flask Web 应用 ---
flask_app = Flask(__name__)
flask_app.secret_key = os.urandom(24)

@flask_app.before_request
def check_authentication():
    # ADMIN_ACCOUNT_SET is loaded once at start, assume its state is stable for this check
    # or reload it under lock if it could change dynamically post-startup in a way not covered by setup_admin
    if request.endpoint in ['setup_admin', 'login', 'static']: return None
    
    # For ADMIN_ACCOUNT_SET check, ensure it's the latest status if it could be set by another thread
    # However, it's typically set once. If concerned, re-load_admin_credentials here.
    # For simplicity, assume initial load is sufficient for this check across requests.
    _admin_creds_temp = load_admin_credentials() # Ensures ADMIN_ACCOUNT_SET is fresh for this check

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
    admin_creds = load_admin_credentials() # Handles its own lock
    if not ADMIN_ACCOUNT_SET: return redirect(url_for('setup_admin'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if admin_creds and username == admin_creds["username"] and check_password_hash(admin_creds["password_hash"], password):
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
    # Check ADMIN_ACCOUNT_SET status (load_admin_credentials updates it)
    load_admin_credentials() # Ensure ADMIN_ACCOUNT_SET is fresh
    if ADMIN_ACCOUNT_SET and 'logged_in' not in session :
        if request.method == 'GET': flash("管理员账户已设置，请登录。", "info")
        return redirect(url_for('login'))
    if ADMIN_ACCOUNT_SET and 'logged_in' in session:
        flash("管理员账户已设置。", "info")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if not username or not password or not confirm_password: flash("用户名和密码都不能为空！", "error")
        elif password != confirm_password: flash("两次输入的密码不一致！", "error")
        elif len(password) < 6: flash("密码长度至少为6个字符。", "error")
        else:
            hashed_password = generate_password_hash(password)
            if save_admin_credentials(username, hashed_password): # Handles its own lock
                flash("管理员账户设置成功！请登录。", "success")
                add_log_entry(f"管理员账户 '{username}' 首次设置成功。", "INFO")
                return redirect(url_for('login'))
            else:
                flash("保存管理员账户时发生错误。", "error")
                add_log_entry("保存管理员账户失败。", "ERROR")
    return render_template('setup_admin.html')


@flask_app.route('/')
def index():
    with APP_STATUS_LOCK: # Make a shallow copy of app_status for rendering
        status_snapshot = {key: list(val) if isinstance(val, list) else val for key, val in app_status.items()}
    return render_template('index.html', status=status_snapshot, username=session.get('username', '访客'))

@flask_app.route('/trigger_update', methods=['POST'])
def trigger_update():
    add_log_entry("收到手动更新请求。")
    with APP_STATUS_LOCK:
        is_running = app_status["is_running_update"]
    
    if is_running:
        flash("更新任务已在运行中，请稍候。", "warning")
    else:
        manual_update_thread = threading.Thread(target=run_ddns_update_job, kwargs={'manual_trigger': True})
        manual_update_thread.start()
        flash("DDNS 更新检查已触发！状态将在稍后更新。", "success")
    return redirect(url_for('index'))

@flask_app.route('/status_json')
def status_json():
    with APP_STATUS_LOCK: # Make a shallow copy
        status_copy = {key: list(val) if isinstance(val, list) else val for key, val in app_status.items()}
    return jsonify(status_copy)


@flask_app.route('/settings', methods=['GET', 'POST'])
def settings():
    global scheduler # Make sure we're referring to the global scheduler instance
    if request.method == 'POST':
        try:
            with GLOBAL_CONFIG_LOCK: # Lock for modifying GLOBAL_CONFIG
                new_interval_str = request.form.get('interval')
                new_interval = GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] 
                if new_interval_str and new_interval_str.isdigit():
                    parsed_interval = int(new_interval_str)
                    if parsed_interval > 0: new_interval = parsed_interval
                    else: flash("检查间隔必须是大于0的有效整数！旧值将保留。", "error")
                else: flash("检查间隔格式无效！旧值将保留。", "error")

                GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] = new_interval
                GLOBAL_CONFIG["ENABLE_IPV4_DDNS"] = 'enable_ipv4' in request.form
                GLOBAL_CONFIG["ENABLE_IPV6_DDNS"] = 'enable_ipv6' in request.form
                GLOBAL_CONFIG["DDNS_INTERFACE_NAME"] = request.form.get('interface_name', '').strip()
            
            save_global_config() # Handles its own GLOBAL_CONFIG_LOCK for saving
            
            if scheduler.running:
                scheduler.shutdown(wait=True) # Wait for current job to finish
            
            scheduler = BackgroundScheduler(daemon=True) # Re-initialize
            current_interval_for_scheduler = 0
            with GLOBAL_CONFIG_LOCK: # Read interval for scheduler
                current_interval_for_scheduler = GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"]

            if current_interval_for_scheduler > 0:
                scheduler.add_job(run_ddns_update_job, 'interval', minutes=current_interval_for_scheduler, id="ddns_job", replace_existing=True)
                if not scheduler.running: scheduler.start()
                add_log_entry(f"DDNS 自动更新任务间隔已更新为 {current_interval_for_scheduler} 分钟并已调度。", "INFO")
            else:
                add_log_entry("DDNS 自动更新间隔设置为0或无效，任务未调度。", "WARNING")
            
            flash("全局设置已成功更新！", "success")
        except Exception as e:
            add_log_entry(f"保存设置或重置调度器时发生错误: {e}", "ERROR")
            flash(f"保存设置时发生错误: {e}", "error")
        return redirect(url_for('settings'))
    
    with GLOBAL_CONFIG_LOCK: # Read config for display
        current_display_config = GLOBAL_CONFIG.copy()
    return render_template('settings.html', config=current_display_config, username=session.get('username', '访客'))

@flask_app.route('/records', methods=['GET'])
def records_management():
    _sync_app_status_records_display() # Handles its own locks
    with APP_STATUS_LOCK: # Read app_status for rendering
        records_display_list = list(app_status["records_status"]) # Create a copy
    return render_template('records_management.html', records=records_display_list, username=session.get('username', '访客'))

@flask_app.route('/records/add', methods=['GET', 'POST'])
def add_record():
    if request.method == 'POST':
        record_name = request.form['name'].strip()
        record_type = request.form['type'].strip().upper()
        temp_record_for_form = dict(request.form) # For repopulating form on error
        temp_record_for_form['proxied'] = 'proxied' in request.form
        temp_record_for_form['enabled'] = 'enabled' in request.form
        temp_record_for_form['origin_rule_enabled'] = 'origin_rule_enabled' in request.form

        if not record_name or not record_type:
            flash("记录名和类型不能为空！", "error")
            return render_template('record_form.html', record=temp_record_for_form, form_title="添加新记录", username=session.get('username', '访客'))
        if record_type not in ["A", "AAAA"]:
            flash("记录类型只能是 A 或 AAAA！", "error")
            return render_template('record_form.html', record=temp_record_for_form, form_title="添加新记录", username=session.get('username', '访客'))
        
        with DDNS_RECORDS_LOCK: # Check for duplicates under lock
            if any(r['name'].lower() == record_name.lower() and r['type'] == record_type for r in DDNS_RECORDS):
                flash(f"已存在同名同类型的记录: '{record_name}' ({record_type})。", "error")
                return render_template('record_form.html', record=temp_record_for_form, form_title="添加新记录", username=session.get('username', '访客'))

        new_record_data = {
            "name": record_name, "type": record_type,
            "proxied": 'proxied' in request.form, "ttl": int(request.form.get('ttl', 120)),
            "enabled": 'enabled' in request.form, "origin_rule_enabled": 'origin_rule_enabled' in request.form,
            "origin_rule_destination_port": request.form.get('origin_rule_destination_port'),
        }
        if new_record_data["origin_rule_enabled"]:
            dest_port_str = new_record_data["origin_rule_destination_port"]
            if not (dest_port_str and dest_port_str.isdigit() and 1 <= int(dest_port_str) <= 65535):
                flash("启用端口转发时，目标内部端口必须是1-65535之间的有效数字。", "error")
                return render_template('record_form.html', record=temp_record_for_form, form_title="添加新记录", username=session.get('username', '访客'))
            new_record_data["origin_rule_destination_port"] = int(dest_port_str)
        else: new_record_data["origin_rule_destination_port"] = None
        
        new_record_filled = ensure_record_fields(new_record_data)
        if new_record_filled["origin_rule_enabled"] and new_record_filled["name"] and new_record_filled["origin_rule_destination_port"]:
            new_record_filled["origin_rule_description"] = _generate_origin_rule_description(new_record_filled["name"], new_record_filled["origin_rule_destination_port"], new_record_filled["id"])
        
        with DDNS_RECORDS_LOCK: DDNS_RECORDS.append(new_record_filled)
        save_ddns_records() # Handles its own lock
        _sync_app_status_records_display()
        flash(f"记录 '{new_record_filled['name']}' 已成功添加！更改将在下次DDNS检查时同步到Cloudflare。", "success")
        return redirect(url_for('records_management'))
    
    return render_template('record_form.html', record={}, form_title="添加新记录", username=session.get('username', '访客'))

@flask_app.route('/records/edit/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    record_to_edit_orig = None
    with DDNS_RECORDS_LOCK: # Find record under lock
        record_to_edit_orig = next((dict(r) for r in DDNS_RECORDS if r.get("id") == record_id), None) # Get a copy
    
    if not record_to_edit_orig:
        flash("未找到指定记录！", "error")
        return redirect(url_for('records_management'))
    
    record_to_edit = ensure_record_fields(record_to_edit_orig)

    if request.method == 'POST':
        original_name = record_to_edit['name']
        new_record_name = request.form['name'].strip()
        new_record_type = record_to_edit['type'] # Type not editable

        form_data_on_error = dict(record_to_edit)
        form_data_on_error.update(request.form.to_dict(flat=False)) # Get form data, possibly multi-value
        # Ensure checkbox values are correctly interpreted from form
        form_data_on_error['proxied'] = 'proxied' in request.form
        form_data_on_error['enabled'] = 'enabled' in request.form
        form_data_on_error['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
        # Convert single-item lists from to_dict(flat=False) to single values for relevant fields
        for key in ['name', 'ttl', 'origin_rule_destination_port']:
            if key in form_data_on_error and isinstance(form_data_on_error[key], list):
                form_data_on_error[key] = form_data_on_error[key][0] if form_data_on_error[key] else ""


        if not new_record_name:
            flash("记录名不能为空！", "error")
            return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))

        with DDNS_RECORDS_LOCK: # Check for duplicates under lock
            if new_record_name.lower() != original_name.lower() and \
               any(r['id'] != record_id and r['name'].lower() == new_record_name.lower() and r['type'] == new_record_type for r in DDNS_RECORDS):
                flash(f"不能修改为已存在的记录名和类型组合: '{new_record_name}' ({new_record_type})。", "error")
                return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))

        # Update fields in the local copy `record_to_edit`
        record_to_edit['name'] = new_record_name
        record_to_edit['proxied'] = 'proxied' in request.form
        record_to_edit['ttl'] = int(request.form.get('ttl', 120))
        record_to_edit['enabled'] = 'enabled' in request.form
        record_to_edit['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
        dest_port_str = request.form.get('origin_rule_destination_port')

        if record_to_edit['origin_rule_enabled']:
            if not (dest_port_str and dest_port_str.isdigit() and 1 <= int(dest_port_str) <= 65535):
                flash("启用端口转发时，目标内部端口必须是1-65535之间的有效数字。", "error")
                return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))
            record_to_edit['origin_rule_destination_port'] = int(dest_port_str)
        else:
            record_to_edit['origin_rule_destination_port'] = None
            record_to_edit['origin_rule_id'] = None

        if record_to_edit["origin_rule_enabled"] and record_to_edit["name"] and record_to_edit["origin_rule_destination_port"]:
            record_to_edit["origin_rule_description"] = _generate_origin_rule_description(record_to_edit["name"], record_to_edit["origin_rule_destination_port"], record_to_edit["id"])
        else: record_to_edit["origin_rule_description"] = ""
        
        with DDNS_RECORDS_LOCK: # Update the actual DDNS_RECORDS list
            found_index = -1
            for i, r_loop_var in enumerate(DDNS_RECORDS):
                if r_loop_var["id"] == record_id:
                    DDNS_RECORDS[i] = record_to_edit
                    found_index = i
                    break
            if found_index == -1: # Should not happen if initial find was successful
                flash("更新记录时发生内部错误，未找到记录的索引。", "error")
                return redirect(url_for('records_management'))

        save_ddns_records()
        _sync_app_status_records_display()
        flash(f"记录 '{record_to_edit['name']}' 已成功更新！更改将在下次DDNS检查时完全同步到Cloudflare。", "success")
        return redirect(url_for('records_management'))
    
    return render_template('record_form.html', record=record_to_edit, form_title=f"编辑记录: {record_to_edit['name']}", username=session.get('username', '访客'))


@flask_app.route('/records/delete/<record_id>', methods=['POST'])
def delete_record(record_id):
    record_to_delete_local_copy = None
    with DDNS_RECORDS_LOCK: # Get a copy of the record to delete
        record_found = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
        if record_found:
            record_to_delete_local_copy = dict(record_found) # Work with a copy for CF operations

    if not record_to_delete_local_copy:
        flash("未找到要删除的本地记录。", "error")
        return redirect(url_for('records_management'))

    record_name = record_to_delete_local_copy['name']
    record_type = record_to_delete_local_copy['type'] # Needed for _get_cloudflare_dns_record

    with GLOBAL_CONFIG_LOCK: # Get API token and Zone ID
        api_token = GLOBAL_CONFIG['CF_API_TOKEN']
        zone_id = GLOBAL_CONFIG['CF_ZONE_ID']
    
    if not api_token or not zone_id:
        flash("Cloudflare API Token 或 Zone ID 未配置，无法删除记录。", "error")
        return redirect(url_for('records_management'))

    try:
        origin_rule_deleted_ok = True
        if record_to_delete_local_copy.get("origin_rule_id") or record_to_delete_local_copy.get("origin_rule_description"):
            ruleset = _get_origin_ruleset(zone_id, api_token)
            if ruleset:
                current_rules = ruleset.get("rules", [])
                rule_id_to_remove = record_to_delete_local_copy.get("origin_rule_id")
                rule_desc_to_remove = record_to_delete_local_copy.get("origin_rule_description")
                filtered_rules, changed_ruleset = [], False
                for r_rule in current_rules:
                    if r_rule.get("id") == rule_id_to_remove and rule_id_to_remove:
                        changed_ruleset = True; add_log_entry(f"记录 {record_name}: 准备从CF删除Origin Rule ID {rule_id_to_remove}", "INFO"); continue
                    if r_rule.get("description") == rule_desc_to_remove and rule_desc_to_remove and not rule_id_to_remove:
                        changed_ruleset = True; add_log_entry(f"记录 {record_name}: 准备从CF删除Origin Rule Desc {rule_desc_to_remove}", "INFO"); continue
                    filtered_rules.append(r_rule)
                if changed_ruleset:
                    update_response = _update_origin_ruleset(zone_id, api_token, filtered_rules, ruleset.get("description"))
                    if not (update_response and update_response.get("success")):
                        origin_rule_deleted_ok = False; flash(f"从 Cloudflare 删除记录 '{record_name}' 的 Origin Rule 失败。", "error")
            else: origin_rule_deleted_ok = False; flash(f"获取 Origin Ruleset 失败，无法为 '{record_name}' 删除 Origin Rule。", "error")
        
        dns_deleted_ok = True
        if origin_rule_deleted_ok:
            cf_dns_info_or_error = _get_cloudflare_dns_record(zone_id, api_token, record_name, record_type)
            if isinstance(cf_dns_info_or_error, dict) and "error_response" in cf_dns_info_or_error:
                dns_deleted_ok = False; flash(f"记录 {record_name}: 无法确认 Cloudflare DNS 记录状态 (API查询失败)。", "error")
            elif cf_dns_info_or_error and cf_dns_info_or_error.get("id"): # Record exists
                if not _delete_cloudflare_dns_record(zone_id, api_token, cf_dns_info_or_error.get("id")):
                    dns_deleted_ok = False; flash(f"从 Cloudflare 删除 DNS 记录 '{record_name}' 失败。", "error")
            elif cf_dns_info_or_error is None: # Record not found, which is fine for deletion
                 add_log_entry(f"DNS 记录 '{record_name}' 在 Cloudflare 上未找到，无需删除。", "INFO")
            # If cf_dns_info_or_error is some other non-error dict but without 'id', it's unexpected. Assume cannot delete.
            elif isinstance(cf_dns_info_or_error, dict) and not cf_dns_info_or_error.get("id"):
                dns_deleted_ok = False; flash(f"记录 {record_name}: 获取到的DNS记录信息不完整，无法删除。", "error")


        if origin_rule_deleted_ok and dns_deleted_ok:
            with DDNS_RECORDS_LOCK: # Remove from local list
                DDNS_RECORDS[:] = [r for r in DDNS_RECORDS if r.get("id") != record_id]
            save_ddns_records()
            _sync_app_status_records_display()
            flash(f"记录 '{record_name}' 已成功从本地和 Cloudflare 删除。", "success")
        else:
             flash(f"记录 '{record_name}' 未能完全从 Cloudflare 删除，本地记录未移除。请检查日志。", "error")
             _sync_app_status_records_display()
    except Exception as e:
        add_log_entry(f"删除记录 '{record_name}' 时发生意外错误: {e}", "ERROR")
        flash(f"删除记录时发生意外错误: {e}", "error")
        _sync_app_status_records_display()
    return redirect(url_for('records_management'))


@flask_app.route('/records/toggle/<record_id>', methods=['POST'])
def toggle_record(record_id):
    updated = False
    with DDNS_RECORDS_LOCK: # Lock for modifying DDNS_RECORDS
        record_to_toggle = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
        if record_to_toggle:
            record_to_toggle['enabled'] = not record_to_toggle['enabled']
            if not record_to_toggle['enabled']:
                record_to_toggle['origin_rule_enabled'] = False
                record_to_toggle['origin_rule_id'] = None
                record_to_toggle['origin_rule_description'] = ""
            updated = True
            flash_msg = f"记录 '{record_to_toggle['name']}' DDNS 更新已{'启用' if record_to_toggle['enabled'] else '禁用'}。"
        else: flash_msg = "未找到指定记录以切换状态。"
    
    if updated:
        save_ddns_records()
        _sync_app_status_records_display()
        flash(flash_msg, "success" if record_to_toggle else "error")
    else:
        flash(flash_msg, "error")
    return redirect(url_for('records_management'))

def _delete_single_dns_record_task(record_info, zone_id, api_token):
    record_id, record_name, record_type = record_info['id'], record_info['name'], record_info['type']
    dns_deleted_ok, message = True, ""
    try:
        cf_dns_info_or_error = _get_cloudflare_dns_record(zone_id, api_token, record_name, record_type)
        if isinstance(cf_dns_info_or_error, dict) and "error_response" in cf_dns_info_or_error:
            dns_deleted_ok = False; message = f"记录 {record_name}: 无法确认Cloudflare DNS记录 (API错误)."
        elif cf_dns_info_or_error and cf_dns_info_or_error.get("id"):
            if not _delete_cloudflare_dns_record(zone_id, api_token, cf_dns_info_or_error.get("id")):
                dns_deleted_ok = False; message = f"记录 {record_name}: Cloudflare DNS 记录删除失败。"
        elif cf_dns_info_or_error is None: # Not found, okay for deletion
            message = f"记录 {record_name}: Cloudflare DNS 记录未找到，无需删除。"
        elif isinstance(cf_dns_info_or_error, dict) and not cf_dns_info_or_error.get("id"): # Unexpected response
            dns_deleted_ok = False; message = f"记录 {record_name}: 获取到的DNS记录信息不完整。"

    except Exception as e:
        dns_deleted_ok = False; message = f"记录 {record_name}: 删除DNS记录时发生异常: {e}"
        add_log_entry(message, "ERROR")
    return record_id, dns_deleted_ok, message

@flask_app.route('/records/batch_delete', methods=['POST'])
def batch_delete_records():
    data = request.get_json()
    record_ids_to_delete = data.get('record_ids', [])
    if not record_ids_to_delete:
        return jsonify(success=False, message="未提供任何记录ID。"), 400

    add_log_entry(f"收到批量删除请求，涉及本地记录IDs: {record_ids_to_delete}", "INFO")
    
    successfully_removed_local_ids = set()
    overall_success_count, overall_failure_count = 0, 0
    messages = []

    with GLOBAL_CONFIG_LOCK: # Get API token and Zone ID
        api_token = GLOBAL_CONFIG['CF_API_TOKEN']
        zone_id = GLOBAL_CONFIG['CF_ZONE_ID']
    
    if not api_token or not zone_id:
        return jsonify(success=False, message="Cloudflare API Token 或 Zone ID 未配置。"), 500

    temp_ddns_records_for_origin_batch = []
    records_info_for_dns_deletion = {}
    with DDNS_RECORDS_LOCK: # Prepare records for batch operations
        for rec_orig in DDNS_RECORDS:
            rec_copy = dict(rec_orig) # Work with copies
            if rec_copy["id"] in record_ids_to_delete:
                rec_copy["origin_rule_enabled"] = False # Signal disable for batch Origin Rule processing
                records_info_for_dns_deletion[rec_copy["id"]] = dict(rec_orig) # Store original copy for DNS deletion
            temp_ddns_records_for_origin_batch.append(rec_copy)

    updated_records_after_origin_batch, cf_origin_rules_put_success = batch_manage_origin_rules(
        temp_ddns_records_for_origin_batch, zone_id, api_token
    )
    if cf_origin_rules_put_success is None: messages.append("批量删除Origin Rules失败: 无法获取当前Cloudflare规则集。")
    elif not cf_origin_rules_put_success: messages.append("批量删除Origin Rules失败: 更新Cloudflare规则集时出错。")

    dns_deletion_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
        future_to_record_id = {
            executor.submit(_delete_single_dns_record_task, records_info_for_dns_deletion[r_id], zone_id, api_token): r_id
            for r_id in record_ids_to_delete if r_id in records_info_for_dns_deletion
        }
        for future in concurrent.futures.as_completed(future_to_record_id):
            record_id = future_to_record_id[future]
            try:
                r_id, dns_deleted_ok, msg = future.result()
                dns_deletion_results[r_id] = {"success": dns_deleted_ok, "message": msg}
            except Exception as e:
                dns_deletion_results[record_id] = {"success": False, "message": f"记录 {record_id}: DNS删除任务异常: {e}"}
                add_log_entry(f"记录 {record_id}: DNS删除任务异常: {e}", "ERROR")

    for r_id in record_ids_to_delete:
        r_info_original = records_info_for_dns_deletion.get(r_id) # Use the copy made earlier
        if not r_info_original:
            messages.append(f"记录ID {r_id}: 未在待删除记录信息中找到，跳过处理。"); overall_failure_count += 1; continue

        dns_result = dns_deletion_results.get(r_id, {"success": False, "message": f"记录 {r_id}: DNS删除结果缺失。"})
        dns_deleted_ok = dns_result["success"]
        if dns_result["message"]: messages.append(dns_result["message"])

        record_origin_rule_handled_successfully = False
        if cf_origin_rules_put_success: record_origin_rule_handled_successfully = True
        elif not cf_origin_rules_put_success and not r_info_original.get("origin_rule_enabled") and not r_info_original.get("origin_rule_id"):
            record_origin_rule_handled_successfully = True # No rule to handle, so considered "handled"
        
        if record_origin_rule_handled_successfully and dns_deleted_ok:
            successfully_removed_local_ids.add(r_id); overall_success_count += 1
        else:
            overall_failure_count += 1
            if not record_origin_rule_handled_successfully and cf_origin_rules_put_success is not True:
                if not any("Origin Rules失败" in msg for msg in messages):
                    messages.append(f"记录 {r_info_original['name']}: Origin Rule 删除可能未成功。")
    
    if successfully_removed_local_ids:
        with DDNS_RECORDS_LOCK:
            DDNS_RECORDS[:] = [r for r in DDNS_RECORDS if r.get("id") not in successfully_removed_local_ids]
        save_ddns_records()
    
    _sync_app_status_records_display()
    final_message = f"批量删除完成。成功从CF移除并从本地删除: {overall_success_count}。部分或完全失败: {overall_failure_count}。详情: {' '.join(sorted(list(set(messages))))}"
    add_log_entry(final_message, "INFO")
    return jsonify(success=overall_failure_count == 0, message=final_message)


@flask_app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings():
    admin_creds = load_admin_credentials() # Handles lock
    if not admin_creds:
        flash("管理员账户信息缺失。", "error"); return redirect(url_for('index'))
        
    with GLOBAL_CONFIG_LOCK: # Read GLOBAL_CONFIG for display
        current_display_config = GLOBAL_CONFIG.copy()
        if GLOBAL_CONFIG["CF_API_TOKEN"]:
            token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
            current_display_config["CF_API_TOKEN_DISPLAY"] = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:] if token_len > 8 else "****"
        else: current_display_config["CF_API_TOKEN_DISPLAY"] = ""


    if request.method == 'POST':
        form_type = request.form.get('form_type')
        action_taken = False
        if form_type == 'password_change':
            # Password change logic (no direct GLOBAL_CONFIG access)
            old_password = request.form.get('old_password', '').strip()
            new_password = request.form.get('new_password', '').strip()
            confirm_new_password = request.form.get('confirm_new_password', '').strip()
            if not old_password and (new_password or confirm_new_password): flash("如需修改密码，请输入当前密码。", "error")
            elif old_password:
                if not check_password_hash(admin_creds["password_hash"], old_password): flash("当前密码不正确。", "error")
                elif not new_password and not confirm_new_password: flash("未输入新密码，密码未更改。", "info")
                elif not new_password or not confirm_new_password: flash("新密码和确认密码均不能为空。", "error")
                elif new_password != confirm_new_password: flash("新密码和确认密码不一致。", "error")
                elif len(new_password) < 6: flash("新密码长度至少为6个字符。", "error")
                else:
                    new_hashed_password = generate_password_hash(new_password)
                    if save_admin_credentials(admin_creds["username"], new_hashed_password): # Handles lock
                        flash("管理员密码已成功修改！请重新登录。", "success")
                        session.pop('logged_in', None); session.pop('username', None)
                        action_taken = True; return redirect(url_for('login'))
                    else: flash("修改密码时发生错误。", "error")
        elif form_type == 'api_config_change':
            new_api_token_form = request.form.get('cf_api_token', '').strip()
            new_zone_id_form = request.form.get('cf_zone_id', '').strip()
            
            with GLOBAL_CONFIG_LOCK: # Lock for modifying GLOBAL_CONFIG
                actual_new_api_token = GLOBAL_CONFIG["CF_API_TOKEN"] # Default to old
                # If form field is different from the masked display OR if original token was empty, take form value
                if new_api_token_form != current_display_config["CF_API_TOKEN_DISPLAY"] or not GLOBAL_CONFIG["CF_API_TOKEN"]:
                    actual_new_api_token = new_api_token_form

                if not actual_new_api_token or not new_zone_id_form:
                    flash("API Token 和 Zone ID 均不能为空！", "error")
                else:
                    token_changed = GLOBAL_CONFIG["CF_API_TOKEN"] != actual_new_api_token
                    zone_id_changed = GLOBAL_CONFIG["CF_ZONE_ID"] != new_zone_id_form
                    if token_changed or zone_id_changed:
                        GLOBAL_CONFIG["CF_API_TOKEN"] = actual_new_api_token
                        GLOBAL_CONFIG["CF_ZONE_ID"] = new_zone_id_form
                        log_msgs = []
                        if token_changed: log_msgs.append("API Token 已更新"); add_log_entry("CF API Token 已更新。", "INFO")
                        if zone_id_changed: log_msgs.append("Zone ID 已更新"); add_log_entry("CF Zone ID 已更新。", "INFO")
                        flash(f"Cloudflare API 设置已成功更新 ({', '.join(log_msgs)})！", "success")
                        action_taken = True
                    else: flash("API 设置未发生变化。", "info")
            if action_taken and (token_changed or zone_id_changed): # Save only if changes were made under lock
                 save_global_config() # Handles its own lock

        else: flash("无效的表单提交。", "error")
        if action_taken: return redirect(url_for('admin_settings'))
            
    return render_template('admin_settings.html', username=session.get('username'), current_config=current_display_config)


# --- 主程序和调度器 ---
scheduler = BackgroundScheduler(daemon=True)

if __name__ == '__main__':
    load_all_config() # Handles its own locks for initial load
    initial_run_thread = threading.Thread(target=run_ddns_update_job)
    initial_run_thread.start()
    
    with GLOBAL_CONFIG_LOCK: # Read interval for scheduler setup
        interval_minutes = GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"]
    
    if interval_minutes > 0:
        scheduler.add_job(run_ddns_update_job, 'interval', minutes=interval_minutes, id="ddns_job", replace_existing=True)
        scheduler.start()
        add_log_entry(f"DDNS 自动更新任务已设置，每 {interval_minutes} 分钟运行一次。")
    else:
        add_log_entry("DDNS 自动更新间隔设置为0或无效，任务未调度。", "WARNING")
    
    try:
        add_log_entry("启动 Flask Web 服务器...")
        flask_app.run(host='::', port=5000, debug=False)
    except (KeyboardInterrupt, SystemExit):
        add_log_entry("接收到关闭信号...", "INFO")
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=True) # Wait for jobs to complete
            add_log_entry("调度器已关闭。")
        add_log_entry("DDNS 应用已关闭。")

