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
        record_conf = ensure_record_fields(dict(record_conf_orig)) 
        record_id = record_conf["id"]
        
        current_record_status = {
            "id": record_id,
            "name": record_conf["name"],
            "type": record_conf["type"],
            "proxied": record_conf["proxied"], # Use local proxied status for display
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
                 current_record_status["origin_rule_status_display"] = f"已启用 -> {record_conf['origin_rule_destination_port']} (ID: ...{record_conf['origin_rule_id'][-6:]})"
            else:
                 current_record_status["origin_rule_status_display"] = f"启用中 (待创建) -> {record_conf['origin_rule_destination_port']}"
        elif record_conf["origin_rule_enabled"]:
             current_record_status["origin_rule_status_display"] = "配置不完整"


        if record_id in old_records_status_map:
            old_status = old_records_status_map[record_id]
            if old_status.get("type") == record_conf["type"]: 
                current_record_status["local_ip"] = old_status.get("local_ip", "N/A")
                current_record_status["cloudflare_ip"] = old_status.get("cloudflare_ip", "N/A")
                current_record_status["last_updated_cloudflare"] = old_status.get("last_updated_cloudflare", "N/A")
                current_record_status["message"] = old_status.get("message", "待检查...")
            else:
                current_record_status["message"] = f"类型已更改为 {record_conf['type']}，待检查..."
        
        if not record_conf["enabled"]:
            current_record_status["message"] = "此记录已禁用。"
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
        add_log_entry(f"Cloudflare API 请求失败 ({method} {url}): {e}", "ERROR")
        if hasattr(e, 'response') and e.response is not None:
            try: add_log_entry(f"API 错误详情: {e.response.json()}", "ERROR")
            except ValueError: add_log_entry(f"API 错误详情 (非JSON): {e.response.text}", "ERROR")
        return None

def _get_cloudflare_dns_record(record_name, record_type):
    endpoint = f"/zones/{GLOBAL_CONFIG['CF_ZONE_ID']}/dns_records"
    params = {"type": record_type, "name": record_name}
    data = _cf_api_request("GET", endpoint, params=params)
    if data and data.get("success"):
        if data["result"]:
            # Return full record details for proxy status check
            record = data["result"][0]
            add_log_entry(f"Cloudflare 记录 '{record_name}' ({record_type}) 当前 IP: {record['content']}, ID: {record['id']}, Proxied: {record.get('proxied', False)}", "DEBUG")
            return record # Return the whole record object
        else:
            add_log_entry(f"在 Cloudflare 上未找到名为 '{record_name}' 的 {record_type} 记录。", "INFO") 
            return None # Changed from (None, None) to just None
    else:
        add_log_entry(f"从 Cloudflare 获取 DNS 记录 '{record_name}' ({record_type}) 失败。", "ERROR")
        return None # Changed from (None, None) to just None

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
        return True 
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
    add_log_entry("获取 Origin Ruleset 失败或为空。", "ERROR" if response else "WARNING")
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
        return response.get("result") 
    add_log_entry("更新 Origin Ruleset 失败。", "ERROR")
    return None

def _generate_origin_rule_description(record_name, dest_port, local_record_id):
    short_local_id = local_record_id.split('-')[0] 
    return f"ddns_fwd_{record_name}_to{dest_port}_id{short_local_id}" 


def manage_cloudflare_origin_rule(local_record):
    record_name = local_record["name"]
    should_be_enabled = local_record["origin_rule_enabled"]
    dest_port = local_record.get("origin_rule_destination_port")
    existing_rule_id = local_record.get("origin_rule_id")
    
    expected_description = local_record.get("origin_rule_description")
    if not expected_description and should_be_enabled and record_name and dest_port:
        expected_description = _generate_origin_rule_description(record_name, dest_port, local_record["id"])
        local_record["origin_rule_description"] = expected_description


    ruleset = _get_origin_ruleset()
    if ruleset is None: 
        add_log_entry(f"无法管理 Origin Rule for {record_name}: 获取当前规则集失败。", "ERROR")
        return None 

    current_rules = ruleset.get("rules", [])
    found_rule_by_id = None
    found_rule_by_desc = None

    if existing_rule_id:
        found_rule_by_id = next((rule for rule in current_rules if rule.get("id") == existing_rule_id), None)
    
    if expected_description:
        found_rule_by_desc = next((rule for rule in current_rules if rule.get("description") == expected_description), None)

    actual_existing_rule_on_cf = found_rule_by_id or found_rule_by_desc
    if actual_existing_rule_on_cf and not existing_rule_id: 
        add_log_entry(f"Origin Rule for {record_name} (desc: {expected_description}) found on CF (ID: {actual_existing_rule_on_cf['id']}), updating local record ID.", "INFO")
        local_record["origin_rule_id"] = actual_existing_rule_on_cf['id']
        existing_rule_id = actual_existing_rule_on_cf['id'] 


    if should_be_enabled:
        if not record_name or not dest_port:
            add_log_entry(f"无法创建 Origin Rule for {record_name}: 主机名或目标内部端口未配置。", "WARNING")
            if existing_rule_id and actual_existing_rule_on_cf:
                current_rules = [rule for rule in current_rules if rule.get("id") != existing_rule_id]
                if _update_origin_ruleset(current_rules, ruleset.get("description")):
                    add_log_entry(f"因配置不完整，已删除旧的 Origin Rule (ID: {existing_rule_id}) for {record_name}。", "INFO")
                    local_record["origin_rule_id"] = None
                    local_record["origin_rule_description"] = "" 
                else:
                    add_log_entry(f"因配置不完整，尝试删除旧 Origin Rule (ID: {existing_rule_id}) for {record_name} 失败。", "ERROR")
                    return None 
            return local_record 

        new_rule_definition = {
            "action": "route",
            "action_parameters": {
                "origin": { 
                    "port": int(dest_port) 
                }
            },
            "expression": f'(http.host eq "{record_name}")', 
            "description": expected_description,
            "enabled": True
        }

        rule_updated_or_created = False
        if actual_existing_rule_on_cf: 
            current_action_params = actual_existing_rule_on_cf.get("action_parameters", {})
            current_origin_params = current_action_params.get("origin", {})
            
            if (actual_existing_rule_on_cf.get("action") != new_rule_definition["action"] or
                current_origin_params.get("port") != int(dest_port) or 
                actual_existing_rule_on_cf.get("expression") != new_rule_definition["expression"] or 
                not actual_existing_rule_on_cf.get("enabled")):
                
                add_log_entry(f"Origin Rule (ID: {existing_rule_id}) for {record_name} 需要更新。", "INFO")
                new_rule_definition["id"] = existing_rule_id 
                updated_rules_list = [] # Create a new list for modification
                for r_val in current_rules: 
                    if r_val.get("id") == existing_rule_id:
                        updated_rules_list.append(new_rule_definition)
                    else:
                        updated_rules_list.append(r_val)
                current_rules = updated_rules_list # Assign the new list back
                rule_updated_or_created = True
            else:
                add_log_entry(f"Origin Rule (ID: {existing_rule_id}) for {record_name} 已是最新，无需更新。", "DEBUG")
                local_record["origin_rule_id"] = existing_rule_id 
                return local_record 
        else: 
            add_log_entry(f"为 {record_name} 创建新的 Origin Rule (Desc: {expected_description})。", "INFO")
            current_rules.append(new_rule_definition)
            rule_updated_or_created = True
        
        if rule_updated_or_created:
            updated_ruleset_response = _update_origin_ruleset(current_rules, ruleset.get("description"))
            if updated_ruleset_response:
                final_rule_on_cf = next((r for r in updated_ruleset_response.get("rules", []) if r.get("description") == expected_description), None)
                if final_rule_on_cf and final_rule_on_cf.get("id"):
                    local_record["origin_rule_id"] = final_rule_on_cf["id"]
                    add_log_entry(f"Origin Rule for {record_name} 已成功应用/更新 (New ID: {final_rule_on_cf['id']})。", "INFO")
                else: 
                    add_log_entry(f"Origin Rule for {record_name} 应用后无法在响应中通过描述找到，请手动检查Cloudflare。", "ERROR")
                    local_record["origin_rule_id"] = None 
                return local_record
            else: 
                add_log_entry(f"应用/更新 Origin Rule for {record_name} 失败。", "ERROR")
                if not existing_rule_id: 
                    local_record["origin_rule_enabled"] = False
                    local_record["origin_rule_id"] = None
                    local_record["origin_rule_description"] = ""
                return None 

    elif not should_be_enabled and actual_existing_rule_on_cf: 
        add_log_entry(f"正在禁用/删除 Origin Rule (ID: {existing_rule_id}, Desc: {actual_existing_rule_on_cf.get('description')}) for {record_name}。", "INFO")
        current_rules = [rule for rule in current_rules if rule.get("id") != existing_rule_id]
        if _update_origin_ruleset(current_rules, ruleset.get("description")):
            add_log_entry(f"Origin Rule (ID: {existing_rule_id}) for {record_name} 已成功从Cloudflare规则集中移除。", "INFO")
            local_record["origin_rule_id"] = None
            local_record["origin_rule_description"] = "" 
            local_record["origin_rule_enabled"] = False 
        else:
            add_log_entry(f"从Cloudflare规则集中移除 Origin Rule (ID: {existing_rule_id}) for {record_name} 失败。", "ERROR")
            return None 
    
    return local_record 


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
    
    current_run_records_status = []

    if not DDNS_RECORDS:
        app_status["status_message"] = "未配置任何 DDNS 记录。"
        add_log_entry(app_status["status_message"], "WARNING")
        app_status["is_running_update"] = False
        _sync_app_status_records_display() 
        return

    needs_records_save = False # Flag to save DDNS_RECORDS if any origin rule ID changes

    for i, record_conf_orig in enumerate(DDNS_RECORDS):
        record_conf = ensure_record_fields(dict(record_conf_orig))

        record_status = {
            "id": record_conf["id"], "name": record_conf["name"], "type": record_conf["type"],
            "proxied": record_conf["proxied"], "ttl": record_conf["ttl"], "enabled": record_conf["enabled"],
            "local_ip": "N/A", "cloudflare_ip": "N/A", "last_updated_cloudflare": "N/A", "message": "",
            "origin_rule_enabled": record_conf["origin_rule_enabled"],
            "origin_rule_destination_port": record_conf["origin_rule_destination_port"],
            "origin_rule_id": record_conf["origin_rule_id"],
            "origin_rule_status_display": "禁用"
        }
        if record_conf["origin_rule_enabled"] and record_conf["origin_rule_destination_port"]:
            if record_conf["origin_rule_id"]:
                 record_status["origin_rule_status_display"] = f"已启用 -> {record_conf['origin_rule_destination_port']}"
            else:
                 record_status["origin_rule_status_display"] = f"启用中 (待创建) -> {record_conf['origin_rule_destination_port']}"
        elif record_conf["origin_rule_enabled"]:
             record_status["origin_rule_status_display"] = "配置不完整"


        if not record_conf["enabled"]:
            record_status["message"] = "此记录已禁用。"
            current_run_records_status.append(record_status)
            add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 已禁用，跳过更新。", "INFO")
            continue

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
            current_run_records_status.append(record_status)
            add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}): {record_status['message']}", "INFO")
            continue

        if not target_ip:
            record_status["message"] = f"未能获取当前公网 {ip_type_for_log} 地址。"
            current_run_records_status.append(record_status)
            add_log_entry(f"记录 '{record_conf['name']}' ({record_conf['type']}) 未能获取目标IP，跳过更新。", "ERROR")
            continue

        add_log_entry(f"--- 处理 DNS 记录: {record_conf['name']} ({record_conf['type']}) ---")
        
        # Get full CF DNS record to check current proxied status
        cf_dns_full_record = _get_cloudflare_dns_record(record_conf["name"], record_conf["type"])
        
        cf_dns_record_id = None
        cloudflare_ip = None
        cf_proxied_status = None

        if cf_dns_full_record:
            cf_dns_record_id = cf_dns_full_record.get("id")
            cloudflare_ip = cf_dns_full_record.get("content")
            cf_proxied_status = cf_dns_full_record.get("proxied", False) # Get actual proxied status
        
        record_status["cloudflare_ip"] = cloudflare_ip if cloudflare_ip else "未找到/失败"
        # Update displayed proxied status based on what's actually on Cloudflare if record exists
        # However, our local config's proxied is the source of truth for *updates*.
        # For display consistency in the table, we use the local config's `proxied` value.
        # The `_sync_app_status_records_display` already does this.

        dns_updated_this_run = False
        # Compare target IP and also the proxied status from local config vs actual CF status
        ip_needs_update = (target_ip != cloudflare_ip)
        proxy_needs_update = (record_conf["proxied"] != cf_proxied_status if cf_dns_full_record else False) # Only if record exists

        if cf_dns_record_id:
            if not ip_needs_update and not proxy_needs_update:
                record_status["message"] = f"DNS IP ({target_ip}) 及代理状态 ({'启用' if record_conf['proxied'] else '禁用'}) 未更改。"
            else:
                log_msg_parts = []
                if ip_needs_update: log_msg_parts.append(f"IP 地址已更改 (本机: {target_ip}, Cloudflare: {cloudflare_ip})")
                if proxy_needs_update: log_msg_parts.append(f"代理状态需更新 (期望: {'启用' if record_conf['proxied'] else '禁用'}, Cloudflare: {'启用' if cf_proxied_status else '禁用'})")
                add_log_entry(f"记录 '{record_conf['name']}': {'; '.join(log_msg_parts)}。")

                if _update_cloudflare_dns_record(cf_dns_record_id, record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"]):
                    record_status["message"] = f"DNS 更新成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
                    record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    dns_updated_this_run = True
                else:
                    record_status["message"] = f"DNS 更新失败。"
        else: 
            if cloudflare_ip is None : # Explicitly means not found, rather than API error during fetch
                add_log_entry(f"DNS 记录 '{record_conf['name']}' ({record_conf['type']}) 不存在，尝试创建。")
                if _create_cloudflare_dns_record(record_conf["name"], record_conf["type"], target_ip, record_conf["ttl"], record_conf["proxied"]):
                    record_status["message"] = f"DNS 记录创建成功 (IP: {target_ip}, 代理: {'启用' if record_conf['proxied'] else '禁用'})。"
                    record_status["last_updated_cloudflare"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    dns_updated_this_run = True
                else:
                    record_status["message"] = f"DNS 记录创建失败。"
            else: 
                 record_status["message"] = "获取 Cloudflare DNS 记录信息失败。"
        
        # Manage Origin Rule
        original_origin_rule_id = record_conf.get("origin_rule_id")
        updated_record_conf_after_origin_rule = manage_cloudflare_origin_rule(record_conf) # This modifies record_conf
        
        if updated_record_conf_after_origin_rule:
            # Check if the origin rule ID was changed by manage_cloudflare_origin_rule
            if original_origin_rule_id != updated_record_conf_after_origin_rule.get("origin_rule_id"):
                needs_records_save = True # Mark that DDNS_RECORDS needs to be saved
            
            DDNS_RECORDS[i] = updated_record_conf_after_origin_rule # Persist changes to main list
            
            # Update record_status with potentially new origin rule info
            record_status["origin_rule_enabled"] = updated_record_conf_after_origin_rule["origin_rule_enabled"]
            record_status["origin_rule_destination_port"] = updated_record_conf_after_origin_rule["origin_rule_destination_port"]
            record_status["origin_rule_id"] = updated_record_conf_after_origin_rule["origin_rule_id"]
            if updated_record_conf_after_origin_rule["origin_rule_enabled"] and updated_record_conf_after_origin_rule["origin_rule_destination_port"]:
                 record_status["origin_rule_status_display"] = f"已启用 -> {updated_record_conf_after_origin_rule['origin_rule_destination_port']}"
                 if not updated_record_conf_after_origin_rule["origin_rule_id"]: record_status["origin_rule_status_display"] += " (创建中)"
            elif updated_record_conf_after_origin_rule["origin_rule_enabled"]:
                 record_status["origin_rule_status_display"] = "配置不完整"
            else:
                 record_status["origin_rule_status_display"] = "禁用"
        else: # Critical failure in origin rule management
            record_status["message"] += " Origin Rule 操作失败。" 
            # Ensure local state reflects that origin rule is not considered active if management failed
            record_status["origin_rule_enabled"] = False 
            record_status["origin_rule_status_display"] = "操作失败"
            DDNS_RECORDS[i]["origin_rule_enabled"] = False # Also update the source of truth
            DDNS_RECORDS[i]["origin_rule_id"] = None
            needs_records_save = True


        current_run_records_status.append(record_status)
        add_log_entry(f"--- 记录 {record_conf['name']} ({record_conf['type']}) 处理完毕 ---")

    app_status["records_status"] = current_run_records_status 
    if needs_records_save:
        save_ddns_records() 

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
    if ADMIN_ACCOUNT_SET:
        flash("管理员账户已设置，请登录。", "info")
        return redirect(url_for('login'))
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
    status_snapshot = {key: list(val) if isinstance(val, list) else val for key, val in app_status.items()}
    return render_template('index.html', status=status_snapshot, username=session.get('username', '访客'))

@flask_app.route('/trigger_update', methods=['POST'])
def trigger_update():
    add_log_entry("收到手动更新请求。")
    if app_status["is_running_update"]:
        flash("更新任务已在运行中，请稍候。", "warning")
    else:
        run_ddns_update_job(manual_trigger=True) 
        flash("DDNS 更新检查已触发！", "success")
    return redirect(url_for('index'))

@flask_app.route('/status_json')
def status_json(): 
    return jsonify({key: list(val) if isinstance(val, list) else val for key, val in app_status.items()})


@flask_app.route('/settings', methods=['GET', 'POST'])
def settings():
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
            if scheduler.running: scheduler.shutdown() 
            scheduler = BackgroundScheduler(daemon=True) 
            if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
                scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
                scheduler.start()
                add_log_entry(f"DDNS 自动更新任务间隔已更新为 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟。", "INFO")
            else: add_log_entry("DDNS 自动更新间隔设置为0或无效。", "WARNING")
            flash("全局设置已成功更新！", "success")
        except Exception as e:
            add_log_entry(f"保存设置时发生错误: {e}", "ERROR")
            flash(f"保存设置时发生错误: {e}", "error")
        return redirect(url_for('settings'))
    return render_template('settings.html', config=GLOBAL_CONFIG, username=session.get('username', '访客'))

@flask_app.route('/records', methods=['GET'])
def records_management():
    _sync_app_status_records_display() 
    return render_template('records_management.html', records=app_status["records_status"], username=session.get('username', '访客'))

@flask_app.route('/records/add', methods=['GET', 'POST'])
def add_record():
    if request.method == 'POST':
        record_name = request.form['name'].strip()
        record_type = request.form['type'].strip().upper()
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
            "enabled": 'enabled' in request.form,
            "origin_rule_enabled": 'origin_rule_enabled' in request.form,
            "origin_rule_destination_port": request.form.get('origin_rule_destination_port'),
        }
        if new_record_data["origin_rule_enabled"]:
            dest_port_str = new_record_data["origin_rule_destination_port"]
            if not (dest_port_str and dest_port_str.isdigit()): 
                flash("启用端口转发时，目标内部端口必须是有效的数字。", "error")
                return render_template('record_form.html', record=new_record_data, form_title="添加新记录", username=session.get('username', '访客'))
            new_record_data["origin_rule_destination_port"] = int(dest_port_str)
        else: 
            new_record_data["origin_rule_destination_port"] = None


        new_record = ensure_record_fields(new_record_data) 
        
        updated_new_record = manage_cloudflare_origin_rule(new_record)
        if updated_new_record is None: 
             flash(f"记录 '{new_record['name']}' 添加失败，因为 Cloudflare Origin Rule 操作失败。", "error")
        else:
            DDNS_RECORDS.append(updated_new_record)
            save_ddns_records() 
            _sync_app_status_records_display() 
            flash(f"记录 '{updated_new_record['name']}' 已成功添加！", "success")
        return redirect(url_for('records_management')) 
    
    return render_template('record_form.html', record={}, form_title="添加新记录", username=session.get('username', '访客'))

@flask_app.route('/records/edit/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    record_to_edit_orig = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
    if not record_to_edit_orig:
        flash("未找到指定记录！", "error")
        return redirect(url_for('records_management'))
    
    # Work with a full copy that has all fields ensured
    record_to_edit = ensure_record_fields(dict(record_to_edit_orig))

    if request.method == 'POST':
        original_name = record_to_edit['name']
        # original_type = record_to_edit['type'] # Not needed for this check if type cannot be changed
        new_record_name = request.form['name'].strip()
        # Assuming record type cannot be changed during edit for simplicity, or add type to form if it can
        new_record_type = record_to_edit['type'] # Keep original type if not editable

        # Check for duplicate name if name changed
        if new_record_name.lower() != original_name.lower() and \
           any(r['id'] != record_id and r['name'].lower() == new_record_name.lower() and r['type'] == new_record_type for r in DDNS_RECORDS):
            flash(f"不能修改为已存在的记录名和类型组合: '{new_record_name}' ({new_record_type})。", "error")
            # Pass back current form values to re-populate
            form_data_on_error = dict(record_to_edit)
            form_data_on_error.update(request.form.to_dict(flat=False)) # Get form values
            # Ensure proxied and enabled are boolean
            form_data_on_error['proxied'] = 'proxied' in request.form
            form_data_on_error['enabled'] = 'enabled' in request.form
            form_data_on_error['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
            return render_template('record_form.html', record=form_data_on_error, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))


        record_to_edit['name'] = new_record_name
        # record_to_edit['type'] = new_record_type # If type is editable
        record_to_edit['proxied'] = 'proxied' in request.form
        record_to_edit['ttl'] = int(request.form.get('ttl', 120))
        record_to_edit['enabled'] = 'enabled' in request.form
        
        record_to_edit['origin_rule_enabled'] = 'origin_rule_enabled' in request.form
        dest_port_str = request.form.get('origin_rule_destination_port')

        if record_to_edit['origin_rule_enabled']:
            if not (dest_port_str and dest_port_str.isdigit()): 
                flash("启用端口转发时，目标内部端口必须是有效的数字。", "error")
                current_form_state = dict(record_to_edit) 
                current_form_state.update(request.form.to_dict()) 
                return render_template('record_form.html', record=current_form_state, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))
            record_to_edit['origin_rule_destination_port'] = int(dest_port_str)
        else: 
            record_to_edit['origin_rule_destination_port'] = None
            
        if not record_to_edit['name'] : # Type is not editable here, so only check name
            flash("记录名不能为空！", "error")
            return render_template('record_form.html', record=record_to_edit, form_title=f"编辑记录: {original_name}", username=session.get('username', '访客'))
        
        # Before calling manage_cloudflare_origin_rule, ensure the DNS record itself is updated on CF if name/proxied changed
        # This is because the origin rule expression depends on http.host (record_name)
        # However, the main DDNS update job handles DNS IP changes. Here we only care about name/proxy for Origin Rule context.
        # For simplicity, we'll let run_ddns_update_job handle the DNS IP/proxy update.
        # The manage_cloudflare_origin_rule will use the new name for its expression.

        updated_record_after_cf_op = manage_cloudflare_origin_rule(record_to_edit)

        if updated_record_after_cf_op is None: 
            flash(f"记录 '{record_to_edit['name']}' 更新失败，因为 Cloudflare Origin Rule 操作失败。", "error")
        else:
            # Also, ensure the DNS record on Cloudflare reflects the new 'proxied' status if it changed.
            # This is slightly tricky as manage_cloudflare_origin_rule doesn't update DNS.
            # The main `run_ddns_update_job` will eventually sync the proxy status.
            # For immediate effect of proxy change during edit, we might need a targeted DNS update here.
            # Let's assume for now that the next run_ddns_update_job will fix proxy.
            # The critical part is that the local DDNS_RECORDS is updated.
            
            # Find the index and update in DDNS_RECORDS
            for i, r_loop_var in enumerate(DDNS_RECORDS): 
                if r_loop_var["id"] == record_id:
                    DDNS_RECORDS[i] = updated_record_after_cf_op # This now contains the potentially updated origin_rule_id
                    break
            save_ddns_records() # Save all changes including name, proxied, ttl, enabled, and origin rule fields
            
            # Trigger a DDNS update to immediately reflect proxy changes if possible
            # This is a good place to ensure the DNS record (especially proxy status) is up-to-date on CF
            # We can call _update_cloudflare_dns_record or _create_cloudflare_dns_record if needed
            # For now, rely on the next scheduled update or manual trigger for DNS proxy sync.
            # The most important part is that the local record is saved correctly.
            
            _sync_app_status_records_display()
            flash(f"记录 '{updated_record_after_cf_op['name']}' 已成功更新！更改将在下次DDNS检查时完全同步到Cloudflare。", "success")
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
    record_type = record_to_delete_local['type']
    
    origin_rule_deleted_successfully = True 
    if record_to_delete_local.get("origin_rule_enabled") and record_to_delete_local.get("origin_rule_id"):
        add_log_entry(f"删除记录 '{record_name}': 尝试删除其关联的 Origin Rule ID {record_to_delete_local['origin_rule_id']}", "INFO")
        temp_record_for_origin_deletion = dict(record_to_delete_local)
        temp_record_for_origin_deletion["origin_rule_enabled"] = False 
        if manage_cloudflare_origin_rule(temp_record_for_origin_deletion) is None:
            origin_rule_deleted_successfully = False
            flash(f"从 Cloudflare 删除 Origin Rule for '{record_name}' 失败。记录未完全删除。", "error")
        else:
             add_log_entry(f"删除记录 '{record_name}': 其关联的 Origin Rule 已成功处理/删除。", "INFO")

    dns_record_deleted_successfully = True 
    if origin_rule_deleted_successfully:
        # Get full record to get DNS ID
        cf_dns_full_record = _get_cloudflare_dns_record(record_name, record_type)
        cf_dns_id_to_delete = cf_dns_full_record.get("id") if cf_dns_full_record else None
        
        if cf_dns_id_to_delete:
            if not _delete_cloudflare_dns_record(cf_dns_id_to_delete):
                dns_record_deleted_successfully = False
                flash(f"从 Cloudflare 删除 DNS 记录 '{record_name}' 失败。本地记录未删除。", "error")
        else:
            add_log_entry(f"DNS 记录 '{record_name}' ({record_type}) 在 Cloudflare 上未找到，无需从 Cloudflare 删除。", "INFO")
    else: 
        dns_record_deleted_successfully = False

    if origin_rule_deleted_successfully and dns_record_deleted_successfully:
        original_len = len(DDNS_RECORDS)
        DDNS_RECORDS = [r for r in DDNS_RECORDS if r.get("id") != record_id]
        if len(DDNS_RECORDS) < original_len:
            save_ddns_records()
            _sync_app_status_records_display()
            flash(f"记录 '{record_name}' 已成功从本地和 Cloudflare (DNS 及相关 Origin Rule) 删除。", "success")
        else:
            flash("从本地删除记录时发生意外错误。", "error") 
    else:
        _sync_app_status_records_display() 

    return redirect(url_for('records_management'))


@flask_app.route('/records/toggle/<record_id>', methods=['POST'])
def toggle_record(record_id):
    record_to_toggle = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
    if record_to_toggle:
        record_to_toggle['enabled'] = not record_to_toggle['enabled']
        save_ddns_records() 
        _sync_app_status_records_display()
        flash(f"记录 '{record_to_toggle['name']}' DDNS 更新已{'启用' if record_to_toggle['enabled'] else '禁用'}。", "success")
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
    
    overall_success_count = 0
    overall_failure_count = 0
    messages = []

    ids_successfully_processed_for_local_removal = set()

    for record_id in record_ids_to_delete:
        record_to_delete = next((r for r in DDNS_RECORDS if r.get("id") == record_id), None)
        if not record_to_delete:
            messages.append(f"记录ID {record_id} 未在本地找到，跳过。")
            overall_failure_count +=1
            continue

        record_name = record_to_delete['name']
        record_type = record_to_delete['type']
        
        origin_rule_ok = True
        if record_to_delete.get("origin_rule_enabled") and record_to_delete.get("origin_rule_id"):
            temp_record_for_origin_del = dict(record_to_delete)
            temp_record_for_origin_del["origin_rule_enabled"] = False 
            if manage_cloudflare_origin_rule(temp_record_for_origin_del) is None:
                origin_rule_ok = False
                messages.append(f"记录 {record_name}: Cloudflare Origin Rule 删除失败。")
        
        dns_record_ok = True
        if origin_rule_ok: 
            cf_dns_full_record = _get_cloudflare_dns_record(record_name, record_type)
            cf_dns_id = cf_dns_full_record.get("id") if cf_dns_full_record else None
            if cf_dns_id:
                if not _delete_cloudflare_dns_record(cf_dns_id):
                    dns_record_ok = False
                    messages.append(f"记录 {record_name}: Cloudflare DNS 记录删除失败。")
        else: 
            dns_record_ok = False

        if origin_rule_ok and dns_record_ok:
            ids_successfully_processed_for_local_removal.add(record_id)
            overall_success_count += 1
            messages.append(f"记录 {record_name}: 已成功处理删除 (CF Origin Rule 和 DNS)。")
        else:
            overall_failure_count += 1

    if ids_successfully_processed_for_local_removal:
        DDNS_RECORDS = [r for r in DDNS_RECORDS if r.get("id") not in ids_successfully_processed_for_local_removal]
        save_ddns_records()
        _sync_app_status_records_display()

    final_message = f"批量删除完成。成功: {overall_success_count}, 失败: {overall_failure_count}. 详情: {' '.join(messages)}"
    add_log_entry(final_message, "INFO")
    return jsonify(success=overall_failure_count == 0, message=final_message)


@flask_app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings():
    admin_creds = load_admin_credentials() 
    if not admin_creds: 
        flash("管理员账户信息缺失。", "error")
        return redirect(url_for('index'))
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'password_change':
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
                    if save_admin_credentials(admin_creds["username"], new_hashed_password):
                        flash("管理员密码已成功修改！请重新登录。", "success")
                        session.pop('logged_in', None); session.pop('username', None)
                        return redirect(url_for('login'))
                    else: flash("修改密码时发生错误。", "error")
        elif form_type == 'api_config_change':
            new_api_token = request.form.get('cf_api_token', '').strip()
            new_zone_id = request.form.get('cf_zone_id', '').strip()
            if not new_api_token or not new_zone_id: flash("API Token 和 Zone ID 均不能为空！", "error")
            else:
                token_changed = GLOBAL_CONFIG["CF_API_TOKEN"] != new_api_token
                zone_id_changed = GLOBAL_CONFIG["CF_ZONE_ID"] != new_zone_id
                if token_changed or zone_id_changed:
                    GLOBAL_CONFIG["CF_API_TOKEN"] = new_api_token
                    GLOBAL_CONFIG["CF_ZONE_ID"] = new_zone_id
                    save_global_config()
                    log_msgs = []
                    if token_changed: log_msgs.append("API Token 已更新"); add_log_entry("CF API Token 已更新。", "INFO")
                    if zone_id_changed: log_msgs.append("Zone ID 已更新"); add_log_entry("CF Zone ID 已更新。", "INFO")
                    flash(f"Cloudflare API 设置已成功更新 ({', '.join(log_msgs)})！", "success")
                else: flash("API 设置未发生变化。", "info")
        else: flash("无效的表单提交。", "error")
        masked_token = ""
        if GLOBAL_CONFIG["CF_API_TOKEN"]:
            token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
            masked_token = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:] if token_len > 8 else "****"
        current_display_config = GLOBAL_CONFIG.copy()
        current_display_config["CF_API_TOKEN"] = masked_token
        return render_template('admin_settings.html', username=session.get('username'), current_config=current_display_config)

    masked_token = ""
    if GLOBAL_CONFIG["CF_API_TOKEN"]:
        token_len = len(GLOBAL_CONFIG["CF_API_TOKEN"])
        masked_token = GLOBAL_CONFIG["CF_API_TOKEN"][:4] + "****" + GLOBAL_CONFIG["CF_API_TOKEN"][-4:] if token_len > 8 else "****"
    current_display_config = GLOBAL_CONFIG.copy()
    current_display_config["CF_API_TOKEN"] = masked_token
    return render_template('admin_settings.html', username=session.get('username'), current_config=current_display_config)


# --- 主程序和调度器 ---
if __name__ == '__main__':
    load_all_config() 
    run_ddns_update_job() 
    scheduler = BackgroundScheduler(daemon=True)
    if GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"] > 0:
        scheduler.add_job(run_ddns_update_job, 'interval', minutes=GLOBAL_CONFIG["DDNS_CHECK_INTERVAL_MINUTES"])
        scheduler.start()
        add_log_entry(f"DDNS 自动更新任务已设置，每 {GLOBAL_CONFIG['DDNS_CHECK_INTERVAL_MINUTES']} 分钟运行一次。")
    else:
        add_log_entry("DDNS 自动更新间隔设置为0或无效。", "WARNING")
    try:
        add_log_entry("启动 Flask Web 服务器...")
        flask_app.run(host='127.0.0.1', port=5000, debug=False) 
    except (KeyboardInterrupt, SystemExit):
        if 'scheduler' in globals() and scheduler.running:
            scheduler.shutdown()
        add_log_entry("DDNS 应用已关闭。")
