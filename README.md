# Cloudflare-ddns-WebUI
Cloudflare-ddns-WebUI是一款基于 Python Flask 构建的轻量级动态域名解析 (DDNS) Web 应用。它旨在为您的家用服务器或动态 IP 环境提供一个直观、安全的 Cloudflare DNS 记录自动更新解决方案。

>目前仅适配win系统

## 主要功能

*   **图形化界面**：通过 Web 界面轻松管理 DDNS 记录和全局设置。
*   **多记录支持**：可同时管理多个域名（或子域名）的 `A` (IPv4) 和 `AAAA` (IPv6) 记录。
*   **自动更新**：后台定时任务自动检测 IP 地址变化并更新 Cloudflare DNS 记录。
*   **手动触发**：支持手动立即触发 IP 更新检查。
*   **IP 地址获取**：
    *   IPv4: 通过多个公共 API 获取公网 IPv4 地址。
    *   IPv6: 通过本地 PowerShell 脚本 (Windows) 获取稳定的公网 IPv6 地址 (GUA)。
*   **自动配置端口转发**: 通过api自动创建和删除Origin Rule端口转发记录。
*   **Cloudflare API**：使用 Cloudflare API v4 进行 DNS/Origin Rule 记录的读取、创建和更新。

![界面截图](https://github.com/fluxaster/Cloudflare-ddns-WebUI/blob/main/a.png)

## 快速开始

### 环境要求

*   Python 3.7+
*   操作系统：目前 IPv6 获取脚本 `get_ipv6.ps1` 仅适用于 Windows。Linux/macOS 用户需要自行修改或提供获取 IPv6 的方法。
*   Cloudflare 账户及一个已配置的域名。

### 安装步骤

1.  **获取API Token和Zone ID**:
    *   登录cloudflare主界面-点击目标域名-概述-保存Zone ID(区域ID)-点击获取api令牌-使用编辑区域DNS模板-可参考下图配置令牌权限
        ![令牌权限参考](https://github.com/fluxaster/Cloudflare-ddns-WebUI/blob/main/b.png)

3.  **克隆仓库或下载压缩包**:
    ```bash
    git clone https://github.com/fluxaster/Cloudflare-ddns-WebUI.git
    ```

4.  **运行Webapp**:
    可直接运行一键启动脚本`start.bat`

5.  **访问控制面板**:
    打开浏览器，访问 `http://127.0.0.1:5000` (或您服务器的 IP 地址和端口)。

6.  **首次设置**:
    *   首次访问会引导您设置管理员账户的用户名和密码。
    *   登录后，您可以在“全局设置”页面配置 Cloudflare API Token 和 Zone ID (也可在 `config.ini` 中配置)。
       *   您需要填入您的 Cloudflare API Token 和 Zone ID。
           *   **API Token**: 从 Cloudflare 控制台创建，确保具有编辑 DNS 的权限。推荐使用区域限定的 API Token。
           *   **Zone ID**: 在您的域名概览页面可以找到。
    *   然后在“记录管理”页面添加您需要进行 DDNS 更新的域名记录。

## 文件结构
```
├── app.py # Flask 主应用逻辑
├── get_ipv6.ps1 # 获取 IPv6 地址的 PowerShell 脚本 (Windows)
├── templates/ # HTML 模板文件夹
│ ├── base.html # 基础模板，包含导航和布局
│ ├── index.html # 状态总览页面
│ ├── login.html # 登录页面
│ ├── setup_admin.html # 首次设置管理员页面
│ ├── settings.html # 全局设置页面
│ ├── records_management.html # DDNS 记录管理页面
│ ├── record_form.html # 添加/编辑记录表单页面
│ └── admin_settings.html # 管理员账户设置（修改密码）
├── config.ini # (程序生成/手动创建) 全局配置文件
├── records.json # (程序生成) DDNS 记录配置文件
├── admin_credentials.json # (程序生成) 管理员账户凭证
└── README.md # 本说明文件
```

## 配置说明

### `config.ini`

*   `[Cloudflare]`
    *   `ApiToken`: 您的 Cloudflare API Token。
    *   `ZoneId`: 您的 Cloudflare Zone ID。
*   `[DDNS]`
    *   `CheckIntervalMinutes`: DDNS 自动检查更新的间隔时间（分钟）。
    *   `EnableIPv4DDNS`: 是否启用 IPv4 DDNS 功能 (`True`/`False`)。
    *   `EnableIPv6DDNS`: 是否启用 IPv6 DDNS 功能 (`True`/`False`)。
    *   `InterfaceName`: (暂未启用) 指定获取 IPv6 地址时使用的网络接口名称。
### `records.json`

此文件由程序自动管理，存储您在 Web 界面上添加的 DDNS 记录。每条记录包含：

*   `id`: 记录的唯一标识符 (UUID)。
*   `name`: 完整的域名，例如 `home.example.com`。
*   `type`: 记录类型，`A` 或 `AAAA`。
*   `proxied`: 是否启用 Cloudflare 代理 (小云朵) (`true`/`false`)。
*   `ttl`: DNS 记录的 TTL 值 (秒)。
*   `enabled`: 是否启用此条记录的 DDNS 更新 (`true`/`false`)。

## IPv6 获取 (`get_ipv6.ps1`)

当前的 `get_ipv6.ps1` 脚本专为 Windows 设计，它会尝试获取：

1.  所有公网 IPv6 地址 (GUA, 通常以 `2` 或 `3` 开头)。
2.  排除临时地址 (通常具有较短的有效生命周期)。
3.  如果指定了网络接口名称 (`InterfaceName` 配置项)，会优先考虑该接口的地址。
4.  从有效地址中选择一个“最稳定”的（目前实现是选择长度最短的非临时 GUA，因为 Windows 下稳定隐私地址通常比临时地址短）。

**对于 Linux/macOS 用户：**
您需要替换或修改 `get_stable_ipv6_windows()` 函数中的命令执行逻辑，以适应您的操作系统获取 IPv6 的方式。

## 开发与贡献

欢迎提交 Pull Requests 或报告 Issues！

如果您想为此项目贡献代码，请：

1.  Fork 本仓库。
2.  创建一个新的分支 (`git checkout -b feature/你的特性`)。
3.  提交您的更改 (`git commit -am '添加新特性'`)。
4.  将您的分支推送到远程仓库 (`git push origin feature/你的特性`)。
5.  创建一个新的 Pull Request。

## 开源许可

本项目采用 [MIT License](LICENSE) 开源。

---
