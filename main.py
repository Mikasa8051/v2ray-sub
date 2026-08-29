import base64
import json
import os
import re
import urllib.parse
import urllib.request

# ==================== 配置区 ====================

# 1. 静态订阅源列表
RAW_SOURCES = [
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ermaozi/get_free_proxy/main/sub"
]

# 2. Telegram 公开频道列表
TG_PUBLIC_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

# 3. 指定强行拦截剔除的伪造 SNI / 假节点域名黑名单
BLOCKED_SNIS = [
    "u729792us3017.wagahaha.xyz",
    "www.ignitelimit.com",
    "www.cloudflare.com"
]

# CDN 加速镜像前缀，用于 GitHub 静态源直连备用回退
MIRROR_PREFIX = "https://ghp.ci/"

# 改进后的通用正则（精准抓取至空白字符或 HTML 结束符）
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[^\s<'\"]+"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# ==================== 工具函数 ====================

def safe_b64decode(s: str) -> str:
    """安全的 Base64 解码函数"""
    s = s.strip().replace('\r', '').replace('\n', '')
    s = re.sub(r'[^a-zA-Z0-9+/=_-]', '', s)
    s = s.replace('-', '+').replace('_', '/')
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_clash_yaml(yaml_text: str) -> list:
    """提取并转换 YAML/Clash 格式中的节点数据"""
    nodes = []
    proxy_blocks = re.findall(r"-\s*\{([^}]+)\}", yaml_text)
    if not proxy_blocks:
        proxy_blocks = re.findall(r"-\s*name:\s*(.*?)(?=\n-\s*name:|\n\s*proxy-groups:|$)", yaml_text, re.S)

    for block in proxy_blocks:
        try:
            kv = {}
            lines = block.split(',') if '{' in block else block.splitlines()
            for item in lines:
                if ':' in item:
                    k, v = item.split(':', 1)
                    kv[k.strip().strip("- ")] = v.strip().strip("'\"")

            p_type = kv.get("type", "").lower()
            name = urllib.parse.quote(kv.get("name", "Node"))
            server = kv.get("server", "")
            port = kv.get("port", "")

            if not server or not port:
                continue

            if p_type == "ss":
                cipher = kv.get("cipher", "")
                password = kv.get("password", "")
                userinfo = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                nodes.append(f"ss://{userinfo}@{server}:{port}#{name}")
            elif p_type in ("vmess", "vless"):
                uuid = kv.get("uuid", "")
                if p_type == "vmess":
                    v_json = {
                        "v": "2", "ps": kv.get("name", "Node"), "add": server,
                        "port": port, "id": uuid, "aid": kv.get("alterId", "0"),
                        "net": kv.get("network", "tcp"), "type": "none",
                        "tls": "tls" if kv.get("tls") == "true" else ""
                    }
                    nodes.append(f"vmess://{base64.b64encode(json.dumps(v_json).encode()).decode()}")
                else:
                    nodes.append(f"vless://{uuid}@{server}:{port}?type={kv.get('network', 'tcp')}#{name}")
            elif p_type == "trojan":
                password = kv.get("password", "")
                nodes.append(f"trojan://{password}@{server}:{port}#{name}")
            elif p_type in ("hysteria2", "hy2"):
                auth = kv.get("password", "") or kv.get("auth", "")
                nodes.append(f"hysteria2://{auth}@{server}:{port}#{name}")
        except Exception:
            continue
    return nodes

def fetch_url_content(url: str) -> str:
    """网络请求函数（支持自动回退至 CDN 镜像源）"""
    urls_to_try = [url]
    if "raw.githubusercontent.com" in url or "github.com" in url:
        urls_to_try.append(MIRROR_PREFIX + url)

    for target_url in urls_to_try:
        try:
            req = urllib.request.Request(target_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode('utf-8', errors='ignore').strip()
                if content:
                    return content
        except Exception:
            continue
    return ""

def fetch_from_sources(url: str) -> list:
    """从静态源解析节点数据"""
    content = fetch_url_content(url)
    if not content:
        print(f"[-] 抓取源失败 [{url}]")
        return []

    if "proxies:" in content or url.endswith((".yaml", ".yml")):
        yaml_nodes = parse_clash_yaml(content)
        if yaml_nodes:
            return yaml_nodes

    curr = content
    for _ in range(3):
        decoded = safe_b64decode(curr)
        if decoded and any(p in decoded for p in ["vmess://", "vless://", "ss://", "trojan://"]):
            curr = decoded
        else:
            break
    
    return curr.splitlines()

def scrape_telegram_channels() -> list:
    """从 Telegram 公开 Web 页面提取节点数据（支持双域名自动备用）"""
    scraped_nodes = []
    for channel in TG_PUBLIC_CHANNELS:
        print(f"[*] [TG爬虫] 正在爬取频道: @{channel}")
        urls = [f"https://t.me/s/{channel}", f"https://telegram.dog/s/{channel}"]
        html = ""
        for u in urls:
            html = fetch_url_content(u)
            if html:
                break
        
        if html:
            matches = re.findall(PROTOCOL_PATTERN, html)
            scraped_nodes.extend(matches)
            
            decoded = safe_b64decode(html)
            if decoded:
                scraped_nodes.extend(re.findall(PROTOCOL_PATTERN, decoded))
        else:
            print(f"[-] 爬取 TG 频道 @{channel} 失败")
    return scraped_nodes

def extract_node_domains(node_str: str) -> list:
    """【核心修复】深层解包节点提取真正的 Address, Host, SNI, Peer 域名"""
    domains = [node_str.lower()]

    try:
        # 1. 针对 VMess 进行 Base64 + JSON 解包
        if node_str.startswith("vmess://"):
            b64_data = node_str[8:]
            decoded_json = safe_b64decode(b64_data)
            if decoded_json:
                js = json.loads(decoded_json)
                for key in ["add", "host", "sni"]:
                    if js.get(key):
                        domains.append(str(js.get(key)).lower())

        # 2. 针对其他协议解析 URL 域名及 URL 参数 (sni, host, peer)
        else:
            parsed = urllib.parse.urlparse(node_str)
            if parsed.hostname:
                domains.append(parsed.hostname.lower())

            query_params = urllib.parse.parse_qs(parsed.query)
            for key in ["sni", "host", "peer"]:
                if key in query_params:
                    for val in query_params[key]:
                        domains.append(val.lower())

            # 特殊处理 Shadowsocks Base64 结构
            if node_str.startswith("ss://"):
                raw_ss = node_str[5:].split('#')[0]
                if '@' in raw_ss:
                    server_part = raw_ss.split('@', 1)[1]
                else:
                    decoded_ss = safe_b64decode(raw_ss)
                    server_part = decoded_ss.split('@', 1)[1] if '@' in decoded_ss else ""
                if ':' in server_part:
                    domains.append(server_part.split(':', 1)[0].lower())
    except Exception:
        pass

    return domains

def is_blacklisted_sni(node_str: str) -> bool:
    """精准检测节点解包后的真实 SNI/Host 是否命中黑名单"""
    extracted_domains = extract_node_domains(node_str)
    for blocked in BLOCKED_SNIS:
        blocked_lower = blocked.lower()
        for domain in extracted_domains:
            if blocked_lower in domain:
                return True
    return False

# ==================== 主逻辑 ====================

def main():
    all_raw_nodes = []

    print("[+] 阶段 1: 正在拉取静态订阅源节点...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 阶段 2: 正在爬取 Telegram 公开频道节点...")
    tg_nodes = scrape_telegram_channels()
    all_raw_nodes.extend(tg_nodes)

    # 规范化格式清理与筛选
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = re.sub(r'<[^>]+>', '', n.strip()) # 剥离残留 HTML 标签
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    # 去重处理
    unique_nodes = list(set(valid_format_nodes))
    print(f"[+] 汇聚去重后共有 {len(unique_nodes)} 个节点")

    print("[+] 阶段 3: 正在精准深层解包并剔除目标伪造 SNI 节点...")
    clean_nodes = []
    blocked_count = 0
    for node in unique_nodes:
        if is_blacklisted_sni(node):
            blocked_count += 1
        else:
            clean_nodes.append(node)

    print(f"[+] 成功拦截并剔除指定黑名单伪节点: {blocked_count} 个")
    print(f"[+] 最终保留优质节点总数: {len(clean_nodes)} 个")  

    # 生成并写入最终的 Base64 订阅文件
    sub_content = "\n".join(clean_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    # 兼容根目录与 public/ 目录（便于 GitHub Pages / Actions 部署）
    os.makedirs("public", exist_ok=True)
    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    with open("public/nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
