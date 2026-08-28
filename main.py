import os
import re
import time
import base64
import json
import requests
import urllib.parse

# 1. 订阅源列表（标准文本 / Clash YAML 格式）
SUBSCRIPTION_SOURCES = [
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_free_proxy/main/sub"
]

# 2. 网页爬虫目标列表
WEB_SCRAPE_URLS = [
    "https://clashnode.github.io/",
    "https://v2rayshare.github.io/",
    "https://www.nodefree.org/",
]

# 3. 电报 Telegram 公开频道列表（免登录/免 API，通过网页预览抓取）
TG_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

# 协议匹配与过滤
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~]+"
SUPPORTED_PROTOCOLS = ("vmess://", "vless://", "ss://", "trojan://", "socks://", "socks5://", "hy2://", "hysteria2://")

CACHE_FILE = "nekoray_sub.txt"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def safe_base64_decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def safe_base64_encode(data_str):
    return base64.b64encode(data_str.encode('utf-8')).decode('utf-8')

def parse_clash_yaml(yaml_text):
    nodes = []
    proxy_blocks = re.findall(r"-\s*\{([^}]+)\}", yaml_text)
    for block in proxy_blocks:
        try:
            kv = {}
            for item in re.split(r',\s*(?=[a-zA-Z0-9_-]+:)', block):
                if ':' in item:
                    k, v = item.split(':', 1)
                    kv[k.strip()] = v.strip().strip("'\"")

            p_type = kv.get("type", "").lower()
            name = urllib.parse.quote(kv.get("name", "Node"))
            server = kv.get("server", "")
            port = kv.get("port", "")

            if not server or not port:
                continue

            if p_type == "ss":
                cipher = kv.get("cipher", "")
                password = kv.get("password", "")
                userinfo = safe_base64_encode(f"{cipher}:{password}")
                nodes.append(f"ss://{userinfo}@{server}:{port}#{name}")

            elif p_type in ("vmess", "vless"):
                uuid = kv.get("uuid", "")
                if p_type == "vmess":
                    v_json = {
                        "v": "2", "ps": kv.get("name", "Node"), "add": server,
                        "port": port, "id": uuid, "aid": kv.get("alterId", "0"),
                        "net": kv.get("network", "tcp"), "type": "none",
                        "host": kv.get("ws-headers", {}).get("Host", "") if isinstance(kv.get("ws-headers"), dict) else "",
                        "path": kv.get("ws-opts", {}).get("path", "") if isinstance(kv.get("ws-opts"), dict) else "",
                        "tls": "tls" if kv.get("tls") == "true" else ""
                    }
                    nodes.append(f"vmess://{safe_base64_encode(json.dumps(v_json))}")
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

def fetch_from_subscription(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            content = resp.text.strip()
            
            if "proxies:" in content or url.endswith(".yaml") or url.endswith(".yml"):
                yaml_nodes = parse_clash_yaml(content)
                if yaml_nodes:
                    return yaml_nodes

            decoded = safe_base64_decode(content)
            if decoded and any(p in decoded for p in SUPPORTED_PROTOCOLS):
                return decoded.splitlines()
            return content.splitlines()
    except Exception:
        print(f"[-] 抓取订阅源失败: {url}")
    return []

def scrape_nodes_from_web(url):
    found_nodes = []
    try:
        print(f"[*] [网页爬虫] 正在爬取页面: {url}")
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            content = resp.text
            matches = re.findall(PROTOCOL_PATTERN, content)
            found_nodes.extend(matches)
            
            decoded = safe_base64_decode(content)
            if decoded:
                decoded_matches = re.findall(PROTOCOL_PATTERN, decoded)
                found_nodes.extend(decoded_matches)
    except Exception as e:
        print(f"[-] 网页爬取失败 {url}: {e}")
    return found_nodes

def scrape_telegram_channels():
    """通过 Telegram Web 预览免登录爬取公开频道"""
    found_nodes = []
    for channel in TG_CHANNELS:
        clean_channel = channel.strip().replace("https://t.me/", "").replace("@", "")
        url = f"https://t.me/s/{clean_channel}"
        print(f"[*] [TG公开爬虫] 正在爬取公开频道: @{clean_channel}")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                content = resp.text
                matches = re.findall(PROTOCOL_PATTERN, content)
                found_nodes.extend(matches)
                
                decoded = safe_base64_decode(content)
                if decoded:
                    decoded_matches = re.findall(PROTOCOL_PATTERN, decoded)
                    found_nodes.extend(decoded_matches)
        except Exception as e:
            print(f"[-] 公开频道爬取失败 @{clean_channel}: {e}")
    return found_nodes

def extract_target_info(node_str):
    try:
        if node_str.startswith("vmess://"):
            b64_data = node_str.replace("vmess://", "")
            json_str = safe_base64_decode(b64_data)
            if json_str:
                data = json.loads(json_str)
                return data.get("add"), int(data.get("port", 0))

        clean_str = re.sub(r"^[a-zA-Z0-9]+://", "", node_str)
        clean_str = clean_str.split("#")[0].split("?")[0]
        
        if "@" in clean_str:
            server_part = clean_str.split("@")[-1]
        else:
            server_part = clean_str
            
        server_part = server_part.split("/")[0]

        if ":" in server_part:
            host, port_str = server_part.rsplit(":", 1)
            return host.strip("[]"), int(port_str)
    except Exception:
        pass
    return None, None

def deduplicate_nodes(nodes):
    unique_strings = list(set(nodes))
    unique_nodes = []
    seen_endpoints = set()

    for node in unique_strings:
        host, port = extract_target_info(node)
        if host and port:
            endpoint = f"{host.lower()}:{port}"
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                unique_nodes.append(node)
        else:
            unique_nodes.append(node)

    return unique_nodes

def update_subscription():
    print("\n[+] 正在启动节点更新流程...")
    raw_nodes = []

    print("[+] 阶段 1: 从开源订阅源拉取...")
    for src in SUBSCRIPTION_SOURCES:
        raw_nodes.extend(fetch_from_subscription(src))

    print("[+] 阶段 2: 启动网页与公开 TG 页面抓取...")
    for url in WEB_SCRAPE_URLS:
        raw_nodes.extend(scrape_nodes_from_web(url))
        
    raw_nodes.extend(scrape_telegram_channels())

    valid_nodes = [n.strip() for n in raw_nodes if n.strip().startswith(SUPPORTED_PROTOCOLS)]
    unique_nodes = deduplicate_nodes(valid_nodes)
    print(f"[+] 深度去重后剩余节点数量: {len(unique_nodes)} 个")

    # 在 GitHub 云端生成 Base64 加密节点池
    final_payload = "\n".join(unique_nodes[:200]) # 精选前 200 个节点
    encoded_payload = safe_base64_encode(final_payload)
    
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        f.write(encoded_payload)
    print(f"[+] 订阅文件生成完毕，成功保存至 {CACHE_FILE}")

if __name__ == "__main__":
    update_subscription()
