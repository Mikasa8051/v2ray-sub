import base64
import json
import re
import urllib.parse
import urllib.request

# 1. 静态订阅源列表
SOURCES = [
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ermaozi/get_free_proxy/main/sub"
]

# 2. TG 公开频道列表
TG_PUBLIC_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

# 精确指定要强行拦截并屏蔽的伪造 SNI / 假节点域名黑名单
BLOCKED_SNIS = [
    "u729792us3017.wagahaha.xyz",
    "www.ignitelimit.com",
    "www.cloudflare.com"
]

PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

def safe_b64decode(s):
    """安全的 Base64 解码"""
    s = s.strip()
    s = re.sub(r'[^a-zA-Z0-9+/=_-]', '', s)
    s = s.replace('-', '+').replace('_', '/')
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_clash_yaml(yaml_text):
    """提取 YAML 中的节点数据"""
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
                        "net": kv.get("network", "tcp"), "type": "none", "tls": "tls" if kv.get("tls") == "true" else ""
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

def fetch_from_sources(url):
    """抓取源节点"""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore').strip()
            
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
    except Exception as e:
        print(f"[-] 抓取源失败 [{url}]: {e}")
        return []

def scrape_telegram_channels():
    """爬取 TG 频道节点"""
    scraped_nodes = []
    for channel in TG_PUBLIC_CHANNELS:
        url = f"https://t.me/s/{channel}"
        try:
            print(f"[*] [TG爬虫] 正在爬取频道: @{channel}")
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                matches = re.findall(PROTOCOL_PATTERN, html)
                scraped_nodes.extend(matches)
                
                decoded = safe_b64decode(html)
                if decoded:
                    scraped_nodes.extend(re.findall(PROTOCOL_PATTERN, decoded))
        except Exception as e:
            print(f"[-] 爬取 TG 频道 @{channel} 失败: {e}")
    return scraped_nodes

def is_blacklisted_sni(node_str):
    """判断节点是否包含指定的 3 条黑名单域名"""
    node_lower = node_str.lower()
    for blocked in BLOCKED_SNIS:
        if blocked.lower() in node_lower:
            return True
    return False

def main():
    all_raw_nodes = []

    print("[+] 阶段 1: 正在拉取静态订阅源节点...")
    for src in SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 阶段 2: 正在爬取 Telegram 公开频道节点...")
    tg_nodes = scrape_telegram_channels()
    all_raw_nodes.extend(tg_nodes)

    # 格式过滤
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    # 去重
    unique_nodes = list(set(valid_format_nodes))
    print(f"[+] 汇聚去重后共有 {len(unique_nodes)} 个节点")

    print("[+] 阶段 3: 正在精确精准剔除目标伪造 SNI 节点...")
    clean_nodes = []
    blocked_count = 0
    for node in unique_nodes:
        if is_blacklisted_sni(node):
            blocked_count += 1
        else:
            clean_nodes.append(node)

    print(f"[+] 拦截剔除指定黑名单伪节点: {blocked_count} 个")
    print(f"[+] 最终保留节点总数: {len(clean_nodes)} 个")

    # 导出 Base64 订阅文件
    sub_content = "\n".join(clean_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
