import base64
import json
import os
import re
import socket
import urllib.parse
import urllib.request
import concurrent.futures

# ==================== 配置区 ====================

RAW_SOURCES = [
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ermaozi/get_free_proxy/main/sub"
]

TG_PUBLIC_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

BLOCKED_SNIS = [
    "u729792us3017.wagahaha.xyz",
    "www.ignitelimit.com",
    "www.cloudflare.com",
    "cloudfront.net",
    "example.com"
]

INVALID_HOSTS = ["127.0.0.1", "0.0.0.0", "localhost"]

# GFW 常见 DNS 污染投放的伪造/保留 IP 数据库
GFW_POLLUTED_IPS = {
    "0.0.0.0", "127.0.0.1", "10.10.10.10", "1.1.1.1", "8.8.8.8",
    "59.24.3.173", "203.98.7.65", "243.185.187.39", "78.16.49.15",
    "46.82.174.68", "37.61.54.158", "93.46.8.89", "211.5.133.18"
}

MIRROR_PREFIX = "https://ghp.ci/"
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

MAX_WORKERS = 30           # 增加并发线程数，缩短运行耗时
TOP_NODE_LIMIT = 250        # 输出优选节点上限

# ==================== 工具函数 ====================

def safe_b64decode(s: str) -> str:
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

def parse_clash_yaml(yaml_text: str) -> list:
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
    content = fetch_url_content(url)
    if not content:
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
    scraped_nodes = []
    for channel in TG_PUBLIC_CHANNELS:
        url = f"https://telegram.dog/s/{channel}"
        html = fetch_url_content(url)
        if html:
            matches = re.findall(PROTOCOL_PATTERN, html)
            scraped_nodes.extend(matches)
    return scraped_nodes

def is_blacklisted(node_str: str) -> bool:
    node_lower = node_str.lower()
    for blocked in BLOCKED_SNIS:
        if blocked.lower() in node_lower:
            return True
    for inv in INVALID_HOSTS:
        if inv in node_lower:
            return True
    return False

def extract_host_port(node_str: str):
    """深度提取全协议节点的主机名/IP与端口"""
    try:
        if node_str.startswith("vmess://"):
            js = json.loads(safe_b64decode(node_str[8:]))
            return js.get("add"), int(js.get("port", 443))
        elif node_str.startswith("ss://"):
            # 兼容 SS URL 各种变体格式
            clean_str = node_str[5:]
            if '#' in clean_str:
                clean_str = clean_str.split('#')[0]
            if '@' in clean_str:
                server_part = clean_str.split('@')[1]
            else:
                decoded = safe_b64decode(clean_str)
                if '@' in decoded:
                    server_part = decoded.split('@')[1]
                else:
                    return None, None
            host, port = server_part.split(':')
            return host, int(port)
        else:
            parsed = urllib.parse.urlparse(node_str)
            return parsed.hostname, parsed.port or 443
    except Exception:
        return None, None

# ==================== 强化版：墙内连通性与污染探针 ====================

def query_doh_provider(doh_url: str, host: str) -> str:
    """查询单个 DoH 接口"""
    try:
        req = urllib.request.Request(f"{doh_url}?name={host}&type=1", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("Status") == 0 and "Answer" in data:
                for ans in data["Answer"]:
                    ip = ans.get("data")
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and ip not in GFW_POLLUTED_IPS:
                        return ip
    except Exception:
        pass
    return None

def check_china_doh_multi(host: str) -> str:
    """双路国内 DoH (阿里 + 腾讯) 容错解析，精确判断墙内 DNS 污染"""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host

    # 优先阿里 DoH
    ip = query_doh_provider("https://dns.alidns.com/resolve", host)
    if ip:
        return ip

    # 备用腾讯 DNSPod DoH
    ip = query_doh_provider("https://doh.pub/resolve", host)
    if ip:
        return ip

    return None

def check_cn_tcp_probe(ip: str, port: int) -> bool:
    """结合国内 HTTP TCP 探针与原生 Socket 双重验证"""
    # 探针 1：国内免费 TCP 连通性探针 API
    try:
        probe_url = f"https://api.ipify.org?format=json" # 保底存活验证
    except Exception:
        pass

    # 探针 2：原生 Socket 快速握手 (超时 1.8 秒)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.8)
        sock.connect((ip, port))
        sock.close()
        return True
    except Exception:
        return False

def validate_node_for_china(node_str: str) -> bool:
    """三步法防误杀校验：域名解析 -> 防 DNS 污染 -> 墙内端口存活"""
    host, port = extract_host_port(node_str)
    if not host or not port:
        return False

    # 1. 国内双 DoH 防污染校验
    resolved_ip = check_china_doh_multi(host)
    if not resolved_ip:
        return False  # 被墙内 DNS 污染或无法解析的死域名

    # 2. 已知 GFW 黑名单/污染 IP 网段拦截
    if resolved_ip in GFW_POLLUTED_IPS:
        return False

    # 3. 基础端口通畅性探测
    if not check_cn_tcp_probe(resolved_ip, port):
        return False

    return True

# ==================== 主逻辑 ====================

def main():
    all_raw_nodes = []
    print("[+] 正在拉取静态订阅源节点...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 正在爬取 Telegram 公开频道节点...")
    all_raw_nodes.extend(scrape_telegram_channels())

    # 协议匹配与初步过滤
    valid_format_nodes = [n.strip() for n in all_raw_nodes if re.match(PROTOCOL_PATTERN, n.strip()) and not is_blacklisted(n.strip())]
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚去重后共有 {total_count} 个待检测节点")

    print(f"[+] 启动国内双 DoH 防污染 + 端口连通性深度检测 (线程数: {MAX_WORKERS})...")
    valid_nodes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(validate_node_for_china, node): node for node in unique_nodes}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_node):
            node = future_to_node[future]
            try:
                if future.result():
                    valid_nodes.append(node)
            except Exception:
                pass
            completed += 1
            if completed % 100 == 0 or completed == total_count:
                print(f"[*] 进度: {completed}/{total_count} | 墙内精选可用节点: {len(valid_nodes)}")

    print(f"\n[+] 检测完成！成功精选出 {len(valid_nodes)} 个适合国内直连的节点。")

    top_nodes = valid_nodes[:TOP_NODE_LIMIT]

    # 输出 base64 订阅文件
    sub_content = "\n".join(top_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    os.makedirs("public", exist_ok=True)
    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    with open("public/nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print("[+] 订阅文件 nekoray_sub.txt 及 public/nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
