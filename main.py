import base64
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
import concurrent.futures
import ipaddress

# ==================== 配置区 ====================

# 高频更新高质量源列表
RAW_SOURCES = [
    "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://fastly.jsdelivr.net/gh/ALIILAPRO/v2rayng-config@master/sub.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2"
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

GFW_POLLUTED_IPS = {
    "0.0.0.0", "127.0.0.1", "10.10.10.10", "1.1.1.1", "8.8.8.8",
    "59.24.3.173", "203.98.7.65", "243.185.187.39", "78.16.49.15",
    "46.82.174.68", "37.61.54.158", "93.46.8.89", "211.5.133.18"
}

# Cloudflare CDN IP 网段识别库 (用于识别假套壳节点)
CF_IP_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in [
        "104.16.0.0/12", "172.67.0.0/16", "162.159.0.0/15", "104.28.0.0/14",
        "198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
        "188.114.96.0/20", "197.234.240.0/22"
    ]
]

MIRROR_PREFIX = "https://ghp.ci/"
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

MAX_WORKERS = 40           # 测试并发数
TOP_NODE_LIMIT = 50        # 精选 50 个真实高质量节点
HANDSHAKE_TIMEOUT = 1.0    # 握手超时时间控制在 1 秒内

# ==================== 工具函数 ====================

def is_cloudflare_ip(ip_str: str) -> bool:
    """检测 IP 是否属于 Cloudflare CDN 网段"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_IP_NETWORKS)
    except Exception:
        return False

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

def extract_node_details(node_str: str):
    """提取节点的地址、端口、TLS 状态及 SNI"""
    try:
        is_tls = False
        sni = None

        if node_str.startswith("vmess://"):
            js = json.loads(safe_b64decode(node_str[8:]))
            host = js.get("add")
            port = int(js.get("port", 443))
            is_tls = js.get("tls") in ["tls", "1", True]
            sni = js.get("sni") or js.get("host") or host
            return host, port, is_tls, sni
        elif node_str.startswith("ss://"):
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
                    return None, None, False, None
            host, port = server_part.split(':')
            return host, int(port), False, None
        else:
            parsed = urllib.parse.urlparse(node_str)
            host = parsed.hostname
            port = parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            is_tls = "security" in query and query["security"][0] in ["tls", "reality"]
            if node_str.startswith("trojan://") or node_str.startswith("hysteria2://") or node_str.startswith("hy2://"):
                is_tls = True
            sni = query.get("sni", [host])[0]
            return host, port, is_tls, sni
    except Exception:
        return None, None, False, None

# ==================== 防污染 DNS 与 连通性复测探针 ====================

def query_doh_provider(doh_url: str, host: str) -> str:
    try:
        req = urllib.request.Request(f"{doh_url}?name={host}&type=1", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=1.5) as resp:
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
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    ip = query_doh_provider("https://dns.alidns.com/resolve", host)
    if ip:
        return ip
    return query_doh_provider("https://doh.pub/resolve", host)

def test_node_connectivity(ip: str, port: int, is_tls: bool, sni: str) -> float:
    """
    通过双重复测（Double-check）校验节点的物理 TCP/TLS 响应，
    既不破坏代理协议，又能排查不稳定节点。
    """
    rtts = []
    for _ in range(2):
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HANDSHAKE_TIMEOUT)
            sock.connect((ip, port))

            if is_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=sni or ip)
                ssl_sock.do_handshake()
                ssl_sock.close()
            else:
                sock.close()

            rtt = (time.time() - start_time) * 1000
            rtts.append(rtt)
        except Exception:
            return -1
        time.sleep(0.05) # 短暂间隔后进行第二次复测

    return sum(rtts) / len(rtts) if len(rtts) == 2 else -1

def validate_and_score_node(node_str: str):
    host, port, is_tls, sni = extract_node_details(node_str)
    if not host or not port:
        return None

    # 1. 国内 DoH 解析真实 IP
    resolved_ip = check_china_doh_multi(host)
    if not resolved_ip or resolved_ip in GFW_POLLUTED_IPS:
        return None

    # 2. 识别 Cloudflare CDN 假套壳
    is_cf = is_cloudflare_ip(resolved_ip)

    # 3. 双重复测延迟探针
    rtt = test_node_connectivity(resolved_ip, port, is_tls, sni)
    if rtt <= 0:
        return None

    # 物理底层 IP:Port 唯一标识
    ip_port_key = f"{resolved_ip}:{port}"
    return (node_str, rtt, ip_port_key, is_cf)

# ==================== 主逻辑 ====================

def main():
    all_raw_nodes = []
    print("[+] 正在从高质量开源源拉取节点...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 正在爬取 Telegram 公开频道节点...")
    all_raw_nodes.extend(scrape_telegram_channels())

    valid_format_nodes = [n.strip() for n in all_raw_nodes if re.match(PROTOCOL_PATTERN, n.strip()) and not is_blacklisted(n.strip())]
    
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚初步去重后共有 {total_count} 个待检测节点")

    print(f"[+] 启动 DoH 解析 + 物理 IP 硬去重 + CDN 智能识别 + 连通性复测 (线程数: {MAX_WORKERS})...")
    
    direct_nodes = []  # 直连真实 VPS 节点（优先）
    cf_nodes = []      # Cloudflare 套壳节点（备用/降权）
    seen_ip_ports = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(validate_and_score_node, node): node for node in unique_nodes}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_node):
            res = future.result()
            if res:
                node_str, rtt, ip_port_key, is_cf = res
                # 物理底层 IP:Port 硬去重
                if ip_port_key not in seen_ip_ports:
                    seen_ip_ports.add(ip_port_key)
                    if is_cf:
                        cf_nodes.append((node_str, rtt))
                    else:
                        direct_nodes.append((node_str, rtt))
            completed += 1
            if completed % 100 == 0 or completed == total_count:
                print(f"[*] 进度: {completed}/{total_count} | 发现物理直连节点: {len(direct_nodes)} | CDN套壳节点: {len(cf_nodes)}")

    # 分别按响应延迟升序排列
    direct_nodes.sort(key=lambda x: x[1])
    cf_nodes.sort(key=lambda x: x[1])

    # 排序策略：优先填满直连 VPS 节点，直连不足时才用 CDN 节点补充，最多保留 5 个 CDN 节点
    final_nodes_with_rtt = direct_nodes[:TOP_NODE_LIMIT]
    if len(final_nodes_with_rtt) < TOP_NODE_LIMIT:
        needed = TOP_NODE_LIMIT - len(final_nodes_with_rtt)
        final_nodes_with_rtt.extend(cf_nodes[:min(needed, 5)])

    top_nodes = [item[0] for item in final_nodes_with_rtt]

    print(f"\n[+] 筛选完成！成功精选出 Top {len(top_nodes)} 个物理独立且真可用的节点（直连 VPS 占比: {len(final_nodes_with_rtt) - min(len(cf_nodes), 5)}/{len(top_nodes)}）。")

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
