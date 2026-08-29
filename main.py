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

# GFW 精准阻断或垃圾 SNI 域名黑名单
BLOCKED_SNIS = [
    "wagahaha.xyz", "ignitelimit.com", "example.com",
    "workers.dev", "pages.dev", "vercel.app",
    "speedtest", "ipify", "herokuapp.com"
]

INVALID_HOSTS = ["127.0.0.1", "0.0.0.0", "localhost"]

GFW_POLLUTED_IPS = {
    "0.0.0.0", "127.0.0.1", "10.10.10.10", "1.1.1.1", "8.8.8.8",
    "59.24.3.173", "203.98.7.65", "243.185.187.39", "78.16.49.15",
    "46.82.174.68", "37.61.54.158", "93.46.8.89", "211.5.133.18"
}

# 现代内核支持的 SS 安全加密算法白名单
ALLOWED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"
}

MIRROR_PREFIX = "https://ghp.ci/"
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

MAX_WORKERS = 40           # 测试并发数
TOP_NODE_LIMIT = 80        # 精选 80 个物理有效优质节点
HANDSHAKE_TIMEOUT = 0.8    # 握手超时时间控制在 0.8 秒内

# ==================== 工具与数据清洗函数 ====================

def clean_node_string(node_str: str) -> str:
    """清理节点链接中的 HTML 标签、多余空格和不可见字符"""
    node_str = re.sub(r'<[^>]+>', '', node_str)  # 剥离所有 HTML 标签
    node_str = node_str.strip().replace('\r', '').replace('\n', '')
    return node_str

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
                if cipher.lower() not in ALLOWED_SS_CIPHERS:
                    continue
                userinfo = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                nodes.append(f"ss://{userinfo}@{server}:{port}#{name}")
            elif p_type in ("vmess", "vless"):
                uuid = kv.get("uuid", "")
                if p_type == "vmess":
                    v_json = {
                        "v": "2", "ps": kv.get("name", "Node"), "add": server,
                        "port": port, "id": uuid, "aid": kv.get("alterId", "0"),
                        "net": kv.get("network", "tcp"), "type": "none",
                        "tls": "tls" if kv.get("tls") == "true" else "",
                        "host": kv.get("servername") or kv.get("ws-headers", {}).get("Host", ""),
                        "path": kv.get("ws-path", "")
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
        if blocked in node_lower:
            return True
    for inv in INVALID_HOSTS:
        if inv in node_lower:
            return True
    return False

def extract_node_details(node_str: str):
    """提取节点的地址、端口、TLS 状态、SNI 以及用于精确去重的凭据 (UUID/Path)"""
    try:
        is_tls = False
        sni = ""
        credential = ""

        if node_str.startswith("vmess://"):
            js = json.loads(safe_b64decode(node_str[8:]))
            host = js.get("add")
            port = int(js.get("port", 443))
            is_tls = js.get("tls") in ["tls", "1", True]
            sni = js.get("sni") or js.get("host") or host
            credential = f"{js.get('id', '')}:{js.get('path', '')}"
            return host, port, is_tls, sni, credential
            
        elif node_str.startswith("ss://"):
            clean_str = node_str[5:]
            if '#' in clean_str:
                clean_str = clean_str.split('#')[0]
            
            if '@' in clean_str:
                userinfo, server_part = clean_str.split('@', 1)
            else:
                decoded = safe_b64decode(clean_str)
                if '@' in decoded:
                    userinfo, server_part = decoded.split('@', 1)
                else:
                    return None, None, False, "", ""
            
            # SS 算法兼容性校验
            try:
                cipher_pass = safe_b64decode(userinfo) if not userinfo.count(':') else userinfo
                cipher = cipher_pass.split(':')[0].lower()
                if cipher not in ALLOWED_SS_CIPHERS:
                    return None, None, False, "", ""
            except Exception:
                pass

            host, port = server_part.split(':')
            return host, int(port), False, "", userinfo
            
        else:
            parsed = urllib.parse.urlparse(node_str)
            host = parsed.hostname
            port = parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            is_tls = "security" in query and query["security"][0] in ["tls", "reality"]
            if node_str.startswith("trojan://") or node_str.startswith("hysteria2://") or node_str.startswith("hy2://"):
                is_tls = True
            sni = query.get("sni", [host])[0]
            credential = parsed.username or parsed.path or ""
            return host, port, is_tls, sni, credential
            
    except Exception:
        return None, None, False, "", ""

# ==================== 防污染 DNS 与 连通性探针 ====================

def query_doh_provider(doh_url: str, host: str) -> str:
    try:
        req = urllib.request.Request(f"{doh_url}?name={host}&type=1", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=1.2) as resp:
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
    ip = query_doh_provider("https://doh.pub/resolve", host)
    if ip:
        return ip
    
    # 备用：如 DoH 均被海外 Actions 限流，退回系统安全解析
    try:
        resolved = socket.gethostbyname(host)
        if resolved not in GFW_POLLUTED_IPS:
            return resolved
    except Exception:
        pass
    return None

def test_node_connectivity(ip: str, port: int, is_tls: bool, sni: str) -> float:
    """双重复测 TCP / TLS 建连响应"""
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
        time.sleep(0.03)

    return sum(rtts) / len(rtts) if len(rtts) == 2 else -1

def validate_and_score_node(node_str: str):
    cleaned_node = clean_node_string(node_str)
    host, port, is_tls, sni, credential = extract_node_details(cleaned_node)
    if not host or not port:
        return None

    # 1. DoH 防污染解析
    resolved_ip = check_china_doh_multi(host)
    if not resolved_ip or resolved_ip in GFW_POLLUTED_IPS:
        return None

    # 2. 建连测速
    rtt = test_node_connectivity(resolved_ip, port, is_tls, sni)
    if rtt <= 0:
        return None

    # 核心修补：联合维度去重 Key (IP + 端口 + SNI + 账号/路径)
    # 彻底解决 Cloudflare 几千个节点因为 IP 相同被只保留 1 个的致命 BUG！
    dedup_key = f"{resolved_ip}:{port}:{sni}:{credential}"
    return (cleaned_node, rtt, dedup_key)

# ==================== 主逻辑 ====================

def main():
    all_raw_nodes = []
    print("[+] 正在拉取高质量开源源...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 正在爬取 Telegram 频道节点...")
    all_raw_nodes.extend(scrape_telegram_channels())

    # 初步清理与黑名单过滤
    valid_format_nodes = []
    for n in all_raw_nodes:
        cleaned = clean_node_string(n)
        if re.match(PROTOCOL_PATTERN, cleaned) and not is_blacklisted(cleaned):
            valid_format_nodes.append(cleaned)
    
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚清洗后共有 {total_count} 个待检测候选节点")

    print(f"[+] 启动 DoH 真实 IP 解析 + 联合维度去重 + 双重 TLS 握手测试 (线程数: {MAX_WORKERS})...")
    
    scored_nodes = []
    seen_keys = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(validate_and_score_node, node): node for node in unique_nodes}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_node):
            res = future.result()
            if res:
                node_str, rtt, dedup_key = res
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    scored_nodes.append((node_str, rtt))
            completed += 1
            if completed % 100 == 0 or completed == total_count:
                print(f"[*] 进度: {completed}/{total_count} | 发现真正物理可用节点: {len(scored_nodes)}")

    # 按响应耗时升序排列
    scored_nodes.sort(key=lambda x: x[1])
    top_nodes = [item[0] for item in scored_nodes[:TOP_NODE_LIMIT]]

    print(f"\n[+] 筛选完成！从 {len(scored_nodes)} 个真正可建连的物理节点中，精选出 Top {len(top_nodes)} 个唯一优选节点。")

    # 输出 Base64 订阅文件
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
