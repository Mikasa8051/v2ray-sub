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

# ==================== 1. 配置区 ====================

# 汇总所有历史与最新的高频更新源列表（已去重）
RAW_SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://fastly.jsdelivr.net/gh/ALIILAPRO/v2rayng-config@master/sub.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/w2ray/v2ray/main/v2ray",
    "https://raw.githubusercontent.com/fsub/v2ray/main/sub",
    "https://raw.githubusercontent.com/Emerge-Nodes/Emerge-Nodes/main/sub",
    "https://raw.githubusercontent.com/vless-node/vless-node/main/vless.txt",
    "https://raw.githubusercontent.com/mftzgv/Free-Node-Merge/main/out/nodes.txt"
]

# Telegram 公开抓取频道
TG_PUBLIC_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

# GFW 精准阻断 SNI 域名与非法主机名黑名单
BLOCKED_SNIS = [
    "wagahaha.xyz", "ignitelimit.com", "example.com",
    "workers.dev", "pages.dev", "vercel.app",
    "speedtest", "ipify", "herokuapp.com"
]

INVALID_HOSTS = ["127.0.0.1", "0.0.0.0", "localhost"]

# GFW 常见污染固定投毒 IP
GFW_POLLUTED_IPS = {
    "0.0.0.0", "127.0.0.1", "10.10.10.10", "1.1.1.1", "8.8.8.8",
    "59.24.3.173", "203.98.7.65", "243.185.187.39", "78.16.49.15",
    "46.82.174.68", "37.61.54.158", "93.46.8.89", "211.5.133.18",
    "159.106.121.75", "203.98.7.66", "243.185.187.30"
}

# 现代内核 (Xray / sing-box) 支持的安全 SS 加密算法
ALLOWED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"
}

MIRROR_PREFIX = "https://ghp.ci/"
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
}

MAX_WORKERS = 40           # 并发测试线程数
TOP_NODE_LIMIT = 80        # 精选优质节点输出数量
HANDSHAKE_TIMEOUT = 1.0    # 单次握手超时上限 (秒)

# ==================== 2. 工具与清洗函数 ====================

def clean_node_string(node_str: str) -> str:
    """清理节点链接中的 HTML 标签、多余空格和控制字符"""
    node_str = re.sub(r'<[^>]+>', '', node_str)
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
    """解析 Clash YAML 格式的订阅并转化为标准链接"""
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
    """带镜像降级的通用 HTTP 请求"""
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
        print(f"  [x] 请求失败/被阻断: {url}")
        return []

    # 过滤反爬虫 HTML 报错页
    if "<html" in content.lower() or "<doctype" in content.lower():
        print(f"  [x] 返回了非节点 HTML 页面: {url}")
        return []

    # 解析 Clash YAML
    if "proxies:" in content or url.endswith((".yaml", ".yml")):
        yaml_nodes = parse_clash_yaml(content)
        if yaml_nodes:
            print(f"  [√] Clash 源成功提取 {len(yaml_nodes)} 个节点: {url}")
            return yaml_nodes

    # 多层 Base64 解码
    curr = content
    for _ in range(3):
        decoded = safe_b64decode(curr)
        if decoded and any(p in decoded for p in ["vmess://", "vless://", "ss://", "trojan://"]):
            curr = decoded
        else:
            break
    
    nodes = [line.strip() for line in curr.splitlines() if line.strip()]
    print(f"  [√] 成功提取 {len(nodes)} 个节点: {url}")
    return nodes

def scrape_telegram_channels() -> list:
    scraped_nodes = []
    for channel in TG_PUBLIC_CHANNELS:
        url = f"https://telegram.dog/s/{channel}"
        html = fetch_url_content(url)
        if html:
            matches = re.findall(PROTOCOL_PATTERN, html)
            scraped_nodes.extend(matches)
    print(f"  [√] Telegram 频道共爬取到 {len(scraped_nodes)} 个节点")
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
    """提取节点的Host、端口、TLS状态、SNI及联合去重凭据"""
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
            
            # SS 校验算法安全性
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

# ==================== 3. DNS 与物理建连测试 ====================

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

    # 多路 DoH 校验
    ip = query_doh_provider("https://dns.alidns.com/resolve", host)
    if ip:
        return ip
    ip = query_doh_provider("https://doh.pub/resolve", host)
    if ip:
        return ip
    
    # DoH 被 Actions 限流时退回系统解析
    try:
        resolved = socket.gethostbyname(host)
        if resolved not in GFW_POLLUTED_IPS:
            return resolved
    except Exception:
        pass
    return None

def test_node_connectivity(ip: str, port: int, is_tls: bool, sni: str) -> float:
    """真实 TCP/TLS 握手延时探针 (双测试取均值)"""
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
        time.sleep(0.02)

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

    # 2. 真实建连测速
    rtt = test_node_connectivity(resolved_ip, port, is_tls, sni)
    if rtt <= 0:
        return None

    # 3. 联合维度 Key 去重 (IP + 端口 + SNI + 账号凭据/Path)
    dedup_key = f"{resolved_ip}:{port}:{sni}:{credential}"
    return (cleaned_node, rtt, dedup_key)

# ==================== 4. 主程序入口 ====================

def main():
    all_raw_nodes = []
    print("[+] 开始拉取全量开源订阅源...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 开始抓取 Telegram 频道...")
    all_raw_nodes.extend(scrape_telegram_channels())

    # 基础清洗与黑名单剥离
    valid_format_nodes = []
    for n in all_raw_nodes:
        cleaned = clean_node_string(n)
        if re.match(PROTOCOL_PATTERN, cleaned) and not is_blacklisted(cleaned):
            valid_format_nodes.append(cleaned)
    
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"\n[+] 汇聚去重后共有 {total_count} 个候选节点进入深度测试流程")

    print(f"[+] 启动物理连通性探针 (并发线程数: {MAX_WORKERS})...")
    
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
                print(f"[*] 扫描进度: {completed}/{total_count} | 当前有效节点: {len(scored_nodes)}")

    # 按物理握手响应延迟升序排序
    scored_nodes.sort(key=lambda x: x[1])
    top_nodes = [item[0] for item in scored_nodes[:TOP_NODE_LIMIT]]

    print(f"\n[+] 测试完毕！最终精选出 {len(top_nodes)} 个最优质可用节点。")

    # 导出 Base64 订阅文件
    sub_content = "\n".join(top_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    os.makedirs("public", exist_ok=True)
    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    with open("public/nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print("[+] 订阅文本 `nekoray_sub.txt` 及 `public/nekoray_sub.txt` 已成功写入并更新！")

if __name__ == "__main__":
    main()
