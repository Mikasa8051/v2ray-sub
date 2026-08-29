import base64
import json
import re
import socket
import ssl
import concurrent.futures
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

# 3. 昨天的核心：精确拦截伪造 SNI / 垃圾域名黑名单
BLOCKED_SNIS = [
    "u729792us3017.wagahaha.xyz",
    "www.ignitelimit.com",
    "www.cloudflare.com",
    "cloudfront.net",
    "example.com"
]

# 4. 1ms 本地回环/假 IP 过滤名单
INVALID_HOSTS = ["127.0.0.1", "0.0.0.0", "localhost"]

# 5. 云端测速参数
MAX_THREADS = 80         # 线程数
CONNECT_TIMEOUT = 1.8    # 连通性超时（秒）

# CDN 加速镜像前缀
MIRROR_PREFIX = "https://ghp.ci/"

# 通用正则与请求头
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# ==================== 工具函数 ====================

def safe_b64decode(s: str) -> str:
    """安全的 Base64 解码函数"""
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
            with urllib.request.urlopen(req, timeout=12) as resp:
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
    """从 Telegram 公开 Web 页面提取节点数据"""
    scraped_nodes = []
    for channel in TG_PUBLIC_CHANNELS:
        url = f"https://telegram.dog/s/{channel}"
        print(f"[*] [TG爬虫] 正在爬取频道: @{channel}")
        html = fetch_url_content(url)
        if html:
            matches = re.findall(PROTOCOL_PATTERN, html)
            scraped_nodes.extend(matches)
        else:
            print(f"[-] 爬取 TG 频道 @{channel} 失败")
    return scraped_nodes

def parse_node_info(node_str: str):
    """提取 Host, Port, SNI 以及 TLS 标识"""
    host, port, sni, use_tls = None, None, None, False
    try:
        if node_str.startswith("vmess://"):
            b64_str = node_str[8:]
            decoded = safe_b64decode(b64_str)
            js = json.loads(decoded)
            host = js.get("add")
            port = int(js.get("port", 443))
            sni = js.get("sni") or js.get("host") or host
            use_tls = js.get("tls") == "tls"
        elif any(node_str.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "ss://"]):
            parsed = urllib.parse.urlparse(node_str)
            host = parsed.hostname
            port = parsed.port
            
            if not host and "@" in parsed.netloc:
                netloc_part = parsed.netloc.split("@")[-1]
                if ":" in netloc_part:
                    host, port_str = netloc_part.split(":", 1)
                    port = int(port_str.split("?")[0].split("#")[0])
            
            query = urllib.parse.parse_qs(parsed.query)
            sni = query.get("sni", [host])[0]
            use_tls = "tls" in query.get("security", [""])[0] or node_str.startswith(("trojan://", "hy2://"))
    except Exception:
        pass

    return host, port, sni, use_tls

def is_blacklisted(node_str: str, host: str) -> bool:
    """第一重防线：黑名单 SNI 与 1ms 回环 IP 校验"""
    node_lower = node_str.lower()
    for blocked in BLOCKED_SNIS:
        if blocked.lower() in node_lower:
            return True
    
    if host and any(inv in host.lower() for inv in INVALID_HOSTS):
        return True

    return False

def check_node_alive(node_str: str) -> str:
    """第二重防线：云端智能 TLS/TCP 握手测试"""
    host, port, sni, use_tls = parse_node_info(node_str)

    if not host or not port:
        return None

    if is_blacklisted(node_str, host):
        return None

    try:
        # TCP 三次握手
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(CONNECT_TIMEOUT)
        
        if use_tls:
            # 带 TLS 握手的高级检测（防止错杀暗影节点）
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with context.wrap_socket(raw_sock, server_hostname=sni or host) as ssl_sock:
                ssl_sock.connect((host, port))
                return node_str
        else:
            # 普通 TCP 校验
            res = raw_sock.connect_ex((host, port))
            raw_sock.close()
            if res == 0:
                return node_str
    except Exception:
        pass

    return None

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

    # 规范化格式筛选
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    # 去重处理
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚去重后共有 {total_count} 个待测节点")

    print(f"[+] 阶段 3: 启动黑名单过滤 + {MAX_THREADS} 线程云端 TLS/TCP 握手测试...")
    clean_nodes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_node_alive, node): node for node in unique_nodes}
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                clean_nodes.append(res)
            completed += 1
            if completed % 500 == 0 or completed == total_count:
                print(f"[*] 测速进度: {completed}/{total_count} | 存活保留节点: {len(clean_nodes)}")

    print(f"\n[+] 测速完成！全网收集: {total_count} 个 -> 精选存活: {len(clean_nodes)} 个")

    # 生成 Base64 订阅文件
    sub_content = "\n".join(clean_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
