import base64
import json
import re
import socket
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

# 3. 测速与并发参数
MAX_THREADS = 100        # 并发线程数
CONNECT_TIMEOUT = 2.5    # 单节点 TCP 建连超时时间（秒）

# CDN 加速镜像前缀
MIRROR_PREFIX = "https://ghp.ci/"

# 通用正则与请求头
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# 本地回环与伪造节点 IP 过滤名单（直接拦截 1ms 假节点）
INVALID_HOSTS = ["127.0.0.1", "0.0.0.0", "localhost"]

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

def parse_node_address(node_str: str):
    """从节点链接中解析出真实的 (Host, Port) 进行 TCP 测速"""
    try:
        if node_str.startswith("vmess://"):
            b64_str = node_str[8:]
            decoded = safe_b64decode(b64_str)
            js = json.loads(decoded)
            return js.get("add"), int(js.get("port", 443))
        
        elif any(node_str.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "ss://"]):
            # 处理标准 URI 格式: protocol://[auth@]host:port...
            parsed = urllib.parse.urlparse(node_str)
            host = parsed.hostname
            port = parsed.port
            
            # 部分 SS 节点包含 Base64 账号信息
            if not host and "@" in parsed.netloc:
                netloc_part = parsed.netloc.split("@")[-1]
                if ":" in netloc_part:
                    host, port_str = netloc_part.split(":", 1)
                    port = int(port_str.split("?")[0].split("#")[0])
            
            if host and port:
                return host, int(port)
    except Exception:
        pass
    return None, None

def check_node_alive(node_str: str) -> str:
    """对单个节点实施真实 TCP 端口连通性测试"""
    host, port = parse_node_address(node_str)
    
    # 过滤无法解析或者属于 1ms 假节点的 Host
    if not host or not port or host in INVALID_HOSTS:
        return None

    try:
        # 创建底层 TCP Socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        
        # 建立三次握手
        result = sock.connect_ex((host, port))
        sock.close()
        
        # 只有端口开放、握手成功才保留
        if result == 0:
            return node_str
    except Exception:
        pass
    
    return None

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

    # 基础格式校验
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    # 去重
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚去重后共有 {total_count} 个待测节点")

    print(f"[+] 阶段 3: 启动 {MAX_THREADS} 线程进行高并发 TCP 连通性测速...")
    alive_nodes = []
    
    # 线程池并发测试端口
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_node_alive, node): node for node in unique_nodes}
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                alive_nodes.append(res)
            completed += 1
            if completed % 500 == 0 or completed == total_count:
                print(f"[*] 测速进度: {completed}/{total_count} | 当前存活节点: {len(alive_nodes)}")

    print(f"\n[+] 测速完成！全网收集: {total_count} 个 -> 实际可用: {len(alive_nodes)} 个")

    # 生成 Base64 订阅文件
    sub_content = "\n".join(alive_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 生成完成！")

if __name__ == "__main__":
    main()
