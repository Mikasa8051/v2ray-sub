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

# ==================== 1. 订阅源与 TG 频道配置 ====================

SOURCES = [
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

TG_CHANNELS = [
    "v2ray_free_conf",
    "Freev2rays",
    "v2ray_free_nodes",
    "FreeV2RayConfig"
]

MIRROR_PREFIX = "https://ghp.ci/"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# ==================== 2. 基础解包与清洗工具 ====================

def safe_b64decode(data: str) -> str:
    """安全 Base64 解码，处理 padding 与非标准字符"""
    data = data.strip().replace('\r', '').replace('\n', '')
    data = re.sub(r'[^a-zA-Z0-9+/=_-]', '', data)
    data = data.replace('-', '+').replace('_', '/')
    missing = len(data) % 4
    if missing:
        data += '=' * (4 - missing)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def fetch_url(url: str) -> str:
    """拉取 URL 内容（含 GitHub 镜像回退）"""
    targets = [url]
    if "raw.githubusercontent.com" in url or "github.com" in url:
        targets.append(MIRROR_PREFIX + url)

    for target in targets:
        try:
            req = urllib.request.Request(target, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=8) as resp:
                text = resp.read().decode('utf-8', errors='ignore').strip()
                if text:
                    return text
        except Exception:
            continue
    return ""

def extract_nodes_from_text(text: str) -> list:
    """递归解包与提取所有符合协议格式的节点"""
    if not text:
        return []

    # 1. 尝试多层 Base64 解码
    curr_text = text
    for _ in range(3):
        decoded = safe_b64decode(curr_text)
        if decoded and any(proto in decoded for proto in ["vmess://", "vless://", "ss://", "trojan://"]):
            curr_text = decoded
        else:
            break

    # 2. 正则抓取节点链接并剥离网页/HTML污染
    pattern = r"(?:vmess|vless|ss|trojan|hy2|hysteria2|tuic)://[^\s<'\"]+"
    raw_matches = re.findall(pattern, curr_text)

    cleaned_nodes = []
    for m in raw_matches:
        m = re.sub(r'<[^>]+>', '', m).strip()
        if len(m) > 10:
            cleaned_nodes.append(m)
    return cleaned_nodes

def fetch_telegram_nodes(channel: str) -> list:
    """抓取 Telegram 公开频道的节点"""
    url = f"https://t.me/s/{channel}"
    html = fetch_url(url)
    if not html:
        # 尝试备用 Web 域名
        url_alt = f"https://telegram.dog/s/{channel}"
        html = fetch_url(url_alt)
    return extract_nodes_from_text(html)

# ==================== 3. 节点网络地址解析器 ====================

def parse_host_port(node_url: str):
    """从节点链接中解析物理 Host 与 Port"""
    try:
        if node_url.startswith("vmess://"):
            b64_str = node_url[8:]
            decoded = safe_b64decode(b64_str)
            js = json.loads(decoded)
            return js.get("add"), int(js.get("port", 443))

        elif node_url.startswith("ss://"):
            clean = node_url[5:].split('#')[0]
            if '@' in clean:
                server_part = clean.split('@', 1)[1]
            else:
                decoded = safe_b64decode(clean)
                if '@' in decoded:
                    server_part = decoded.split('@', 1)[1]
                else:
                    return None, None
            host, port = server_part.rsplit(':', 1)
            return host, int(port)

        else:  # vless, trojan, hy2, hysteria2, tuic
            parsed = urllib.parse.urlparse(node_url)
            if parsed.hostname and parsed.port:
                return parsed.hostname, int(parsed.port)
            elif parsed.hostname:
                return parsed.hostname, 443
    except Exception:
        pass
    return None, None

# ==================== 4. 真实网络探测器 ====================

def ping_test(host: str, port: int, timeout: float = 1.2) -> float:
    """TCP / SSL 基础连通性握手测试"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 针对 443 端口进行简易 TLS 握手测试
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
            ssl_sock.close()
        else:
            sock.close()

        return (time.time() - start) * 1000
    except Exception:
        return -1.0

def verify_node(node_url: str):
    """节点验证任务流程"""
    host, port = parse_host_port(node_url)
    if not host or not port:
        return None

    rtt = ping_test(host, port)
    if rtt > 0:
        return (node_url, rtt)
    return None

# ==================== 5. 主控制流程 ====================

def main():
    print("========================================")
    print(" 开始运行多源 + Telegram 节点抓取任务")
    print("========================================\n")

    raw_nodes = []

    # 1. 抓取订阅源
    print("[1/3] 正在拉取开源订阅源...")
    for idx, url in enumerate(SOURCES, 1):
        content = fetch_url(url)
        nodes = extract_nodes_from_text(content)
        print(f"  [订阅源 {idx}/{len(SOURCES)}] {url[:40]}... -> 提取到 {len(nodes)} 个节点")
        raw_nodes.extend(nodes)

    # 2. 抓取 Telegram 频道
    print("\n[2/3] 正在拉取 Telegram 频道...")
    for ch in TG_CHANNELS:
        nodes = fetch_telegram_nodes(ch)
        print(f"  [Telegram 频道] @{ch} -> 提取到 {len(nodes)} 个节点")
        raw_nodes.extend(nodes)

    # 3. 去重与物理连通性检测
    unique_nodes = list(set(raw_nodes))
    total_found = len(unique_nodes)
    print(f"\n[3/3] 汇聚去重后共有 {total_found} 个候选节点进入连通性检测...")

    valid_results = []
    max_workers = 30
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_node, node): node for node in unique_nodes}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                valid_results.append(res)
            completed += 1
            if completed % 100 == 0 or completed == total_found:
                print(f"  检测进度: {completed}/{total_found} | 存活节点: {len(valid_results)}")

    # 按响应延迟排序
    valid_results.sort(key=lambda x: x[1])
    top_nodes = [item[0] for item in valid_results[:100]]

    print(f"\n检测完成！发现 {len(valid_results)} 个存活节点，精选前 {len(top_nodes)} 个写入订阅...")

    # 输出 Base64 文件
    sub_text = "\n".join(top_nodes)
    encoded_sub = base64.b64encode(sub_text.encode('utf-8')).decode('utf-8')

    os.makedirs("public", exist_ok=True)
    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    with open("public/nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print("\n========================================")
    print(" 订阅文件 nekoray_sub.txt 生成成功！")
    print("========================================\n")

if __name__ == "__main__":
    main()
