import base64
import json
import re
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# 1. 静态订阅源列表
SOURCES = [
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
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

# 联通优选关键字与黑名单
UNICOM_FAVORITE_KEYWORDS = ['HK', '香港', 'JP', '日本', 'KR', '韩国', 'SG', '新加坡', 'US', '美国']
BLOCKED_IPS = {'127.0.0.1', '0.0.0.0', 'localhost', '10.0.0.0', '172.16.0.0', '192.168.0.0'}
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

def safe_b64decode(s):
    """安全的 Base64 解码（支持自动补全与递归）"""
    s = s.strip()
    # 过滤非 Base64 字符
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
    # 匹配 YAML 中 proxies 列表块
    proxy_blocks = re.findall(r"-\s*\{([^}]+)\}", yaml_text)
    if not proxy_blocks:
        # 兼容缩进换行格式的 YAML
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
    """拉取静态订阅源（多重解码）"""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore').strip()
            
            if "proxies:" in content or url.endswith((".yaml", ".yml")):
                yaml_nodes = parse_clash_yaml(content)
                if yaml_nodes:
                    return yaml_nodes

            # 循环解码最多 3 层 Base64，防止多重嵌套
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
    """爬取 TG 公开频道"""
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

def parse_node_info(node_str):
    """健壮的节点信息解析器（支持提取多格式 SS、VMess、VLess 等）"""
    host, port, name = None, None, ""
    try:
        if node_str.startswith("vmess://"):
            b64_data = node_str[8:]
            info = json.loads(safe_b64decode(b64_data))
            host = info.get('add')
            port = int(info.get('port', 443))
            name = info.get('ps', '')
        elif node_str.startswith("ss://"):
            # 兼容 SS 标准与 SIP002 格式
            clean_str = node_str[5:]
            if "#" in clean_str:
                clean_str, name = clean_str.split("#", 1)
                name = urllib.parse.unquote(name)
            if "@" in clean_str:
                server_part = clean_str.split("@")[-1]
                if ":" in server_part:
                    host, port_str = server_part.split(":", 1)
                    port = int(port_str.split("/")[0].split("?")[0])
        elif node_str.startswith(("vless://", "trojan://", "hysteria2://", "hy2://", "tuic://")):
            # 匹配常规协议的标准 URL 格式
            match = re.search(r'@([^:]+):(\d+)', node_str)
            if match:
                host = match.group(1)
                port = int(match.group(2))
            if "#" in node_str:
                name = urllib.parse.unquote(node_str.split("#")[-1])
    except Exception:
        pass
    return host, port, name

def check_node_quality(node_str):
    """快速 TCP 端口连通性检测与简单评分"""
    host, port, name = parse_node_info(node_str)
    
    if not host or not port or host in BLOCKED_IPS:
        return None

    try:
        # 防卡死：解析主机域名 IP，如果解析失败直接跳过
        ip = socket.gethostbyname(host)
        if ip in BLOCKED_IPS:
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)  # 控制在 1.5 秒内响应
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            score = 0
            # 针对较新协议给予加分
            if node_str.startswith(("hysteria2://", "hy2://", "tuic://", "vless://")):
                score += 20
            # 命中地区关键字给予加分
            for kw in UNICOM_FAVORITE_KEYWORDS:
                if kw.lower() in name.lower() or kw.lower() in host.lower():
                    score += 50
                    break
            return (score, node_str)
    except Exception:
        pass
    return None

def main():
    all_raw_nodes = []

    print("[+] 阶段 1: 正在拉取静态订阅源节点...")
    for src in SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 阶段 2: 正在爬取 Telegram 公开频道节点...")
    tg_nodes = scrape_telegram_channels()
    all_raw_nodes.extend(tg_nodes)

    # 提取格式合规的节点并去重
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    unique_nodes = list(set(valid_format_nodes))
    print(f"[+] 汇聚去重后共有 {len(unique_nodes)} 个待检测节点")

    print("[+] 阶段 3: 正在进行并发质量检测与优选...")
    scored_nodes = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_node_quality, unique_nodes)
        for res in results:
            if res:
                scored_nodes.append(res)

    # 排序：按照得分降序，并截取前 200 个可用节点
    scored_nodes.sort(key=lambda x: x[0], reverse=True)
    final_nodes = [item[1] for item in scored_nodes[:200]]

    print(f"[+] 检测完毕！成功筛选出存活节点: {len(final_nodes)} 个")

    # 导出 Base64 订阅文件
    sub_content = "\n".join(final_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
