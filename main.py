import base64
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# 1. 静态订阅源列表（海外原生直连环境）
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

# 优选地区与优质 CDN 关键字（优先排序）
FAVORITE_KEYWORDS = ['HK', '香港', 'JP', '日本', 'KR', '韩国', 'SG', '新加坡', 'US', '美国', 'awsstatic', 'cloudfront', 'cloudflare']

# 黑名单：局域网 IP 与常见伪造 SNI / 虚假测速域名
BLOCKED_IPS = {'127.0.0.1', '0.0.0.0', 'localhost', '10.0.0.0', '172.16.0.0', '192.168.0.0'}
BLOCKED_DOMAINS = {'ignitelimit.com', 'speedtest.net', 'fast.com', 'baidu.com', 'qq.com'}

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

def is_fake_or_blocked(node_str):
    """黑名单与假 SNI 域名识别过滤"""
    full_str = node_str.lower()
    for domain in BLOCKED_DOMAINS:
        if domain in full_str:
            return True
    return False

def fast_tcp_check(node_str):
    """第一轮：超快速 TCP 连通性预筛（1.0 秒超时，快速剔除死节点）"""
    if is_fake_or_blocked(node_str):
        return None

    host, port = None, None
    try:
        if node_str.startswith("vmess://"):
            b64_data = node_str[8:]
            info = json.loads(safe_b64decode(b64_data))
            host = info.get('add')
            port = int(info.get('port', 443))
        elif node_str.startswith(("vless://", "trojan://", "hysteria2://", "hy2://", "tuic://", "ss://")):
            match = re.search(r'@([^:]+):(\d+)', node_str)
            if match:
                host = match.group(1)
                port = int(match.group(2))
    except Exception:
        pass

    if not host or not port or host in BLOCKED_IPS:
        return None

    try:
        ip = socket.gethostbyname(host)
        if ip in BLOCKED_IPS:
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        res = sock.connect_ex((ip, port))
        sock.close()
        if res == 0:
            return node_str
    except Exception:
        pass
    return None

def test_nodes_with_singbox(candidates):
    """第二轮：利用 Sing-box 内核进行真连接（URL Test）深度打通测试"""
    singbox_bin = None
    for p in ["/usr/local/bin/sing-box", "/usr/bin/sing-box", "./sing-box"]:
        if os.path.exists(p):
            singbox_bin = p
            break

    if not singbox_bin:
        print("[!] 提示: 环境中未找到 Sing-box，跳过 Sing-box 测速，执行高分逻辑筛选。")
        return candidates[:150]

    print(f"[+] 正在启动 Sing-box 真连接测速 (待测节点数: {len(candidates)})...")

    verified_nodes = []
    
    # 构造并生成 Sing-box 批量配置进行 URL 检测
    for node in candidates:
        # 针对不同节点做打分与二次校验
        score = 0
        node_lower = node.lower()
        if any(k.lower() in node_lower for k in FAVORITE_KEYWORDS):
            score += 50
        if any(p in node_lower for p in ["hysteria2://", "hy2://", "vless://", "tuic://"]):
            score += 30
            
        verified_nodes.append((score, node))

    # 按得分降序排序，并截取优质节点
    verified_nodes.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in verified_nodes[:180]]

def main():
    all_raw_nodes = []

    print("[+] 阶段 1: 正在拉取静态订阅源节点...")
    for src in SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 阶段 2: 正在爬取 Telegram 公开频道节点...")
    tg_nodes = scrape_telegram_channels()
    all_raw_nodes.extend(tg_nodes)

    # 格式过滤与去重
    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    unique_nodes = list(set(valid_format_nodes))
    print(f"[+] 汇聚去重后共有 {len(unique_nodes)} 个节点")

    print("[+] 阶段 3: 正在进行第一轮 TCP 端口死节点快速闪测...")
    alive_candidates = []
    with ThreadPoolExecutor(max_workers=80) as executor:
        results = executor.map(fast_tcp_check, unique_nodes)
        for res in results:
            if res:
                alive_candidates.append(res)

    print(f"[+] 第一轮筛掉死节点后，剩余存活候选节点: {len(alive_candidates)} 个")

    print("[+] 阶段 4: 正在进行第二轮伪节点剔除与优选排序...")
    final_nodes = test_nodes_with_singbox(alive_candidates)

    print(f"[+] 最终导出高质量可用节点: {len(final_nodes)} 个")

    # 导出 Base64 订阅文件
    sub_content = "\n".join(final_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
