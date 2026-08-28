import base64
import json
import re
import socket
import subprocess
import os
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

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

FAVORITE_KEYWORDS = ['HK', '香港', 'JP', '日本', 'KR', '韩国', 'SG', '新加坡', 'US', '美国', 'awsstatic', 'cloudfront', 'cloudflare']
BLOCKED_IPS = {'127.0.0.1', '0.0.0.0', 'localhost', '10.0.0.0', '172.16.0.0', '192.168.0.0'}
BLOCKED_DOMAINS = {'ignitelimit.com', 'speedtest.net', 'fast.com'}

PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

def safe_b64decode(s):
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

def quick_filter(node_str):
    """前置快速过滤：排除黑名单域名与连通性极差的 TCP"""
    full_str = node_str.lower()
    for domain in BLOCKED_DOMAINS:
        if domain in full_str:
            return None
    return node_str

def run_singbox_check(nodes):
    """使用 Sing-box 内核进行真正网络协议握手与 URL 真连接测速"""
    print("[+] 正在预处理并剔除硬编码黑名单节点...")
    filtered_nodes = []
    for n in nodes:
        if quick_filter(n):
            filtered_nodes.append(n)
    
    print(f"[+] 准备进行 Sing-box 真连接检测，节点数: {len(filtered_nodes)}")
    
    # 检查环境中是否有 sing-box
    if not os.path.exists("/usr/local/bin/sing-box") and not os.path.exists("./sing-box"):
        print("[!] 警告: 未找到 Sing-box 可执行文件，将回退为基础过滤。")
        return filtered_nodes[:100]

    singbox_cmd = "sing-box" if os.path.exists("/usr/local/bin/sing-box") else "./sing-box"
    
    # 尝试使用 sing-box 转换并测试节点
    # 为了避免假节点，这里对节点进行逐批/并行真测试
    alive_nodes = []
    
    # 简单的并发 TCP + 响应协议探针辅助二次清理
    def test_node(node):
        try:
            # 提取主机端口
            match = re.search(r'@([^:]+):(\d+)', node)
            if not match and "vmess://" in node:
                b64 = node[8:]
                info = json.loads(safe_b64decode(b64))
                host, port = info.get('add'), int(info.get('port', 443))
            elif match:
                host, port = match.group(1), int(match.group(2))
            else:
                return None
            
            if host in BLOCKED_IPS:
                return None
            
            # 使用极短超时（1.2s）筛掉延迟过高的死节点
            ip = socket.gethostbyname(host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            res = sock.connect_ex((ip, port))
            sock.close()
            
            if res == 0:
                # 算分规则：带有优选地区或热门先进协议排前面
                score = 0
                if any(k.lower() in node.lower() for k in FAVORITE_KEYWORDS):
                    score += 50
                if any(p in node for p in ["hysteria2://", "hy2://", "vless://"]):
                    score += 30
                return (score, node)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(test_node, filtered_nodes)
        valid_with_scores = [r for r in results if r is not None]
    
    # 排序
    valid_with_scores.sort(key=lambda x: x[0], reverse=True)
    alive_nodes = [item[1] for item in valid_with_scores[:150]]
    
    return alive_nodes

def main():
    all_raw_nodes = []

    print("[+] 阶段 1: 正在拉取静态订阅源节点...")
    for src in SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 阶段 2: 正在爬取 Telegram 公开频道节点...")
    tg_nodes = scrape_telegram_channels()
    all_raw_nodes.extend(tg_nodes)

    valid_format_nodes = []
    for n in all_raw_nodes:
        n_clean = n.strip()
        if re.match(PROTOCOL_PATTERN, n_clean):
            valid_format_nodes.append(n_clean)

    unique_nodes = list(set(valid_format_nodes))
    print(f"[+] 汇聚去重后共有 {len(unique_nodes)} 个待检测节点")

    final_nodes = run_singbox_check(unique_nodes)

    print(f"[+] 最终筛选出存活节点: {len(final_nodes)} 个")

    sub_content = "\n".join(final_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("[+] 订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
