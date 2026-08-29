import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request

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

# 真实测速参数
TEST_URL = "https://speed.cloudflare.com/__down?bytes=5000000"  # 下载 5MB 测试文件测速
DOWNLOAD_TIMEOUT = 4.0      # 单个节点测速超时时间（秒）
MIN_SPEED_KBS = 200.0       # 最低保留网速阈值 (KB/s)，低于此速度直接剔除
TOP_NODE_LIMIT = 200        # 最终精选保留的最大高效节点数

LOCAL_PROXY_PORT = 10808    # sing-box 本地代理端口
MIRROR_PREFIX = "https://ghp.ci/"
PROTOCOL_PATTERN = r"(?:vmess|vless|ss|trojan|socks5|hy2|hysteria2|tuic)://[a-zA-Z0-9%_\.\:\-\=\+\/\?\&\#\~\@\-\+]+"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

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

# ==================== sing-box 动态测速核心 ====================

def generate_singbox_config(outbound_json: dict) -> dict:
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": LOCAL_PROXY_PORT
            }
        ],
        "outbounds": [
            outbound_json,
            {"type": "direct", "tag": "direct"}
        ]
    }

def parse_singbox_outbound(node_str: str):
    try:
        if node_str.startswith("vmess://"):
            js = json.loads(safe_b64decode(node_str[8:]))
            return {
                "type": "vmess",
                "tag": "proxy",
                "server": js.get("add"),
                "server_port": int(js.get("port", 443)),
                "uuid": js.get("id"),
                "security": "auto",
                "tls": {"enabled": js.get("tls") == "tls", "insecure": True} if js.get("tls") == "tls" else {}
            }
        elif node_str.startswith("vless://"):
            parsed = urllib.parse.urlparse(node_str)
            query = urllib.parse.parse_qs(parsed.query)
            uuid = parsed.username
            return {
                "type": "vless",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "uuid": uuid,
                "tls": {"enabled": True, "insecure": True} if "tls" in query.get("security", [""]) else {}
            }
        elif node_str.startswith("trojan://"):
            parsed = urllib.parse.urlparse(node_str)
            return {
                "type": "trojan",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "password": parsed.username,
                "tls": {"enabled": True, "insecure": True}
            }
        elif node_str.startswith("ss://"):
            parsed = urllib.parse.urlparse(node_str)
            user_info = safe_b64decode(parsed.username) if parsed.username else ""
            if ":" in user_info:
                method, password = user_info.split(":", 1)
                return {
                    "type": "shadowsocks",
                    "tag": "proxy",
                    "server": parsed.hostname,
                    "server_port": parsed.port,
                    "method": method,
                    "password": password
                }
    except Exception:
        pass
    return None

def measure_download_speed_via_proxy(node_str: str) -> float:
    outbound = parse_singbox_outbound(node_str)
    if not outbound:
        return 0.0

    config = generate_singbox_config(outbound)
    config_file = f"temp_config_{os.getpid()}.json"
    
    speed_kbs = 0.0
    proc = None
    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            ["sing-box", "run", "-c", config_file], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.4)

        proxy_handler = urllib.request.ProxyHandler({
            'http': f'http://127.0.0.1:{LOCAL_PROXY_PORT}', 
            'https': f'http://127.0.0.1:{LOCAL_PROXY_PORT}'
        })
        opener = urllib.request.build_opener(proxy_handler)

        start_time = time.time()
        req = urllib.request.Request(TEST_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with opener.open(req, timeout=DOWNLOAD_TIMEOUT) as response:
            bytes_downloaded = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                bytes_downloaded += len(chunk)
                if time.time() - start_time > DOWNLOAD_TIMEOUT:
                    break

            duration = time.time() - start_time
            if duration > 0 and bytes_downloaded > 0:
                speed_kbs = (bytes_downloaded / 1024.0) / duration
    except Exception:
        speed_kbs = 0.0
    finally:
        if proc:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
        if os.path.exists(config_file):
            try:
                os.remove(config_file)
            except Exception:
                pass

    return speed_kbs

# ==================== 主逻辑 ====================

def main():
    all_raw_nodes = []
    print("[+] 正在拉取静态订阅源节点...")
    for src in RAW_SOURCES:
        nodes = fetch_from_sources(src)
        all_raw_nodes.extend(nodes)

    print("[+] 正在爬取 Telegram 公开频道节点...")
    all_raw_nodes.extend(scrape_telegram_channels())

    valid_format_nodes = [n.strip() for n in all_raw_nodes if re.match(PROTOCOL_PATTERN, n.strip()) and not is_blacklisted(n.strip())]
    unique_nodes = list(set(valid_format_nodes))
    total_count = len(unique_nodes)
    print(f"[+] 汇聚去重并过滤黑名单后共有 {total_count} 个待测节点")

    print(f"[+] [方案 B] 正在调用 sing-box 进行【真实文件下载流量测速】...")
    speed_results = []
    
    candidate_nodes = unique_nodes[:600]
    
    for idx, node in enumerate(candidate_nodes, 1):
        speed = measure_download_speed_via_proxy(node)
        if speed >= MIN_SPEED_KBS:
            speed_results.append((node, speed))
            print(f"[{idx}/{len(candidate_nodes)}] 节点可真实连接 -> 速度: {speed:.1f} KB/s")
        else:
            if idx % 50 == 0:
                print(f"[{idx}/{len(candidate_nodes)}] 测速推进中... (已找到 {len(speed_results)} 个高速节点)")

    print(f"\n[+] 测速完成！共获取到 {len(speed_results)} 个高速节点（网速 >= {MIN_SPEED_KBS} KB/s）")

    # 按网速从大到小降序排列
    speed_results.sort(key=lambda x: x[1], reverse=True)

    # 截取网速前 200 名
    top_nodes = speed_results[:TOP_NODE_LIMIT]
    top_clean_nodes = [item[0] for item in top_nodes]

    if top_nodes:
        print(f"[+] 精选完成：已保留前 {len(top_clean_nodes)} 个最高速节点（最高速度: {top_nodes[0][1]/1024:.2f} MB/s）")

    # 输出文件
    sub_content = "\n".join(top_clean_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    os.makedirs("public", exist_ok=True)
    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    with open("public/nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)

    print("[+] 订阅文件 nekoray_sub.txt 及 public/nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
