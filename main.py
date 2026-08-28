import base64
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# 1. 扩充开源节点源
SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/pek322/v2ray-free/main/v2ray",
    "https://raw.githubusercontent.com/m2237/v2ray-free/main/v2ray"
]

# 2. 联通直连优选地区关键字（按联通体验优先级排序）
UNICOM_FAVORITE_KEYWORDS = ['HK', '香港', 'JP', '日本', 'KR', '韩国', 'SG', '新加坡', 'US', '美国']

# 3. 常见无效/局域网/黑洞 IP 拦截列表
BLOCKED_IPS = {'127.0.0.1', '0.0.0.0', 'localhost', '10.0.0.0', '172.16.0.0', '192.168.0.0'}

def fetch_raw_nodes(url):
    """抓取源节点并解码"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore').strip()
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)
            try:
                decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                return decoded.splitlines()
            except Exception:
                return content.splitlines()
    except Exception as e:
        print(f"抓取源失败 [{url}]: {e}")
        return []

def parse_node_info(node_str):
    """解析节点提取 IP/域名、端口以及节点名称"""
    host, port, name = None, None, ""
    try:
        if node_str.startswith("vmess://"):
            b64_data = node_str[8:]
            missing_padding = len(b64_data) % 4
            if missing_padding:
                b64_data += '=' * (4 - missing_padding)
            info = json.loads(base64.b64decode(b64_data).decode('utf-8', errors='ignore'))
            host = info.get('add')
            port = int(info.get('port', 443))
            name = info.get('ps', '')
        elif node_str.startswith(("vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
            # 正则匹配 host:port 和 #ps 标签
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
    """校验连通性与响应质量，剔除假节点与黑洞地址"""
    host, port, name = parse_node_info(node_str)
    
    # 规则 1：无有效 host/port，或匹配到本地黑洞 IP 直接过滤
    if not host or not port or host in BLOCKED_IPS:
        return None

    try:
        # 规则 2：使用极短超时（1.8秒）压测建连速度，过滤延迟极高的垃圾节点
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.8)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            # 规则 3：给节点按联通偏好打权重排序分
            score = 0
            # 协议加分（Hysteria2/TUIC/VLESS 在联通网络下抗封锁能力强）
            if node_str.startswith(("hysteria2://", "hy2://", "tuic://", "vless://")):
                score += 20
            
            # 地区加分
            for kw in UNICOM_FAVORITE_KEYWORDS:
                if kw.lower() in name.lower() or kw.lower() in host.lower():
                    score += 50
                    break
                    
            return (score, node_str)
    except Exception:
        pass
    return None

def main():
    raw_nodes = []
    print("开始抓取多源节点...")
    for src in SOURCES:
        nodes = fetch_raw_nodes(src)
        raw_nodes.extend(nodes)

    # 去重
    unique_nodes = list(set([n.strip() for n in raw_nodes if n.strip()]))
    print(f"共抓取到 {len(unique_nodes)} 个待检测节点")

    # 多线程测试与优选
    print("正在进行联通线路匹配、防假节点过滤与质量打分...")
    scored_nodes = []
    with ThreadPoolExecutor(max_workers=40) as executor:
        results = executor.map(check_node_quality, unique_nodes)
        for res in results:
            if res:
                scored_nodes.append(res)

    # 按质量打分从高到低排序（联通优选地区 + 高效协议排在最前面）
    scored_nodes.sort(key=lambda x: x[0], reverse=True)
    valid_nodes = [item[1] for item in scored_nodes]

    print(f"筛选完成！保留高质量节点: {len(valid_nodes)} 个")

    # 打包为标准 Base64 订阅输出
    sub_content = "\n".join(valid_nodes)
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open("nekoray_sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("订阅文件 nekoray_sub.txt 更新成功！")

if __name__ == "__main__":
    main()
