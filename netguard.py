"""SSRF 防护：域名解析 + 公网 IP 校验。"""
import ipaddress, os, socket
import httpx

FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")  # 代理/沙箱常用的 fake-ip 段
RESOLVER = os.getenv("RESOLVER", "auto")  # auto | system | doh
DOH_URL = os.getenv("DOH_URL", "https://cloudflare-dns.com/dns-query")

class NXDomain(Exception): pass
class Forbidden(Exception): pass

def is_public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped: a = a.ipv4_mapped
    return a.is_global and not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)

def _system(domain):
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise NXDomain(domain)
    return sorted({i[4][0] for i in infos})

def _doh(domain):
    ips, nx = [], False
    for t in ("A", "AAAA"):
        r = httpx.get(DOH_URL, params={"name": domain, "type": t}, headers={"accept": "application/dns-json"}, timeout=6)
        j = r.json()
        if j.get("Status") == 3: nx = True
        ips += [a["data"] for a in j.get("Answer", []) if a.get("type") in (1, 28)]
    if not ips: raise NXDomain(domain)
    return ips

def resolve_safe(domain: str):
    """返回 (校验过的IP列表, 实际连接目标)。拒绝任何解析到非公网地址的域名。"""
    try: ipaddress.ip_address(domain); raise Forbidden("不允许直接输入 IP 地址")
    except ValueError: pass
    if RESOLVER == "doh":
        ips = _doh(domain); target = ips[0]
    else:
        ips = _system(domain)
        if RESOLVER == "auto" and all(ipaddress.ip_address(i) in FAKE_IP_NET for i in ips):
            # 运行在 fake-ip 代理后：用 DoH 获取真实记录做存在性和 SSRF 校验，连接仍交给代理
            ips = _doh(domain); target = domain
        else:
            target = None
    bad = [i for i in ips if not is_public(i)]
    if bad: raise Forbidden(f"域名解析到非公网地址 {', '.join(bad)}，已拒绝")
    # 直接连校验过的 IP，防 DNS rebinding
    return ips, target or next((i for i in ips if ":" not in i), ips[0])
