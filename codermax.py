#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codermax - Gateway UDP (modulador/encoder) -> HTTP MPEG-TS / HLS (m3u8) / M3U

* Captura os streams UDP (multicast ou unicast) de uma placa de rede local
  em modo PASSIVO (AF_PACKET + filtro BPF): nao ocupa portas UDP, portanto
  nao conflita com o Flussonic nem com outros softwares que recebam os
  mesmos streams.
* Entrega cada canal como:
    - MPEG-TS direto via HTTP   ->  http://HOST:30024/TOKEN/canal.ts
    - HLS                       ->  http://HOST:30024/TOKEN/canal/index.m3u8
    - Lista M3U                 ->  http://HOST:30024/TOKEN/playlist.m3u
* Interface web em  http://HOST:30024/

Dependencias: Python 3.8+ (somente biblioteca padrao) e ffmpeg/ffprobe.
Precisa rodar como root (ou com CAP_NET_RAW) para a captura passiva.
"""

import collections
import ctypes
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.3.0"
APP = "Codermax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
DATA_DIR = os.environ.get("CODERMAX_DATA", os.path.join(BASE_DIR, "data"))
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
HLS_ROOT = os.environ.get(
    "CODERMAX_HLS",
    "/dev/shm/codermax-hls" if os.path.isdir("/dev/shm") else os.path.join(DATA_DIR, "hls"),
)
FFMPEG = shutil.which("ffmpeg") or "ffmpeg"
FFPROBE = shutil.which("ffprobe") or "ffprobe"

START_TIME = time.time()

# --------------------------------------------------------------------------
# Logs (console + memoria para a interface)
# --------------------------------------------------------------------------
LOG_RING = collections.deque(maxlen=400)


class RingHandler(logging.Handler):
    def emit(self, record):
        try:
            LOG_RING.append({
                "t": record.created,
                "level": record.levelname,
                "msg": record.getMessage(),
            })
        except Exception:
            pass


log = logging.getLogger("codermax")
log.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_h)
log.addHandler(RingHandler())

# --------------------------------------------------------------------------
# Utilitarios
# --------------------------------------------------------------------------


def slugify(text):
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text or "canal"


def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()
    return "pbkdf2$%s$%s" % (salt, dk)


def check_password(pw, stored):
    try:
        _, salt, _dk = stored.split("$")
        return hmac.compare_digest(hash_password(pw, salt), stored)
    except Exception:
        return False


def is_multicast(ip):
    try:
        return ipaddress.IPv4Address(ip).is_multicast
    except Exception:
        return False


def parse_group_spec(spec, limit=1024):
    """'239.1.1.1-239.1.1.50, 239.2.0.0/28, 239.9.9.9' -> lista de IPs multicast."""
    out = []
    for part in re.split(r"[,\s;]+", (spec or "").strip()):
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.IPv4Network(part, strict=False)
                ips = list(net.hosts()) if net.num_addresses > 2 else list(net)
            elif "-" in part:
                a, b = part.split("-", 1)
                a = ipaddress.IPv4Address(a.strip())
                b = b.strip()
                if "." not in b:  # 239.1.1.1-50
                    b = ".".join(str(a).split(".")[:3] + [b])
                b = ipaddress.IPv4Address(b)
                ips = [ipaddress.IPv4Address(i) for i in range(int(a), int(b) + 1)]
            else:
                ips = [ipaddress.IPv4Address(part)]
        except ValueError:
            raise ValueError("Faixa invalida: %s" % part)
        for ip in ips:
            if ip.is_multicast:
                out.append(str(ip))
            if len(out) >= limit:
                return out
    return out


def fmt_bitrate(bps):
    if bps >= 1e6:
        return "%.2f Mbps" % (bps / 1e6)
    if bps >= 1e3:
        return "%.0f kbps" % (bps / 1e3)
    return "%d bps" % bps


# --------------------------------------------------------------------------
# Configuracao
# --------------------------------------------------------------------------

DEFAULTS = {
    "port": 30024,
    "bind": "0.0.0.0",
    "public_url": "",          # ex: http://200.200.200.200:30024  (vazio = automatico)
    "admin_user": "nicolas",
    "admin_pass_hash": "",
    "stream_token": "",
    "default_format": "hls",   # hls | ts
    "hls_time": 4,
    "hls_list_size": 6,
    "hls_idle_timeout": 60,
    "source_idle_timeout": 20,
    "transcode_bitrate": "3000k",
    "channels": [],
}


class Config:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = {}
        self.load()

    def load(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        data = {}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        merged = dict(DEFAULTS)
        merged.update(data)
        # usuario/senha via variaveis (usadas pelo instalador) ou senha aleatoria
        env_user, env_pass = os.environ.get("CODERMAX_SET_USER"), os.environ.get("CODERMAX_SET_PASS")
        if env_user:
            merged["admin_user"] = env_user
        if env_pass:
            merged["admin_pass_hash"] = hash_password(env_pass)
        if not merged.get("admin_pass_hash"):
            pw = secrets.token_urlsafe(9)
            merged["admin_pass_hash"] = hash_password(pw)
            log.warning("Senha inicial gerada: %s  (usuario: %s) - troque no painel", pw, merged["admin_user"])
        if not merged.get("stream_token"):
            merged["stream_token"] = secrets.token_hex(8)
        if os.environ.get("CODERMAX_PORT"):
            merged["port"] = int(os.environ["CODERMAX_PORT"])
        self.data = merged
        self.save()

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)

    def get(self, k, default=None):
        with self.lock:
            return self.data.get(k, default)

    def set(self, **kw):
        with self.lock:
            self.data.update(kw)
            self.save()

    # canais -------------------------------------------------------------
    def channels(self):
        with self.lock:
            return [dict(c) for c in self.data["channels"]]

    def channel(self, key):
        with self.lock:
            for c in self.data["channels"]:
                if c["id"] == key or c["slug"] == key:
                    return dict(c)
        return None

    def unique_slug(self, base, ignore_id=None):
        base = slugify(base)
        slugs = {c["slug"] for c in self.data["channels"] if c["id"] != ignore_id}
        slug, n = base, 2
        while slug in slugs or slug in ("api", "playlist", "live"):
            slug = "%s-%d" % (base, n)
            n += 1
        return slug

    def upsert_channel(self, ch):
        with self.lock:
            for i, c in enumerate(self.data["channels"]):
                if c["id"] == ch["id"]:
                    self.data["channels"][i] = ch
                    break
            else:
                self.data["channels"].append(ch)
            self.save()

    def delete_channel(self, cid):
        with self.lock:
            self.data["channels"] = [c for c in self.data["channels"] if c["id"] != cid]
            self.save()


# --------------------------------------------------------------------------
# Interfaces de rede
# --------------------------------------------------------------------------

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B


def _ioctl_ipv4(name, req):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = fcntl.ioctl(s.fileno(), req, struct.pack("256s", name[:15].encode()))
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        s.close()


def default_route_ifaces():
    res = set()
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) > 7 and p[1] == "00000000" and p[7] == "00000000":
                    res.add(p[0])
    except OSError:
        pass
    return res


def _sysread(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def iface_ipv4(name):
    """Lista de 'ip/prefixo' da interface."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", name],
                             capture_output=True, text=True, timeout=4).stdout
        j = json.loads(out or "[]")
        res = []
        for it in j:
            for a in it.get("addr_info", []):
                if a.get("family") == "inet":
                    res.append("%s/%s" % (a["local"], a.get("prefixlen", 32)))
        return res
    except Exception:
        ip = _ioctl_ipv4(name, SIOCGIFADDR)
        if not ip:
            return []
        mask = _ioctl_ipv4(name, SIOCGIFNETMASK) or "255.255.255.255"
        pfx = ipaddress.IPv4Network("0.0.0.0/%s" % mask).prefixlen
        return ["%s/%d" % (ip, pfx)]


def list_interfaces():
    defaults = default_route_ifaces()
    out = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        names = [n for _, n in socket.if_nameindex()]
    for name in names:
        base = "/sys/class/net/%s" % name
        virtual = os.path.exists("/sys/devices/virtual/net/%s" % name)
        if name.startswith(("veth", "docker", "br-", "virbr", "ifb")) and virtual:
            continue
        rx = _sysread(base + "/statistics/rx_bytes", "0")
        speed = _sysread(base + "/speed")
        try:
            speed = int(speed) if speed and int(speed) > 0 else None
        except ValueError:
            speed = None
        role = "local"
        if name == "lo":
            role = "loopback"
        elif name in defaults:
            role = "internet"
        out.append({
            "name": name,
            "ipv4": iface_ipv4(name),
            "mac": _sysread(base + "/address", ""),
            "state": (_sysread(base + "/operstate", "unknown") or "unknown").lower(),
            "rx_bytes": int(rx or 0),
            "speed": speed,
            "virtual": virtual,
            "role": role,
        })
    order = {"local": 0, "internet": 1, "loopback": 2}
    out.sort(key=lambda i: (order.get(i["role"], 3), i["virtual"], i["name"]))
    return out


# --------------------------------------------------------------------------
# Captura passiva (AF_PACKET + BPF)
# --------------------------------------------------------------------------

ETH_P_IP = 0x0800
SO_ATTACH_FILTER = 26
SO_RCVBUFFORCE = 33
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4


def _bpf(dst_ip=None, dst_port=None):
    """Filtro BPF sobre o cabecalho IP (socket AF_PACKET/SOCK_DGRAM)."""
    ACCEPT, REJECT = "ACCEPT", "REJECT"
    prog = [
        (0x30, None, REJECT, 9),        # ldb [9]   protocolo
        (0x15, None, REJECT, 17),       # jeq #17 (UDP)
        (0x28, None, None, 6),          # ldh [6]   flags/frag
        (0x45, REJECT, None, 0x1FFF),   # jset #0x1fff -> fragmento: rejeita
    ]
    if dst_ip:
        prog += [
            (0x20, None, None, 16),     # ld [16]   IP destino
            (0x15, None, REJECT, struct.unpack("!I", socket.inet_aton(dst_ip))[0]),
        ]
    if dst_port:
        prog += [
            (0xB1, None, None, 0),      # ldxb 4*([0]&0xf)
            (0x48, None, None, 2),      # ldh [x+2] porta destino
            (0x15, None, REJECT, int(dst_port)),
        ]
    prog += [(0x06, None, None, 0x40000), (0x06, None, None, 0)]  # ACCEPT, REJECT
    idx = {ACCEPT: len(prog) - 2, REJECT: len(prog) - 1}
    raw = b""
    for i, (code, jt, jf, k) in enumerate(prog):
        jt_off = idx[jt] - i - 1 if jt else 0
        jf_off = idx[jf] - i - 1 if jf else 0
        raw += struct.pack("HBBI", code, jt_off, jf_off, k & 0xFFFFFFFF)
    return raw, len(prog)


def open_packet_socket(iface, dst_ip=None, dst_port=None, promisc=False):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    code, n = _bpf(dst_ip, dst_port)
    buf = ctypes.create_string_buffer(code)
    fprog = struct.pack("HL", n, ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    del buf  # o kernel copia o filtro no setsockopt
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 16 * 1024 * 1024)
    except OSError:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.bind((iface, ETH_P_IP))
    if promisc:
        mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b"")
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    return s


class MulticastJoiner:
    """Faz IGMP join nos grupos (sem receber dados - so para o switch/kernel
    encaminhar o trafego para a placa). Nao ocupa nenhuma porta conhecida."""

    def __init__(self, iface, groups):
        self.socks = []
        ifindex = socket.if_nametoindex(iface)
        s = None
        for i, g in enumerate(groups):
            if i % 20 == 0:  # net.ipv4.igmp_max_memberships (padrao 20) por socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socks.append(s)
            mreq = struct.pack("4s4si", socket.inet_aton(g), socket.inet_aton("0.0.0.0"), ifindex)
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError as e:
                log.warning("Join %s em %s falhou: %s", g, iface, e)

    def close(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.socks = []


def parse_udp(d):
    """d = pacote IPv4 (sem cabecalho de enlace). Retorna (src, dst, sport, dport, payload)."""
    if len(d) < 28 or d[9] != 17:
        return None
    ihl = (d[0] & 0x0F) * 4
    total = (d[2] << 8) | d[3]
    sport, dport = struct.unpack_from("!HH", d, ihl)
    return (socket.inet_ntoa(d[12:16]), socket.inet_ntoa(d[16:20]), sport, dport,
            d[ihl + 8:min(total, len(d))])


def extract_ts(p):
    """Retorna (bytes_ts, tipo). tipo: mpegts | rtp | udp"""
    n = len(p)
    if n >= 188 and p[0] == 0x47 and (n < 376 or p[188] == 0x47):
        return p[:n - n % 188], "mpegts"
    if n >= 200 and (p[0] >> 6) == 2:
        off = 12 + 4 * (p[0] & 0x0F)
        if p[0] & 0x10 and n >= off + 4:
            off += 4 + 4 * struct.unpack_from("!H", p, off + 2)[0]
        if n >= off + 188 and p[off] == 0x47:
            q = p[off:]
            return q[:len(q) - len(q) % 188], "rtp"
    return None, "udp"


def ffprobe_bytes(data, timeout=20):
    """Analisa um trecho de MPEG-TS e retorna programas/servicos."""
    if not data:
        return None
    try:
        r = subprocess.run(
            [FFPROBE, "-v", "error", "-analyzeduration", "5000000", "-probesize", "8000000",
             "-f", "mpegts", "-show_programs", "-show_streams", "-of", "json", "-i", "pipe:0"],
            input=data, capture_output=True, timeout=timeout)
        j = json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    except Exception as e:
        log.warning("ffprobe falhou: %s", e)
        return None

    def stream_info(s):
        d = {"type": s.get("codec_type"), "codec": s.get("codec_name"), "pid": s.get("id")}
        if s.get("codec_type") == "video":
            d["res"] = "%sx%s" % (s.get("width"), s.get("height"))
            fr = s.get("avg_frame_rate") or s.get("r_frame_rate") or ""
            try:
                a, b = fr.split("/")
                d["fps"] = round(int(a) / int(b), 2) if int(b) else None
            except Exception:
                pass
        if s.get("codec_type") == "audio":
            d["channels"] = s.get("channels")
            lang = (s.get("tags") or {}).get("language")
            if lang:
                d["lang"] = lang
        return d

    programs = []
    for p in j.get("programs", []):
        tags = p.get("tags") or {}
        programs.append({
            "program": p.get("program_id") or p.get("program_num"),
            "service_name": tags.get("service_name") or "",
            "provider": tags.get("service_provider") or "",
            "streams": [stream_info(s) for s in p.get("streams", [])],
        })
    if not programs and j.get("streams"):
        programs.append({"program": None, "service_name": "", "provider": "",
                         "streams": [stream_info(s) for s in j["streams"]]})
    return programs


# --------------------------------------------------------------------------
# Scanner de streams UDP
# --------------------------------------------------------------------------

SCAN_LOCK = threading.Lock()
SCAN_STATE = {"running": False, "progress": 0, "result": None, "error": None, "started": 0}


def run_scan(iface, duration=8, groups_spec="", promisc=False, probe=True, show_other=False):
    groups = parse_group_spec(groups_spec)
    flows = {}
    CAP = 3 * 1024 * 1024
    joiner = MulticastJoiner(iface, groups) if groups else None
    s = open_packet_socket(iface, promisc=promisc)
    s.settimeout(0.3)
    t0 = time.time()
    end = t0 + duration
    try:
        while True:
            now = time.time()
            if now >= end:
                break
            SCAN_STATE["progress"] = int(100 * (now - t0) / duration * (0.7 if probe else 1))
            try:
                d, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[2] == PACKET_OUTGOING:
                continue
            u = parse_udp(d)
            if not u:
                continue
            src, dst, sport, dport, payload = u
            key = (dst, dport)
            f = flows.get(key)
            if f is None:
                ts, kind = extract_ts(payload)
                f = flows[key] = {
                    "dst": dst, "port": dport, "sources": {}, "kind": kind,
                    "packets": 0, "bytes": 0, "first": now, "last": now,
                    "multicast": is_multicast(dst), "buf": bytearray(),
                }
            f["packets"] += 1
            f["bytes"] += len(payload)
            f["last"] = now
            f["sources"][src] = f["sources"].get(src, 0) + 1
            if f["kind"] in ("mpegts", "rtp") and len(f["buf"]) < CAP:
                ts, _ = extract_ts(payload)
                if ts:
                    f["buf"] += ts
            elif f["kind"] == "udp" and f["packets"] < 5:
                ts, kind = extract_ts(payload)
                if ts:
                    f["kind"] = kind
    finally:
        s.close()
        if joiner:
            joiner.close()

    result = []
    elapsed = max(time.time() - t0, 0.1)
    items = [f for f in flows.values() if show_other or f["kind"] != "udp"]
    items.sort(key=lambda f: (-int(f["kind"] != "udp"), f["dst"], f["port"]))
    for i, f in enumerate(items):
        if probe and f["kind"] != "udp":
            SCAN_STATE["progress"] = 70 + int(30 * i / max(len(items), 1))
            programs = ffprobe_bytes(bytes(f["buf"]))
        else:
            programs = None
        result.append({
            "dst": f["dst"], "port": f["port"], "kind": f["kind"],
            "multicast": f["multicast"],
            "source": max(f["sources"], key=f["sources"].get),
            "packets": f["packets"],
            "bitrate": int(f["bytes"] * 8 / elapsed),
            "programs": programs,
        })
    return {"iface": iface, "duration": duration, "joined": len(groups), "flows": result,
            "time": time.time()}


# --------------------------------------------------------------------------
# Hubs de distribuicao
# --------------------------------------------------------------------------


class Subscriber:
    def __init__(self, kind="client", info=""):
        # filas generosas: perda de pacote = som/imagem travando
        self.q = queue.Queue(maxsize=8000 if kind == "client" else 30000)
        self.id = secrets.token_hex(4)
        self.kind = kind
        self.info = info if isinstance(info, dict) else {"desc": info}
        self.bytes_out = 0
        self.since = time.time()
        self.dropped = 0
        self.closed = False

    def push(self, data):
        try:
            self.q.put_nowait(data)
        except queue.Full:
            self.dropped += 1
            if self.kind == "client" and self.dropped > 4000:
                self.closed = True  # cliente lento demais (internet dele nao acompanha)
            elif self.kind == "internal" and self.dropped % 500 == 1:
                log.warning("Fila interna cheia (%s): %d pacotes descartados - CPU sobrecarregada?",
                            self.info.get("desc", "?"), self.dropped)

    def read(self, timeout=5, maxbytes=128 * 1024):
        chunk = self.q.get(timeout=timeout)
        if chunk is None:
            return None
        parts, size = [chunk], len(chunk)
        while size < maxbytes:
            try:
                c = self.q.get_nowait()
            except queue.Empty:
                break
            if c is None:
                self.closed = True
                break
            parts.append(c)
            size += len(c)
        return b"".join(parts)


class Hub:
    """Base: recebe dados e distribui para N assinantes. Inicia sob demanda."""

    name = "hub"

    def __init__(self):
        self.lock = threading.RLock()
        self.subs = []
        self.running = False
        self.idle_since = time.time()
        self.bytes_in = 0
        self.last_data = 0
        self._rate_bytes = 0
        self._rate_t = time.time()
        self.bitrate = 0
        self.error = None
        self.history = collections.deque(maxlen=120)
        self.cc_errors = 0

    def subscribe(self, kind="client", info=""):
        sub = Subscriber(kind, info)
        with self.lock:
            self.subs.append(sub)
            if not self.running:
                self.running = True
                self.error = None
                self.started = time.time()
                self.start()
        return sub

    def unsubscribe(self, sub):
        with self.lock:
            if sub in self.subs:
                self.subs.remove(sub)
            if not self.subs:
                self.idle_since = time.time()
        sub.closed = True

    def publish(self, data):
        self.bytes_in += len(data)
        self.last_data = time.time()
        for s in list(self.subs):
            s.push(data)

    def stats_tick(self):
        now = time.time()
        dt = now - self._rate_t
        if dt >= 1:
            self.bitrate = int((self.bytes_in - self._rate_bytes) * 8 / dt) if self.running else 0
            self._rate_bytes = self.bytes_in
            self._rate_t = now
            self.history.append((int(now), self.bitrate))

    def count(self, kind=None):
        with self.lock:
            return sum(1 for s in self.subs if kind is None or s.kind == kind)

    def stop(self):
        with self.lock:
            self.running = False
            subs = list(self.subs)
        for s in subs:
            try:
                s.q.put_nowait(None)
            except queue.Full:
                s.closed = True

    def start(self):
        raise NotImplementedError


class UdpSource(Hub):
    """Recebe um stream UDP de uma interface.

    mode='raw'    -> captura passiva AF_PACKET (padrao, nao ocupa a porta)
    mode='socket' -> socket UDP tradicional com SO_REUSEADDR
    """

    def __init__(self, iface, ip, port, mode="raw"):
        super().__init__()
        self.iface, self.ip, self.port, self.mode = iface, ip, int(port), mode
        self.name = "udp://%s:%d@%s" % (ip, self.port, iface)
        self.kind = None
        self.thread = None
        self._cc = {}

    def check_cc(self, ts):
        """Conta erros de continuidade (perda de pacotes) do MPEG-TS."""
        cc = self._cc
        for i in range(0, len(ts) - 187, 188):
            b1, b2, b3 = ts[i + 1], ts[i + 2], ts[i + 3]
            pid = ((b1 & 0x1F) << 8) | b2
            if pid == 0x1FFF or not (b3 & 0x10):
                continue
            c = b3 & 0x0F
            last = cc.get(pid)
            if last is not None and c != ((last + 1) & 0x0F) and c != last:
                self.cc_errors += 1
            cc[pid] = c

    def start(self):
        self.thread = threading.Thread(target=self._run, name=self.name, daemon=True)
        self.thread.start()
        log.info("Captura iniciada %s (%s)", self.name, self.mode)

    def _open(self):
        joiner = None
        if is_multicast(self.ip):
            joiner = MulticastJoiner(self.iface, [self.ip])
        if self.mode == "socket":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 8 * 1024 * 1024)
            except OSError:
                pass
            s.bind((self.ip if is_multicast(self.ip) else "", self.port))
            if joiner:
                joiner.close()
                mreq = struct.pack("4s4si", socket.inet_aton(self.ip), socket.inet_aton("0.0.0.0"),
                                   socket.if_nametoindex(self.iface))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                joiner = None
        else:
            s = open_packet_socket(self.iface, self.ip, self.port)
        s.settimeout(1.0)
        return s, joiner

    def _run(self):
        backoff = 1
        while self.running:
            try:
                s, joiner = self._open()
            except Exception as e:
                self.error = "Falha ao abrir captura: %s" % e
                log.error("%s: %s", self.name, self.error)
                time.sleep(min(backoff, 10))
                backoff *= 2
                continue
            backoff = 1
            raw = self.mode != "socket"
            try:
                while self.running:
                    try:
                        if raw:
                            d, addr = s.recvfrom(65535)
                            if addr[2] == PACKET_OUTGOING:
                                continue
                            u = parse_udp(d)
                            if not u or u[1] != self.ip or u[3] != self.port:
                                continue
                            payload = u[4]
                        else:
                            payload = s.recv(65535)
                    except socket.timeout:
                        self.stats_tick()
                        continue
                    ts, kind = extract_ts(payload)
                    if ts:
                        self.kind = kind
                        self.check_cc(ts)
                        self.publish(ts)
                    self.stats_tick()
            except Exception as e:
                self.error = str(e)
                log.error("%s: %s", self.name, e)
                time.sleep(1)
            finally:
                try:
                    s.close()
                except OSError:
                    pass
                if joiner:
                    joiner.close()
        self.bitrate = 0
        log.info("Captura parada %s", self.name)


class FFmpegPipe(Hub):
    """ffmpeg alimentado por um hub (stdin). Saida em stdout vira um novo hub
    (ex.: filtro de programa MPTS) ou arquivos (HLS)."""

    def __init__(self, name, upstream, args, stdout_hub=True, workdir=None):
        super().__init__()
        self.name = name
        self.upstream = upstream
        self.args = args
        self.stdout_hub = stdout_hub
        self.workdir = workdir
        self.proc = None
        self.up_sub = None
        self.stderr_tail = collections.deque(maxlen=20)
        self.restarts = 0

    def start(self):
        threading.Thread(target=self._run, name=self.name, daemon=True).start()

    def _prepare(self):
        pass

    def _run(self):
        self.up_sub = self.upstream.subscribe(kind="internal", info=self.name)
        try:
            while self.running:
                self._prepare()
                cmd = [FFMPEG, "-hide_banner", "-nostdin", "-loglevel", "warning"] + self.args
                try:
                    self.proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE if self.stdout_hub else subprocess.DEVNULL,
                        stderr=subprocess.PIPE, cwd=self.workdir)
                except OSError as e:
                    self.error = "ffmpeg nao encontrado: %s" % e
                    log.error(self.error)
                    time.sleep(5)
                    continue
                log.info("ffmpeg iniciado: %s", self.name)
                threading.Thread(target=self._stderr, args=(self.proc,), daemon=True).start()
                if self.stdout_hub:
                    threading.Thread(target=self._stdout, args=(self.proc,), daemon=True).start()
                self._feed(self.proc)
                self._kill()
                if self.running:
                    self.restarts += 1
                    self.error = "ffmpeg reiniciado: " + " | ".join(list(self.stderr_tail)[-3:])
                    log.warning("%s: ffmpeg encerrou, reiniciando (%s)", self.name,
                                " | ".join(list(self.stderr_tail)[-2:]))
                    time.sleep(2)
        finally:
            self.upstream.unsubscribe(self.up_sub)
            self._kill()
            self.bitrate = 0
            log.info("ffmpeg parado: %s", self.name)

    def _feed(self, proc):
        while self.running and proc.poll() is None:
            try:
                data = self.up_sub.read(timeout=2)
            except queue.Empty:
                self.stats_tick()
                continue
            if data is None:
                if not self.upstream.running:
                    break
                continue
            try:
                proc.stdin.write(data)
            except (BrokenPipeError, OSError, ValueError):
                break
            if not self.stdout_hub:
                self.bytes_in += len(data)
                self.last_data = time.time()
            self.stats_tick()

    def _stdout(self, proc):
        while True:
            try:
                d = proc.stdout.read1(65536) if hasattr(proc.stdout, "read1") else proc.stdout.read(65536)
            except (OSError, ValueError):
                break
            if not d:
                break
            self.publish(d)

    def _stderr(self, proc):
        for line in iter(proc.stderr.readline, b""):
            line = line.decode("utf-8", "replace").strip()
            if line:
                self.stderr_tail.append(line)

    def _kill(self):
        p = self.proc
        if not p:
            return
        try:
            p.stdin.close()
        except Exception:
            pass
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        self.proc = None


AUDIO_AAC = ["-c:a", "aac", "-b:a", "128k", "-ac", "2", "-ar", "48000",
             "-af", "aresample=async=1000"]


def audio_map(ch, prefix="0"):
    """Mapeia a faixa de audio escolhida (-1 = todas)."""
    tr = int(ch.get("audio_track", 0) or 0)
    return ["-map", "%s:a?" % prefix] if tr < 0 else ["-map", "%s:a:%d?" % (prefix, tr)]


class HlsWorker(FFmpegPipe):
    def __init__(self, ch, upstream, cfg):
        self.dir = os.path.join(HLS_ROOT, ch["id"])
        self.last_access = time.time()
        self.viewers = {}  # ip -> info
        args = ["-fflags", "+genpts+discardcorrupt", "-err_detect", "ignore_err",
                "-analyzeduration", "2000000", "-probesize", "3000000",
                "-thread_queue_size", "4096", "-f", "mpegts", "-i", "pipe:0",
                "-map", "0:v:0?"]
        aac_upstream = ch.get("audio_mode", "aac") != "copy"
        # com AAC o hub do canal ja entrega 1 faixa pronta; o HLS so copia
        args += ["-map", "0:a?"] if aac_upstream else audio_map(ch)
        if ch.get("transcode"):
            args += ["-c:v", "libx264", "-preset", "veryfast", "-profile:v", "main",
                     "-vf", "yadif=0:-1:1,scale=-2:'min(ih,1080)'",
                     "-b:v", cfg.get("transcode_bitrate", "3000k"),
                     "-maxrate", cfg.get("transcode_bitrate", "3000k"),
                     "-bufsize", "6M", "-g", "50", "-sc_threshold", "0"] + AUDIO_AAC
        else:
            args += ["-c:v", "copy"]
            args += ["-c:a", "copy"]
        args += ["-max_muxing_queue_size", "4096"]
        args += ["-f", "hls", "-hls_time", str(cfg.get("hls_time", 4)),
                 "-hls_list_size", str(cfg.get("hls_list_size", 6)),
                 "-hls_flags", "delete_segments+omit_endlist+temp_file+independent_segments",
                 "-hls_delete_threshold", "3",
                 "-hls_segment_filename", os.path.join(self.dir, "seg_%06d.ts"),
                 os.path.join(self.dir, "index.m3u8")]
        super().__init__("hls:" + ch["slug"], upstream, args, stdout_hub=False)

    def _prepare(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, exist_ok=True)

    def touch(self, ip=None, channel=None, nbytes=0, ua=""):
        self.last_access = time.time()
        if ip:
            v = self.viewers.get(ip)
            if not v or time.time() - v["last"] > 30:
                v = self.viewers[ip] = {"since": time.time(), "bytes": 0, "channel": channel, "ua": ua}
            v["last"] = time.time()
            v["bytes"] += nbytes
            if len(self.viewers) > 500:
                for k in [k for k, x in self.viewers.items() if time.time() - x["last"] > 30]:
                    self.viewers.pop(k, None)

    def stop(self):
        super().stop()

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# --------------------------------------------------------------------------
# Runtime: liga canais, fontes e saidas
# --------------------------------------------------------------------------


class Runtime:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.sources = {}    # (iface, ip, port, mode) -> UdpSource
        self.filters = {}    # chid -> (assinatura, FFmpegPipe)
        self.hls = {}        # chid -> (assinatura, HlsWorker)
        self.keep = {}       # chid -> (hub, sub) mantem canal "sempre ativo"
        threading.Thread(target=self._reaper, name="reaper", daemon=True).start()
        self.apply_always_on()

    def source_for(self, ch):
        key = (ch["iface"], ch["udp_ip"], int(ch["udp_port"]), ch.get("capture", "raw"))
        with self.lock:
            src = self.sources.get(key)
            if src is None:
                src = self.sources[key] = UdpSource(*key)
            return src

    def ts_hub(self, ch):
        src = self.source_for(ch)
        prog = ch.get("program")
        fix = ch.get("audio_mode", "aac") != "copy"   # padrao: AAC em todos os links
        if prog in (None, "", 0) and not fix:
            return src
        sig = (src.name, prog, fix, ch.get("audio_track", 0))
        with self.lock:
            cur = self.filters.get(ch["id"])
            if cur and cur[0] == sig:
                return cur[1]
            if cur:
                cur[1].stop()
            args = ["-fflags", "+genpts+discardcorrupt+nobuffer", "-analyzeduration", "1000000",
                    "-probesize", "1500000", "-thread_queue_size", "4096",
                    "-f", "mpegts", "-i", "pipe:0"]
            pfx = "0:p:%d" % int(prog) if prog not in (None, "", 0) else "0"
            if fix:
                args += ["-map", pfx + ":v:0?"] + audio_map(ch, pfx) + ["-c:v", "copy"] + AUDIO_AAC
            else:
                args += ["-map", pfx + "?", "-c", "copy"]
            args += ["-max_muxing_queue_size", "4096", "-flush_packets", "1",
                    "-muxdelay", "0", "-muxpreload", "0",
                    "-f", "mpegts", "-mpegts_flags", "+resend_headers",
                    "-metadata", "service_name=%s" % ch["name"], "pipe:1"]
            hub = FFmpegPipe("%s:%s" % ("prog%s" % prog if prog else "audiofix", ch["slug"]), src, args)
            self.filters[ch["id"]] = (sig, hub)
            return hub

    def hls_for(self, ch):
        hub = self.ts_hub(ch)
        sig = (id(hub), bool(ch.get("transcode")), ch.get("audio_mode", "aac"),
               ch.get("audio_track", 0), self.cfg.get("hls_time"),
               self.cfg.get("hls_list_size"), self.cfg.get("transcode_bitrate"))
        with self.lock:
            cur = self.hls.get(ch["id"])
            if cur and cur[0] == sig:
                w = cur[1]
            else:
                if cur:
                    cur[1].stop()
                w = HlsWorker(ch, hub, self.cfg)
                self.hls[ch["id"]] = (sig, w)
            w.touch()
            if not w.running:
                with w.lock:
                    w.running = True
                    w.error = None
                    w.start()
            return w

    def reset_channel(self, cid):
        with self.lock:
            k = self.keep.pop(cid, None)
            if k:
                k[0].unsubscribe(k[1])
            h = self.hls.pop(cid, None)
            if h:
                h[1].stop()
            f = self.filters.pop(cid, None)
            if f:
                f[1].stop()
        self.apply_always_on()

    def apply_always_on(self):
        for ch in self.cfg.channels():
            if ch.get("enabled", True) and ch.get("always_on"):
                with self.lock:
                    if ch["id"] in self.keep:
                        continue
                    hub = self.ts_hub(ch)
                    self.keep[ch["id"]] = (hub, hub.subscribe(kind="keep", info="sempre ativo"))
                    threading.Thread(target=self._drain, args=(self.keep[ch["id"]][1],),
                                     daemon=True).start()
                if ch.get("hls_always"):
                    self.hls_for(ch)

    @staticmethod
    def _drain(sub):
        while not sub.closed:
            try:
                if sub.read(timeout=2) is None:
                    pass
            except queue.Empty:
                pass

    def _reaper(self):
        while True:
            time.sleep(3)
            try:
                hls_idle = int(self.cfg.get("hls_idle_timeout", 60))
                src_idle = int(self.cfg.get("source_idle_timeout", 20))
                chans = {c["id"]: c for c in self.cfg.channels()}
                with self.lock:
                    for cid, (_, w) in list(self.hls.items()):
                        ch = chans.get(cid)
                        keep = ch and ch.get("always_on") and ch.get("hls_always")
                        if w.running and not keep and time.time() - w.last_access > hls_idle:
                            log.info("HLS ocioso, parando %s", w.name)
                            w.stop()
                    hubs = [f[1] for f in self.filters.values()] + list(self.sources.values())
                for hub in hubs:
                    hub.stats_tick()
                    if hub.running and hub.count() == 0 and time.time() - hub.idle_since > src_idle:
                        hub.stop()
                for _, w in list(self.hls.values()):
                    w.stats_tick()
            except Exception as e:
                log.error("reaper: %s", e)

    def all_hubs(self):
        with self.lock:
            return list(self.sources.values()) + [f[1] for f in self.filters.values()]

    def clients(self):
        out = []
        for hub in self.all_hubs():
            with hub.lock:
                subs = list(hub.subs)
            for s in subs:
                if s.kind == "client":
                    d = dict(s.info)
                    d.update(id=s.id, since=s.since, bytes=s.bytes_out,
                             rate=int(s.bytes_out * 8 / max(time.time() - s.since, 1)))
                    out.append(d)
        for cid, (_, w) in list(self.hls.items()):
            for ip, info in list(w.viewers.items()):
                if time.time() - info["last"] < 30:
                    out.append({"id": "hls-%s-%s" % (cid, ip), "ip": ip, "channel": info["channel"],
                                "proto": "HLS", "since": info["since"], "bytes": info["bytes"],
                                "rate": int(info["bytes"] * 8 / max(time.time() - info["since"], 1)),
                                "ua": info.get("ua", "")})
        return sorted(out, key=lambda c: c["since"])

    def kick(self, sid):
        for hub in self.all_hubs():
            with hub.lock:
                subs = list(hub.subs)
            for s in subs:
                if s.id == sid:
                    s.closed = True
                    try:
                        s.q.put_nowait(None)
                    except queue.Full:
                        pass
                    return True
        return False

    def channel_clients(self, ch):
        n = 0
        for hub in self.all_hubs():
            with hub.lock:
                n += sum(1 for s in hub.subs if s.kind == "client" and s.info.get("cid") == ch["id"])
        h = self.hls.get(ch["id"])
        if h:
            n += sum(1 for v in h[1].viewers.values() if time.time() - v["last"] < 30)
        return n

    THUMBS = {}

    def thumbnail(self, ch, max_age=20):
        cached = self.THUMBS.get(ch["id"])
        if cached and time.time() - cached[0] < max_age:
            return cached[1]
        hub = self.ts_hub(ch)
        sub = hub.subscribe(kind="internal", info="miniatura")
        buf, t_end = bytearray(), time.time() + 6
        try:
            while time.time() < t_end and len(buf) < 3 * 1024 * 1024:
                try:
                    d = sub.read(timeout=1)
                except queue.Empty:
                    continue
                if d is None:
                    break
                buf += d
                if len(buf) > 600 * 1024 and time.time() > t_end - 4:
                    break
        finally:
            hub.unsubscribe(sub)
        img = None
        if buf:
            try:
                r = subprocess.run([FFMPEG, "-hide_banner", "-loglevel", "error", "-f", "mpegts",
                                    "-i", "pipe:0", "-map", "0:v:0", "-vf", "scale=480:-2",
                                    "-frames:v", "1", "-q:v", "5", "-f", "image2", "-c:v", "mjpeg",
                                    "pipe:1"], input=bytes(buf), capture_output=True, timeout=15)
                img = r.stdout or None
            except Exception as e:
                log.warning("Miniatura falhou (%s): %s", ch["name"], e)
        self.THUMBS[ch["id"]] = (time.time(), img)
        return img

    def channel_status(self, ch):
        src = self.sources.get((ch["iface"], ch["udp_ip"], int(ch["udp_port"]), ch.get("capture", "raw")))
        flt = self.filters.get(ch["id"])
        hls = self.hls.get(ch["id"])
        st = {"state": "parado", "bitrate": 0, "clients": 0, "hls": False, "error": None,
              "last_data": 0, "kind": None}
        if src:
            st["bitrate"] = src.bitrate
            st["last_data"] = src.last_data
            st["kind"] = src.kind
            st["error"] = src.error
            if src.running:
                age = time.time() - src.last_data if src.last_data else 1e9
                st["state"] = "ativo" if age < 3 else "sem_sinal"
            st["clients"] = src.count("client")
        if flt:
            st["clients"] += flt[1].count("client")
            st["error"] = st["error"] or flt[1].error
        if hls and hls[1].running:
            st["hls"] = True
            st["hls_error"] = hls[1].error
        st["clients"] = self.channel_clients(ch)
        st["cc_errors"] = src.cc_errors if src else 0
        st["history"] = [b for _, b in list(src.history)[-60:]] if src else []
        st["uptime"] = (time.time() - src.started) if src and src.running and getattr(src, "started", 0) else 0
        return st


# --------------------------------------------------------------------------
# Monitor do servidor
# --------------------------------------------------------------------------
_CPU_PREV = [0, 0]


def system_stats():
    st = {}
    try:
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        idle, total = v[3] + v[4], sum(v)
        di, dt = idle - _CPU_PREV[0], total - _CPU_PREV[1]
        _CPU_PREV[:] = [idle, total]
        st["cpu"] = round(100 * (1 - di / dt), 1) if dt > 0 else 0
    except Exception:
        st["cpu"] = 0
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, val = line.split(":")
                mem[k] = int(val.split()[0]) * 1024
        st["mem_total"] = mem["MemTotal"]
        st["mem_used"] = mem["MemTotal"] - mem.get("MemAvailable", mem["MemFree"])
    except Exception:
        st["mem_total"] = st["mem_used"] = 0
    try:
        du = shutil.disk_usage("/")
        st["disk_total"], st["disk_used"] = du.total, du.used
    except Exception:
        st["disk_total"] = st["disk_used"] = 0
    try:
        st["load"] = os.getloadavg()
    except OSError:
        st["load"] = (0, 0, 0)
    st["cores"] = os.cpu_count()
    try:
        with open("/proc/uptime") as f:
            st["uptime"] = float(f.read().split()[0])
    except Exception:
        st["uptime"] = 0
    return st


# --------------------------------------------------------------------------
# Deteccao do Flussonic / portas em uso
# --------------------------------------------------------------------------


def _listening_ports():
    """Le /proc/net/tcp* e retorna {inode: porta} das portas em LISTEN."""
    res = {}
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    p = line.split()
                    if p[3] == "0A":
                        res[p[9]] = int(p[1].rsplit(":", 1)[1], 16)
        except OSError:
            pass
    return res


def detect_flussonic():
    inodes = _listening_ports()
    pids, ports = [], set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "flussonic" not in cmd.lower() or "codermax" in cmd.lower():
            continue
        pids.append(int(pid))
        try:
            for fd in os.listdir("/proc/%s/fd" % pid):
                try:
                    link = os.readlink("/proc/%s/fd/%s" % (pid, fd))
                except OSError:
                    continue
                if link.startswith("socket:["):
                    ino = link[8:-1]
                    if ino in inodes:
                        ports.add(inodes[ino])
        except OSError:
            pass
    return {"detected": bool(pids), "pids": pids[:5], "ports": sorted(ports)}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

SESSIONS = {}
SESSION_TTL = 12 * 3600
CFG = None
RT = None


def new_channel_from(data, existing=None):
    ch = dict(existing or {})
    name = (data.get("name") or ch.get("name") or "").strip()
    if not name:
        raise ValueError("Informe o nome do canal")
    ip = (data.get("udp_ip") or ch.get("udp_ip") or "").strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError("IP UDP invalido")
    port = int(data.get("udp_port") or ch.get("udp_port") or 0)
    if not 1 <= port <= 65535:
        raise ValueError("Porta UDP invalida")
    iface = (data.get("iface") or ch.get("iface") or "").strip()
    if not iface or not os.path.exists("/sys/class/net/%s" % iface):
        raise ValueError("Interface de rede invalida")
    prog = data.get("program", ch.get("program"))
    prog = int(prog) if prog not in (None, "", "0", 0) else None
    capture = data.get("capture", ch.get("capture", "raw"))
    if capture not in ("raw", "socket"):
        capture = "raw"
    ch.update({
        "id": ch.get("id") or secrets.token_hex(4),
        "name": name,
        "group": (data.get("group", ch.get("group", "")) or "").strip(),
        "logo": (data.get("logo", ch.get("logo", "")) or "").strip(),
        "udp_ip": ip,
        "udp_port": port,
        "iface": iface,
        "program": prog,
        "capture": capture,
        "transcode": bool(data.get("transcode", ch.get("transcode", False))),
        "always_on": bool(data.get("always_on", ch.get("always_on", False))),
        "hls_always": bool(data.get("hls_always", ch.get("hls_always", False))),
        "enabled": bool(data.get("enabled", ch.get("enabled", True))),
        "max_clients": max(0, int(data.get("max_clients", ch.get("max_clients", 0)) or 0)),
        "audio_mode": data.get("audio_mode", ch.get("audio_mode", "aac")) if
        data.get("audio_mode", ch.get("audio_mode", "aac")) in ("aac", "copy") else "aac",
        "audio_track": max(-1, min(int(data.get("audio_track", ch.get("audio_track", 0)) or 0), 15)),

        "notes": (data.get("notes", ch.get("notes", "")) or "").strip()[:300],
        "created": ch.get("created") or time.time(),
    })
    wanted = (data.get("slug") or "").strip() or ch.get("slug") or name
    ch["slug"] = CFG.unique_slug(wanted, ignore_id=ch["id"])
    return ch


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "%s/%s" % (APP, VERSION)

    def log_message(self, fmt, *args):  # silencia o log padrao
        pass

    # ---------- helpers ----------
    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1024 * 1024:
            raise ValueError("Requisicao grande demais")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _session(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"cmx_session=([A-Za-z0-9_\-]+)", cookie)
        if not m:
            return None
        exp = SESSIONS.get(m.group(1))
        if exp and exp > time.time():
            return m.group(1)
        return None

    def _base_url(self):
        pub = (CFG.get("public_url") or "").strip().rstrip("/")
        if pub:
            if not pub.startswith("http"):
                pub = "http://" + pub
            return pub
        host = self.headers.get("Host") or "%s:%s" % (self.server.server_address[0], CFG.get("port"))
        return "http://" + host

    # ---------- roteamento ----------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _route(self, method):
        url = urlparse(self.path)
        path = url.path
        qs = parse_qs(url.query)
        try:
            if path.startswith("/api/"):
                return self._api(method, path[5:], qs)
            if method != "GET":
                return self._send(405, {"error": "metodo nao permitido"})
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[8:])
            if path == "/favicon.ico":
                return self._static("favicon.svg")
            parts = [p for p in path.split("/") if p]
            if parts and hmac.compare_digest(parts[0], CFG.get("stream_token")):
                return self._stream(parts[1:], qs)
            return self._send(404, "Nao encontrado", "text/plain; charset=utf-8")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # pragma: no cover
            log.exception("Erro em %s %s", method, path)
            try:
                self._send(500, {"error": str(e)})
            except Exception:
                pass

    def _static(self, name):
        name = os.path.normpath(name).lstrip("/")
        if name.startswith(".."):
            return self._send(404, "")
        fp = os.path.join(WEB_DIR, name)
        if not os.path.isfile(fp):
            return self._send(404, "Nao encontrado", "text/plain")
        with open(fp, "rb") as f:
            body = f.read()
        ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith(("javascript", "svg+xml")):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)

    # ---------- streams ----------
    def _stream(self, parts, qs):
        if not parts:
            return self._send(404, "")
        if parts[0] in ("playlist.m3u", "playlist.m3u8", "lista.m3u"):
            fmt = (qs.get("format") or qs.get("type") or [CFG.get("default_format", "hls")])[0]
            return self._playlist(fmt)
        if len(parts) == 1 and parts[0].endswith(".ts"):
            ch = CFG.channel(parts[0][:-3])
            if not ch or not ch.get("enabled", True):
                return self._send(404, "Canal nao encontrado", "text/plain")
            return self._serve_ts(ch)
        if len(parts) == 1 and parts[0].endswith(".m3u8"):
            ch = CFG.channel(parts[0][:-5])
            if ch:
                return self._send(302, "", "text/plain", {"Location": "%s/index.m3u8" % parts[0][:-5]})
        if len(parts) == 2:
            ch = CFG.channel(parts[0])
            if not ch or not ch.get("enabled", True):
                return self._send(404, "Canal nao encontrado", "text/plain")
            if parts[1] in ("index.m3u8", "mono.m3u8", "playlist.m3u8"):
                return self._serve_hls_index(ch)
            if parts[1] in ("mpegts", "stream.ts"):
                return self._serve_ts(ch)
            if re.fullmatch(r"seg_\d+\.ts", parts[1]):
                return self._serve_hls_segment(ch, parts[1])
        return self._send(404, "Nao encontrado", "text/plain")

    def _playlist(self, fmt):
        base = self._base_url()
        tok = CFG.get("stream_token")
        lines = ["#EXTM3U"]
        for ch in CFG.channels():
            if not ch.get("enabled", True):
                continue
            attrs = 'tvg-id="%s" tvg-name="%s"' % (ch["slug"], ch["name"].replace('"', "'"))
            if ch.get("logo"):
                attrs += ' tvg-logo="%s"' % ch["logo"]
            attrs += ' group-title="%s"' % (ch.get("group") or "Codermax").replace('"', "'")
            lines.append("#EXTINF:-1 %s,%s" % (attrs, ch["name"]))
            if fmt == "ts":
                lines.append("%s/%s/%s.ts" % (base, tok, ch["slug"]))
            else:
                lines.append("%s/%s/%s/index.m3u8" % (base, tok, ch["slug"]))
        body = "\n".join(lines) + "\n"
        self._send(200, body, "audio/x-mpegurl; charset=utf-8",
                   {"Content-Disposition": 'inline; filename="codermax.m3u"',
                    "Access-Control-Allow-Origin": "*"})

    def _serve_ts(self, ch):
        client = self.headers.get("X-Forwarded-For") or self.client_address[0]
        if ch.get("max_clients") and RT.channel_clients(ch) >= ch["max_clients"]:
            log.warning("Limite de clientes atingido em %s (%s recusado)", ch["slug"], client)
            return self._send(503, "Limite de conexoes do canal atingido", "text/plain; charset=utf-8")
        hub = RT.ts_hub(ch)
        sub = hub.subscribe(kind="client", info={
            "ip": client, "channel": ch["name"], "cid": ch["id"], "proto": "MPEG-TS",
            "ua": (self.headers.get("User-Agent") or "")[:120]})
        log.info("Cliente TS %s conectou em %s", client, ch["slug"])
        self.close_connection = True
        try:
            self.connection.settimeout(30)
            self.send_response(200)
            self.send_header("Content-Type", "video/mp2t")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command == "HEAD":
                return
            waited = 0
            while not sub.closed:
                try:
                    data = sub.read(timeout=5)
                except queue.Empty:
                    waited += 5
                    if waited >= 60:
                        break  # 1 minuto sem sinal: encerra
                    continue
                if data is None:
                    break
                waited = 0
                self.wfile.write(data)
                sub.bytes_out += len(data)
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            pass
        finally:
            hub.unsubscribe(sub)
            log.info("Cliente TS %s saiu de %s", client, ch["slug"])

    def _client_ip(self):
        return self.headers.get("X-Forwarded-For") or self.client_address[0]

    def _serve_hls_index(self, ch):
        ip = self._client_ip()
        h = RT.hls.get(ch["id"])
        if ch.get("max_clients") and RT.channel_clients(ch) >= ch["max_clients"] and \
                not (h and ip in h[1].viewers and time.time() - h[1].viewers[ip]["last"] < 30):
            return self._send(503, "Limite de conexoes do canal atingido", "text/plain; charset=utf-8")
        w = RT.hls_for(ch)
        w.touch(ip, ch["name"], 0, (self.headers.get("User-Agent") or "")[:120])
        fp = os.path.join(w.dir, "index.m3u8")
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                with open(fp, "rb") as f:
                    body = f.read()
                if b"#EXTINF" in body:
                    return self._send(200, body, "application/vnd.apple.mpegurl",
                                      {"Access-Control-Allow-Origin": "*"})
            except OSError:
                pass
            w.touch()
            time.sleep(0.4)
        return self._send(503, "Canal sem sinal ou iniciando, tente novamente",
                          "text/plain; charset=utf-8",
                          {"Retry-After": "3", "Access-Control-Allow-Origin": "*"})

    def _serve_hls_segment(self, ch, name):
        w = RT.hls_for(ch)
        fp = os.path.join(w.dir, name)
        try:
            with open(fp, "rb") as f:
                body = f.read()
        except OSError:
            return self._send(404, "Segmento expirou", "text/plain")
        w.touch(self._client_ip(), ch["name"], len(body), (self.headers.get("User-Agent") or "")[:120])
        self.send_response(200)
        self.send_header("Content-Type", "video/mp2t")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "max-age=60")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---------- API ----------
    def _api(self, method, path, qs):
        if path == "login" and method == "POST":
            d = self._json_body()
            if d.get("user") == CFG.get("admin_user") and check_password(d.get("pass", ""),
                                                                         CFG.get("admin_pass_hash")):
                sid = secrets.token_urlsafe(24)
                SESSIONS[sid] = time.time() + SESSION_TTL
                return self._send(200, {"ok": True}, headers={
                    "Set-Cookie": "cmx_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                  % (sid, SESSION_TTL)})
            time.sleep(1.5)
            log.warning("Login invalido de %s", self.client_address[0])
            return self._send(401, {"error": "Usuario ou senha incorretos"})
        sid = self._session()
        if not sid:
            return self._send(401, {"error": "nao autenticado"})
        if path == "logout":
            SESSIONS.pop(sid, None)
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "cmx_session=; Path=/; Max-Age=0"})

        if path == "status" and method == "GET":
            chans = []
            for ch in CFG.channels():
                ch["status"] = RT.channel_status(ch)
                chans.append(ch)
            try:
                load = os.getloadavg()
            except OSError:
                load = (0, 0, 0)
            return self._send(200, {
                "app": APP, "version": VERSION, "hostname": socket.gethostname(),
                "uptime": time.time() - START_TIME, "load": load,
                "ffmpeg": bool(shutil.which("ffmpeg")), "port": CFG.get("port"),
                "base_url": self._base_url(), "token": CFG.get("stream_token"),
                "default_format": CFG.get("default_format"),
                "channels": chans, "user": CFG.get("admin_user"),
                "default_pass": check_password("codermax", CFG.get("admin_pass_hash")),
            })
        if path == "system":
            return self._send(200, system_stats())
        if path == "clients" and method == "GET":
            return self._send(200, {"clients": RT.clients()})
        m = re.fullmatch(r"clients/([a-f0-9]+)", path)
        if m and method == "DELETE":
            ok = RT.kick(m.group(1))
            if ok:
                log.info("Conexao %s derrubada pelo administrador", m.group(1))
            return self._send(200 if ok else 404, {"ok": ok})
        if path == "backup" and method == "GET":
            data = {k: v for k, v in CFG.data.items() if k not in ("admin_pass_hash",)}
            data["_codermax_backup"] = VERSION
            body = json.dumps(data, indent=2, ensure_ascii=False)
            return self._send(200, body, "application/json; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="codermax-backup-%s.json"'
                                       % time.strftime("%Y%m%d-%H%M")})
        if path == "restore" and method == "POST":
            d = self._json_body()
            if "_codermax_backup" not in d or not isinstance(d.get("channels"), list):
                raise ValueError("Arquivo de backup invalido")
            for ch in CFG.channels():
                RT.reset_channel(ch["id"])
            upd = {k: d[k] for k in ("channels", "public_url", "default_format", "hls_time",
                                     "hls_list_size", "hls_idle_timeout", "source_idle_timeout",
                                     "transcode_bitrate", "stream_token") if k in d}
            CFG.set(**upd)
            RT.apply_always_on()
            log.warning("Backup restaurado (%d canais)", len(d["channels"]))
            return self._send(200, {"ok": True, "channels": len(d["channels"])})
        if path == "channels/order" and method == "POST":
            ids = self._json_body().get("ids") or []
            with CFG.lock:
                pos = {cid: i for i, cid in enumerate(ids)}
                CFG.data["channels"].sort(key=lambda c: pos.get(c["id"], 10 ** 6))
                CFG.save()
            return self._send(200, {"ok": True})
        if path == "interfaces":
            return self._send(200, {"interfaces": list_interfaces(), "time": time.time()})
        if path == "flussonic":
            return self._send(200, detect_flussonic())
        if path == "logs":
            return self._send(200, {"logs": list(LOG_RING)[-200:]})

        if path == "scan" and method == "POST":
            d = self._json_body()
            iface = d.get("iface")
            if not iface or not os.path.exists("/sys/class/net/%s" % iface):
                raise ValueError("Escolha uma interface valida")
            dur = max(2, min(int(d.get("duration") or 8), 60))
            groups = d.get("groups") or ""
            parse_group_spec(groups)  # valida antes
            if not SCAN_LOCK.acquire(blocking=False):
                return self._send(409, {"error": "Ja existe uma varredura em andamento"})

            def job():
                try:
                    SCAN_STATE.update(running=True, progress=0, result=None, error=None,
                                      started=time.time())
                    log.info("Varredura em %s por %ss (grupos: %s)", iface, dur, groups or "-")
                    res = run_scan(iface, dur, groups, bool(d.get("promisc")),
                                   bool(d.get("probe", True)), bool(d.get("show_other")))
                    SCAN_STATE["result"] = res
                    log.info("Varredura concluida: %d stream(s)", len(res["flows"]))
                except Exception as e:
                    SCAN_STATE["error"] = str(e)
                    log.error("Varredura falhou: %s", e)
                finally:
                    SCAN_STATE.update(running=False, progress=100)
                    SCAN_LOCK.release()

            threading.Thread(target=job, daemon=True).start()
            return self._send(200, {"ok": True})
        if path == "scan" and method == "GET":
            return self._send(200, SCAN_STATE)

        if path == "channels" and method == "GET":
            return self._send(200, {"channels": CFG.channels()})
        if path == "channels" and method == "POST":
            d = self._json_body()
            items = d.get("channels") if isinstance(d.get("channels"), list) else [d]
            created = []
            for item in items:
                ch = new_channel_from(item)
                CFG.upsert_channel(ch)
                created.append(ch)
                log.info("Canal criado: %s (%s:%s @%s)", ch["name"], ch["udp_ip"],
                         ch["udp_port"], ch["iface"])
            RT.apply_always_on()
            return self._send(200, {"ok": True, "channels": created})
        m = re.fullmatch(r"channels/([a-f0-9]+)(/(\w+))?", path)
        if m:
            ch = CFG.channel(m.group(1))
            if not ch:
                return self._send(404, {"error": "Canal nao encontrado"})
            action = m.group(3)
            if method == "PUT" and not action:
                new = new_channel_from(self._json_body(), ch)
                CFG.upsert_channel(new)
                RT.reset_channel(ch["id"])
                log.info("Canal atualizado: %s", new["name"])
                return self._send(200, {"ok": True, "channel": new})
            if method == "DELETE" and not action:
                CFG.delete_channel(ch["id"])
                RT.reset_channel(ch["id"])
                log.info("Canal removido: %s", ch["name"])
                return self._send(200, {"ok": True})
            if action == "thumb" and method == "GET":
                img = RT.thumbnail(ch, max_age=int((qs.get("age") or ["20"])[0]))
                if not img:
                    return self._send(404, {"error": "sem imagem"})
                return self._send(200, img, "image/jpeg")
            if action == "toggle" and method == "POST":
                ch["enabled"] = not ch.get("enabled", True)
                CFG.upsert_channel(ch)
                RT.reset_channel(ch["id"])
                return self._send(200, {"ok": True, "enabled": ch["enabled"]})
            if action == "restart" and method == "POST":
                RT.reset_channel(ch["id"])
                return self._send(200, {"ok": True})
            if action == "probe" and method == "POST":
                hub = RT.ts_hub(ch)
                sub = hub.subscribe(kind="internal", info="probe")
                buf, t_end = bytearray(), time.time() + 5
                try:
                    while time.time() < t_end and len(buf) < 4 * 1024 * 1024:
                        try:
                            d = sub.read(timeout=1)
                        except queue.Empty:
                            continue
                        if d is None:
                            break
                        buf += d
                finally:
                    hub.unsubscribe(sub)
                if not buf:
                    return self._send(200, {"ok": False, "error": "Nenhum dado recebido em 5s"})
                return self._send(200, {"ok": True, "bytes": len(buf),
                                        "bitrate": int(len(buf) * 8 / 5),
                                        "programs": ffprobe_bytes(bytes(buf))})

        if path == "settings" and method == "GET":
            keys = ["port", "public_url", "admin_user", "default_format", "hls_time",
                    "hls_list_size", "hls_idle_timeout", "source_idle_timeout",
                    "transcode_bitrate", "stream_token"]
            return self._send(200, {k: CFG.get(k) for k in keys})
        if path == "settings" and method == "PUT":
            d = self._json_body()
            upd = {}
            if "public_url" in d:
                upd["public_url"] = (d["public_url"] or "").strip()
            if d.get("default_format") in ("hls", "ts"):
                upd["default_format"] = d["default_format"]
            for k, lo, hi in (("hls_time", 1, 12), ("hls_list_size", 3, 30),
                              ("hls_idle_timeout", 10, 3600), ("source_idle_timeout", 5, 3600)):
                if k in d:
                    upd[k] = max(lo, min(int(d[k]), hi))
            if d.get("transcode_bitrate"):
                if not re.fullmatch(r"\d+[kKmM]?", str(d["transcode_bitrate"])):
                    raise ValueError("Bitrate invalido (ex.: 3000k)")
                upd["transcode_bitrate"] = str(d["transcode_bitrate"])
            if "port" in d:
                p = int(d["port"])
                if not 1 <= p <= 65535:
                    raise ValueError("Porta invalida")
                upd["port"] = p
            if d.get("admin_user"):
                upd["admin_user"] = d["admin_user"].strip()
            if d.get("new_pass"):
                if not check_password(d.get("current_pass", ""), CFG.get("admin_pass_hash")):
                    raise ValueError("Senha atual incorreta")
                if len(d["new_pass"]) < 6:
                    raise ValueError("A nova senha deve ter pelo menos 6 caracteres")
                upd["admin_pass_hash"] = hash_password(d["new_pass"])
            if d.get("regen_token"):
                upd["stream_token"] = secrets.token_hex(8)
                log.warning("Token de stream regenerado - links antigos deixam de funcionar")
            restart = "port" in upd and upd["port"] != CFG.get("port")
            CFG.set(**upd)
            return self._send(200, {"ok": True, "restart_required": restart})

        return self._send(404, {"error": "rota desconhecida"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def main():
    global CFG, RT
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(HLS_ROOT, exist_ok=True)
    CFG = Config(CONFIG_FILE)
    if os.geteuid() != 0:
        log.warning("Rodando sem root: a captura passiva (AF_PACKET) precisa de root ou CAP_NET_RAW")
    if not shutil.which("ffmpeg"):
        log.warning("ffmpeg nao encontrado: HLS e filtro de programa nao funcionarao")
    RT = Runtime(CFG)
    port, bind = int(CFG.get("port")), CFG.get("bind", "0.0.0.0")
    try:
        httpd = Server((bind, port), Handler)
    except OSError as e:
        log.error("Nao foi possivel abrir a porta %s:%s (%s). Ela ja esta em uso? "
                  "Altere 'port' em %s ou use CODERMAX_PORT.", bind, port, e, CONFIG_FILE)
        sys.exit(1)
    fl = detect_flussonic()
    if fl["detected"]:
        log.info("Flussonic detectado (portas TCP: %s) - Codermax roda isolado na porta %d",
                 ", ".join(map(str, fl["ports"])) or "?", port)
    log.info("%s %s ouvindo em http://%s:%d/  (dados: %s)", APP, VERSION, bind, port, DATA_DIR)
    log.info("Usuario do painel: %s", CFG.get("admin_user"))

    def shutdown(*_):
        log.info("Encerrando...")
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    httpd.serve_forever()
    for _, w in list(RT.hls.values()):
        w.stop()
        w.cleanup()


if __name__ == "__main__":
    main()
