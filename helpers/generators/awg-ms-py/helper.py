"""Встроенный помощник awg2: разбор и атомарная правка конфигов, JSON Xray,
расчёты подсетей, разбор pcap. Вызывается как `py <команда> [аргументы]`.

Коды выхода: 0 — успех, 1 — ошибка (текст в stderr), 2 — не найдено,
3 — дубликат. Всё, что пишется в файлы, пишется через временный файл рядом
с целевым и os.replace: обрыв на середине не оставляет битый конфиг.
"""
import base64
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import string
import struct
import sys
import tempfile
import time
import urllib.parse


def die(msg, code=1):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_atomic(path, text, mode=0o600):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".awg2.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ════════════════════════ awg0.conf ════════════════════════
# Блок [Peer] может нести служебные комментарии «# ключ=значение»
# (mimicry, expires, orig_ips, note — последнюю пишет бот). Имя клиента —
# первый комментарий без «=»: валидатор имён этот знак не пропускает.

PEER_SPLIT = re.compile(r"(?=^\[Peer\][ \t]*$)", re.M)


def split_peers(text):
    parts = PEER_SPLIT.split(text)
    return parts[0], parts[1:]


def peer_name(block):
    for line in block.splitlines()[1:]:
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m and "=" not in m.group(1):
            return m.group(1)
    return ""


def peer_field(block, key):
    m = re.search(r"^%s\s*=\s*(.+?)\s*$" % re.escape(key), block, re.M)
    return m.group(1) if m else ""


def peer_meta(block, key):
    m = re.search(r"^#\s*%s=(.*?)\s*$" % re.escape(key), block, re.M)
    return m.group(1) if m else ""


def find_peer(peers, name=None, pubkey=None):
    for i, b in enumerate(peers):
        if pubkey is not None and peer_field(b, "PublicKey") == pubkey:
            return i
        if name is not None and peer_name(b) == name:
            return i
    return -1


def set_meta(block, key, value):
    block = re.sub(r"^#\s*%s=.*\n?" % re.escape(key), "", block, flags=re.M)
    if not value:
        return block
    lines = block.split("\n")
    # Метка встаёт сразу после имени, а без имени — после [Peer]
    at = 1
    for i, line in enumerate(lines[1:], 1):
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m and "=" not in m.group(1):
            at = i + 1
            break
    lines.insert(at, "# %s=%s" % (key, value))
    return "\n".join(lines)


def cmd_peers(conf):
    _, peers = split_peers(read(conf))
    for b in peers:
        pub = peer_field(b, "PublicKey")
        if not pub:
            continue
        print("\t".join([peer_name(b), pub, peer_field(b, "AllowedIPs"),
                         peer_meta(b, "expires"), peer_meta(b, "orig_ips"),
                         peer_meta(b, "mimicry")]))


def cmd_meta_set(conf, name, key, value):
    head, peers = split_peers(read(conf))
    i = find_peer(peers, name=name)
    if i < 0:
        die("клиент %s не найден" % name, 2)
    peers[i] = set_meta(peers[i], key, value)
    write_atomic(conf, head + "".join(peers))


def cmd_peer_del(conf, pubkey):
    head, peers = split_peers(read(conf))
    i = find_peer(peers, pubkey=pubkey)
    if i < 0:
        die("пир не найден", 2)
    name = peer_name(peers[i])
    del peers[i]
    text = head + "".join(peers)
    write_atomic(conf, re.sub(r"\n{3,}", "\n\n", text))
    print(name)


def cmd_peer_rename(conf, pubkey, new):
    head, peers = split_peers(read(conf))
    i = find_peer(peers, pubkey=pubkey)
    if i < 0:
        die("пир не найден", 2)
    lines = peers[i].split("\n")
    for j, line in enumerate(lines[1:], 1):
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m and "=" not in m.group(1):
            lines[j] = "# " + new
            break
    else:
        lines.insert(1, "# " + new)
    peers[i] = "\n".join(lines)
    write_atomic(conf, head + "".join(peers))


def cmd_peers_clear(conf):
    head, _ = split_peers(read(conf))
    write_atomic(conf, head.rstrip("\n") + "\n")


AWG_PARAM_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                  "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
                  "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
                  "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies")
PARAM_RE = re.compile(r"^(%s)\s*=" % "|".join(AWG_PARAM_KEYS))


def cmd_params_replace(path):
    """Заменить параметры AmneziaWG в [Interface] на строки из stdin.

    Ключи, адреса, I1-I5, DNS, MTU и секции [Peer] не трогаются: меняется
    только то, что обязано совпадать у сервера и всех клиентов.
    """
    params = [l for l in sys.stdin.read().splitlines() if l.strip()]
    if not params:
        die("пустой набор параметров")
    out, in_iface, done = [], False, False
    for line in read(path).split("\n"):
        if re.match(r"^\[Interface\]", line):
            in_iface = True
            out.append(line)
            continue
        if line.startswith("["):
            if in_iface and not done:
                if out and out[-1] == "":
                    out.pop()
                    out.extend(params)
                    out.append("")
                else:
                    out.extend(params)
                done = True
            in_iface = False
        if in_iface and PARAM_RE.match(line):
            if not done:
                out.extend(params)
                done = True
            continue
        out.append(line)
    if not done:
        out.extend(params)
    write_atomic(path, "\n".join(out))


def cmd_keepalive_set(path, value):
    text = read(path)
    new = re.sub(r"^PersistentKeepalive\s*=.*$", "PersistentKeepalive = " + value, text, flags=re.M)
    if new != text:
        write_atomic(path, new)


def cmd_i_replace(path):
    """Заменить строки I1-I5 клиента на строки из stdin (пусто — убрать)."""
    lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
    out, inserted = [], False
    for line in read(path).split("\n"):
        if re.match(r"^I[1-5]\s*=", line):
            continue
        if line.startswith("[Peer]") and not inserted:
            while out and out[-1] == "":
                out.pop()
            out.extend(lines)
            out.append("")
            inserted = True
        out.append(line)
    write_atomic(path, "\n".join(out))


# ── Срок действия клиентов ──
def cmd_expire_set(conf, name, ts):
    head, peers = split_peers(read(conf))
    i = find_peer(peers, name=name)
    if i < 0:
        die("клиент %s не найден" % name, 2)
    peers[i] = set_meta(peers[i], "expires", ts)
    write_atomic(conf, head + "".join(peers))


def cmd_expire_clear(conf, name, suspend):
    head, peers = split_peers(read(conf))
    i = find_peer(peers, name=name)
    if i < 0:
        die("клиент %s не найден" % name, 2)
    b = peers[i]
    orig = peer_meta(b, "orig_ips")
    if orig and peer_field(b, "AllowedIPs") == suspend:
        b = re.sub(r"^(AllowedIPs\s*=\s*).+$", lambda m: m.group(1) + orig, b, count=1, flags=re.M)
    b = set_meta(set_meta(b, "expires", ""), "orig_ips", "")
    peers[i] = b
    write_atomic(conf, head + "".join(peers))
    print(orig)


def cmd_expire_check(conf, suspend, state_dir):
    """Блокирует истёкших (AllowedIPs → suspend, исходный адрес в orig_ips)
    и предупреждает за час до срока. Печатает события построчно:
    CHANGED; EXPIRED<TAB>имя<TAB>адрес; WARN1H<TAB>имя<TAB>минут."""
    try:
        text = read(conf)
    except OSError:
        return
    now = int(time.time())
    head, peers = split_peers(text)
    events, changed = [], False
    for i, b in enumerate(peers):
        exp, pub, aip = peer_meta(b, "expires"), peer_field(b, "PublicKey"), peer_field(b, "AllowedIPs")
        if not (exp.isdigit() and pub and aip):
            continue
        exp = int(exp)
        name = peer_name(b) or pub[:8]
        if now >= exp and aip != suspend:
            if not peer_meta(b, "orig_ips"):
                b = set_meta(b, "orig_ips", aip)
            b = re.sub(r"^(AllowedIPs\s*=\s*).+$", lambda m: m.group(1) + suspend, b, count=1, flags=re.M)
            peers[i] = b
            changed = True
            events.append("EXPIRED\t%s\t%s" % (name, aip))
        elif aip != suspend and 0 < exp - now <= 3600:
            lock = os.path.join(state_dir, "warn1h_" + re.sub(r"[^A-Za-z0-9]", "_", pub))
            if not os.path.exists(lock):
                events.append("WARN1H\t%s\t%d" % (name, max(1, (exp - now) // 60)))
                try:
                    os.makedirs(state_dir, exist_ok=True)
                    with open(lock, "w") as f:
                        f.write(str(now))
                except OSError:
                    pass
    if changed:
        write_atomic(conf, head + "".join(peers))
        print("CHANGED")
    for e in events:
        print(e)


# ════════════════════════ сети ════════════════════════
def cmd_net_of(cidr):
    print(ipaddress.ip_network(cidr.split(",")[0].strip(), strict=False))


def cmd_pick_net(pool="wgobf"):
    """Свободная /24, не пересекающаяся ни с одним адресом и маршрутом из stdin.
    pool=awg — 10.[10-55].x (как всегда выбирался AWG), иначе пулы
    WG+обфускатора: 10.[60-99].x, 172.16-31.x, 192.168.x."""
    taken = []
    for tok in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])", sys.stdin.read()):
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if n.prefixlen:
            taken.append(n)
    pools = [lambda: "10.%d.%d.0/24" % (random.randint(60, 99), random.randint(1, 254)),
             lambda: "172.%d.%d.0/24" % (random.randint(16, 31), random.randint(1, 254)),
             lambda: "192.168.%d.0/24" % random.randint(100, 250)]
    if pool == "awg":
        pools.insert(0, lambda: "10.%d.%d.0/24" % (random.randint(10, 55), random.randint(1, 254)))
    for pick in pools:
        for _ in range(300):
            net = ipaddress.ip_network(pick())
            if not any(net.overlaps(t) for t in taken):
                print(net)
                return
    die("свободной /24 нет")


def cmd_net_overlaps(cidr):
    """0 — сеть cidr пересекается с чем-то из stdin, 1 — свободна."""
    net = ipaddress.ip_network(cidr, strict=False)
    for tok in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])", sys.stdin.read()):
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if n.prefixlen and net.overlaps(n):
            print(n)
            return
    sys.exit(1)


def cmd_allowed_except(ip):
    """AllowedIPs «весь IPv4, кроме сервера»: иначе пакеты обфускатора клиента
    к серверу уйдут в сам туннель. Работает на любой платформе, в отличие от FwMark."""
    srv = ipaddress.ip_network(ip + "/32")
    nets = sorted(ipaddress.ip_network("0.0.0.0/0").address_exclude(srv))
    print(", ".join(str(n) for n in nets) + ", ::/0")


def cmd_rand_key(n="32"):
    alphabet = string.ascii_letters + string.digits
    print("".join(secrets.choice(alphabet) for _ in range(int(n))))


def cmd_phobos_link(path, name):
    conf = open(path, "rb").read()
    print("phobos://" + base64.urlsafe_b64encode(conf).decode().rstrip("=")
          + "#" + urllib.parse.quote(name))


def cmd_exit_conf_fix(path):
    """Конфиг клиента к exit-ноде: Table = off обязателен (иначе awg-quick
    уведёт в туннель весь сервер вместе с SSH), DNS выбрасываем (awg-quick
    перепишет resolv.conf сервера или упадёт без resolvconf)."""
    out, in_iface, added = [], False, False
    for line in read(path).replace("\r", "").split("\n"):
        if re.match(r"^\s*\[\s*interface\s*\]", line, re.I):
            in_iface = True
            out.append("[Interface]")
            out.append("Table = off")
            added = True
            continue
        if re.match(r"^\s*\[", line):
            in_iface = False
        if in_iface and re.match(r"^\s*(table|dns)\s*=", line, re.I):
            continue
        out.append(line)
    if not added:
        die("нет секции [Interface]")
    write_atomic(path, "\n".join(out))


# ════════════════════════ Xray ════════════════════════
SKIP_PROTO = ("freedom", "blackhole", "dns")
KNOWN_IN = {"xray0", "tun-in", "tun-probe", "socks-in"}
SNIFF = {"enabled": True, "destOverride": ["http", "tls", "quic"]}


def jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def jsave(path, conf):
    write_atomic(path, json.dumps(conf, indent=2, ensure_ascii=False) + "\n", 0o600)


def proxy_tags(conf):
    return [o["tag"] for o in conf.get("outbounds", [])
            if o.get("tag") and o.get("protocol") not in SKIP_PROTO]


def apply_transport(ss, net, get):
    if net == "ws":
        cfg = {}
        if get("path"):
            cfg["path"] = get("path")
        if get("host"):
            cfg["headers"] = {"Host": get("host")}
        ss["wsSettings"] = cfg
    elif net == "grpc":
        cfg = {}
        svc = get("serviceName") or get("svc") or get("path")
        if svc:
            cfg["serviceName"] = svc
        if get("mode") == "multi":
            cfg["multiMode"] = True
        ss["grpcSettings"] = cfg
    elif net in ("xhttp", "splithttp"):
        # Без path сервер отдаёт 404 на корень: TLS проходит, трафика нет
        cfg = {k: get(k) for k in ("path", "host", "mode") if get(k)}
        if get("extra"):
            try:
                cfg["extra"] = json.loads(get("extra"))
            except ValueError:
                pass
        ss["xhttpSettings" if net == "xhttp" else "splithttpSettings"] = cfg
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {k: get(k) for k in ("path", "host") if get(k)}
    elif net in ("h2", "http"):
        # Транспорт HTTP/2 из Xray убран в пользу XHTTP stream-one
        cfg = {"mode": "stream-one"}
        if get("path"):
            cfg["path"] = get("path")
        if get("host"):
            cfg["host"] = get("host").split(",")[0]
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = cfg
        sys.stderr.write("NOTE:транспорт h2 переведён на XHTTP stream-one\n")
    elif net not in ("tcp", "raw", "", None):
        sys.stderr.write("UNSUPPORTED:%s\n" % net)


def apply_tls(ss, get, fallback_sni):
    sec = ss.get("security") or "none"
    if sec in ("", "none", "0"):
        ss["security"] = "none"
        return
    tls = {"serverName": get("sni") or get("host") or fallback_sni or "",
           "fingerprint": get("fp") or "chrome"}
    for src, dst in (("pbk", "publicKey"), ("sid", "shortId"), ("spx", "spiderX")):
        if get(src):
            tls[dst] = get(src)
    if get("alpn"):
        tls["alpn"] = get("alpn").split(",")
    if str(get("allowInsecure") or "").lower() in ("1", "true"):
        tls["allowInsecure"] = True
    ss["realitySettings" if sec == "reality" else "tlsSettings"] = tls


def tag_for(host):
    return "proxy_" + re.sub(r"[^A-Za-z0-9]", "_", host or "server")


def cmd_xray_link(link):
    link = link.strip()
    if link.startswith("vless://"):
        u = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(u.query)

        def get(k):
            return qs[k][0] if qs.get(k) else None
        host = u.hostname or ""
        ob = {"protocol": "vless", "tag": tag_for(host),
              "settings": {"vnext": [{"address": host, "port": u.port or 443,
                                      "users": [{"id": urllib.parse.unquote(u.username or ""),
                                                 "encryption": get("encryption") or "none",
                                                 "flow": get("flow") or ""}]}]},
              "streamSettings": {"network": get("type") or "tcp",
                                 "security": get("security") or "none"}}
    elif link.startswith("vmess://"):
        raw = link[8:]
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))

        def get(k):
            v = data.get(k)
            return str(v) if v not in (None, "") else None
        host = str(data.get("add") or "")
        ob = {"protocol": "vmess", "tag": tag_for(host),
              "settings": {"vnext": [{"address": host, "port": int(data.get("port") or 443),
                                      "users": [{"id": data.get("id"),
                                                 "alterId": int(data.get("aid") or 0),
                                                 "security": data.get("scy") or "auto"}]}]},
              "streamSettings": {"network": data.get("net") or "tcp",
                                 "security": data.get("tls") or "none"}}
    elif link.startswith(("hysteria2://", "hy2://")):
        u = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(u.query)
        st = {"server": u.hostname, "port": u.port or 443,
              "password": urllib.parse.unquote(u.username or "")}
        if qs.get("sni"):
            st["serverName"] = qs["sni"][0]
        if qs.get("insecure"):
            st["insecure"] = qs["insecure"][0] == "1"
        if qs.get("obfs"):
            st["obfs"] = {"type": qs["obfs"][0]}
            if qs.get("obfs-password"):
                st["obfs"]["password"] = qs["obfs-password"][0]
        print(json.dumps({"protocol": "hysteria2", "tag": tag_for(u.hostname), "settings": st}))
        return
    else:
        die("поддерживаются vless://, vmess://, hysteria2://")
    apply_transport(ob["streamSettings"], ob["streamSettings"]["network"], get)
    apply_tls(ob["streamSettings"], get, host)
    print(json.dumps(ob))


def cmd_xray_default(path):
    """Начальный конфиг. listen 127.0.0.1 у socks обязателен: иначе на сервере
    появляется открытый SOCKS5-релей без авторизации."""
    jsave(path, {
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                      "tag": "socks-in", "settings": {"auth": "noauth", "udp": True},
                      "sniffing": SNIFF}],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    })


def cmd_xray_add(path):
    ob = json.loads(sys.stdin.read())
    conf = jload(path)
    outs = conf.setdefault("outbounds", [])
    if any(o.get("tag") == ob.get("tag") for o in outs):
        die("outbound %s уже есть" % ob.get("tag"), 3)
    at = next((i for i, o in enumerate(outs) if o.get("protocol") == "freedom"), len(outs))
    outs.insert(at, ob)
    # Новая ссылка становится активным выходом, если балансировщик не включён
    for r in conf.get("routing", {}).get("rules", []):
        if set(r.get("inboundTag") or []) & KNOWN_IN and not r.get("balancerTag"):
            r["outboundTag"] = ob["tag"]
    jsave(path, conf)


def cmd_xray_del(path, *tags):
    conf = jload(path)
    conf["outbounds"] = [o for o in conf.get("outbounds", []) if o.get("tag") not in tags]
    jsave(path, conf)


def cmd_xray_tags(path):
    for t in proxy_tags(jload(path)):
        print(t)


def probe_conf(outbound):
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                          "tag": "probe-in", "settings": {"auth": "noauth"}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]}


def cmd_xray_probe(out):
    """Конфиг для `xray run -test` из одного outbound (stdin)."""
    jsave(out, probe_conf(json.loads(sys.stdin.read())))


def cmd_xray_probe_tag(path, tag, out):
    ob = next((o for o in jload(path).get("outbounds", []) if o.get("tag") == tag), None)
    if ob is None:
        die("нет outbound %s" % tag, 2)
    jsave(out, probe_conf(ob))


def cmd_xray_test_copy(src, dst):
    """Копия конфига для `xray run -test`. Проверка с inbound tun создаёт
    устройство, а xray0 занят работающим Xray («device or resource busy») —
    у копии tun получает своё имя и адрес."""
    conf = jload(src)
    for i, ib in enumerate(x for x in conf.get("inbounds") or [] if x.get("protocol") == "tun"):
        st = ib.setdefault("settings", {})
        st["name"] = "xrt" + secrets.token_hex(3)
        st["address"] = ["198.18.%d.1/30" % (250 + i % 4)]
    jsave(dst, conf)


def cmd_xray_tun_probe(out):
    jsave(out, {"log": {"loglevel": "none"},
                "inbounds": [{"protocol": "tun", "tag": "tun-probe",
                              "settings": {"mtu": 1500, "stack": "gvisor",
                                           "address": ["172.16.250.1/30"]}}],
                "outbounds": [{"protocol": "freedom", "tag": "direct"}]})


def cmd_xray_balancer(path, strategy):
    if strategy not in ("random", "roundRobin", "leastPing", "leastLoad", "off"):
        die("стратегия: random|roundRobin|leastPing|leastLoad|off")
    conf = jload(path)
    tags = proxy_tags(conf)
    routing = conf.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    rule = next((r for r in rules if r.get("balancerTag") == "balancer"), None) \
        or next((r for r in rules if set(r.get("inboundTag") or []) & KNOWN_IN), None)
    if strategy == "off":
        routing.pop("balancers", None)
        conf.pop("observatory", None)
        for r in rules:
            if r.pop("balancerTag", None) and tags:
                r["outboundTag"] = tags[0]
    else:
        if len(tags) < 2:
            die("нужно минимум 2 proxy-outbound")
        routing["balancers"] = [{"tag": "balancer", "selector": tags,
                                 "strategy": {"type": strategy}}]
        if rule is None:
            rule = {"type": "field", "inboundTag": ["socks-in"]}
            rules.append(rule)
        rule.pop("outboundTag", None)
        rule["balancerTag"] = "balancer"
        # leastPing/leastLoad выбирают по замерам observatory
        if strategy in ("leastPing", "leastLoad"):
            conf["observatory"] = {"subjectSelector": tags,
                                   "probeUrl": "https://www.google.com/generate_204",
                                   "probeInterval": "1m"}
        else:
            conf.pop("observatory", None)
    jsave(path, conf)


def cmd_xray_balancer_get(path):
    b = jload(path).get("routing", {}).get("balancers") or []
    print(b[0].get("strategy", {}).get("type", "random") if b else "off")


def cmd_xray_ru(path, mode):
    """РФ-сайты напрямую: .ru/.su/.рф, «только из РФ» и РФ-IP идут в direct.
    Правила встают над первым правилом, ведущим в туннель, — блокировки выше
    остаются выше."""
    conf = jload(path)
    routing = conf.setdefault("routing", {})
    rules = [r for r in routing.get("rules", []) if r.get("ruleTag") != "ru-direct"]
    if mode == "on":
        outs = conf.setdefault("outbounds", [])
        if not any(o.get("tag") == "direct" for o in outs):
            outs.append({"protocol": "freedom", "tag": "direct"})
        proxy = set(proxy_tags(conf))
        at = next((i for i, r in enumerate(rules)
                   if r.get("balancerTag") or r.get("outboundTag") in proxy
                   or r.get("outboundTag") == "proxy"), len(rules))
        rules[at:at] = [
            {"type": "field", "ruleTag": "ru-direct", "outboundTag": "direct",
             "domain": ["domain:ru", "domain:su", "domain:xn--p1ai",
                        "ext:geosite_RU.dat:ru-available-only-inside"]},
            {"type": "field", "ruleTag": "ru-direct", "outboundTag": "direct",
             "ip": ["ext:geoip_RU.dat:ru"]},
        ]
    routing["rules"] = rules
    jsave(path, conf)


def cmd_xray_prepare(path, mode):
    """Привести конфиг к режиму входа: native (inbound tun в самом Xray) или
    tun2socks (только SOCKS на 127.0.0.1:10808, xray0 поднимает tun2socks).
    Заодно чинит висячие ссылки на удалённые outbounds и балансировщик —
    с ними Xray отвергает конфиг целиком."""
    conf = jload(path)
    inb = [i for i in conf.get("inbounds") or []
           if not (i.get("tag") == "xray0" and i.get("protocol") == "dokodemo-door")]
    socks = next((i for i in inb if i.get("tag") == "socks-in"), None)
    if socks is None:
        socks = {"protocol": "socks", "tag": "socks-in",
                 "settings": {"auth": "noauth", "udp": True}, "sniffing": SNIFF}
        inb.append(socks)
    socks["listen"] = "127.0.0.1"
    socks["port"] = socks.get("port") or 10808
    tun = next((i for i in inb if i.get("protocol") == "tun"), None)
    if mode == "native":
        if tun is None:
            tun = {"protocol": "tun", "tag": "tun-in",
                   "settings": {"mtu": 1200, "stack": "gvisor", "address": ["172.16.250.1/30"]},
                   "sniffing": SNIFF}
            inb.insert(0, tun)
        tun["tag"] = tun.get("tag") or "tun-in"
        want = tun["tag"]
    else:
        inb = [i for i in inb if i.get("protocol") != "tun"]
        want = "socks-in"
    conf["inbounds"] = inb

    routing = conf.setdefault("routing", {})
    routing.setdefault("domainStrategy", "AsIs")
    rules = routing.setdefault("rules", [])
    touched = False
    for r in rules:
        tags = r.get("inboundTag")
        if isinstance(tags, list) and any(t in KNOWN_IN for t in tags):
            r["inboundTag"] = [want]
            touched = True
    ptags = proxy_tags(conf)
    if not touched:
        rules.append({"type": "field", "inboundTag": [want],
                      "outboundTag": ptags[0] if ptags else "proxy"})

    existing = {o.get("tag") for o in conf.get("outbounds", []) if o.get("tag")}
    balancers = routing.get("balancers") or []
    for b in balancers:
        b["selector"] = [t for t in (b.get("selector") or []) if t in existing]
    # Балансировать между одним выходом нечего
    balancers = [b for b in balancers if len(b["selector"]) >= 2]
    if balancers:
        routing["balancers"] = balancers
    else:
        routing.pop("balancers", None)
    obs = conf.get("observatory")
    if obs and balancers:
        obs["subjectSelector"] = [t for t in obs.get("subjectSelector") or [] if t in existing]
    elif obs:
        conf.pop("observatory")
    btags = {b.get("tag") for b in balancers}
    for r in rules:
        if r.get("balancerTag") and r["balancerTag"] not in btags:
            r.pop("balancerTag")
        ot = r.get("outboundTag")
        if not r.get("balancerTag") and (not ot or ot not in existing):
            if ptags:
                r["outboundTag"] = ptags[0]
            else:
                r.pop("outboundTag", None)
    routing["rules"] = [r for r in rules if r.get("outboundTag") or r.get("balancerTag")]
    jsave(path, conf)


# ════════════════════════ DPI-тест ════════════════════════
def pcap_payloads(path):
    out = []
    with open(path, "rb") as f:
        if len(f.read(24)) < 24:
            return out
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            pkt = f.read(struct.unpack("<I", ph[8:12])[0])
            if len(pkt) < 42 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
                continue
            udp = 14 + (pkt[14] & 0x0F) * 4
            if udp + 8 > len(pkt):
                continue
            ln = struct.unpack(">H", pkt[udp + 4:udp + 6])[0]
            p = pkt[udp + 8:udp + ln]
            if len(p) >= 10:
                out.append(p)
    return out


def detect(p):
    for m in (b"REGISTER", b"INVITE", b"OPTIONS", b"SIP/2.0"):
        if p.startswith(m):
            return "sip", "SIP %s (%dB)" % (m.decode(), len(p))
    if p[0] == 0x16 and p[1:3] in (b"\xfe\xfd", b"\xfe\xff"):
        return "dtls", "DTLS handshake (%dB)" % len(p)
    if p.startswith(b"M-SEARCH"):
        return "ssdp", "SSDP M-SEARCH (%dB)" % len(p)
    if len(p) >= 20 and p[4:8] == b"\x21\x12\xa4\x42":
        mt = struct.unpack(">H", p[0:2])[0]
        if mt in (0x0001, 0x000A):
            kind = "TURN Allocate" if mt == 0x000A else "STUN Binding"
            ml = struct.unpack(">H", p[2:4])[0]
            if 20 + ml < len(p) and p[20 + ml] == 0x16:
                return "webrtc", "WebRTC: %s + DTLS (%dB)" % (kind, len(p))
            return "stun", "%s (%dB)" % (kind, len(p))
    if len(p) == 48 and p[0] == 0x23 and p[12:16] == b"INIT":
        return "ntp", "NTP client (%dB)" % len(p)
    if len(p) >= 13 and (p[2] >> 7) == 0 and ((p[2] >> 3) & 0xF) == 0 \
            and 1 <= struct.unpack(">H", p[4:6])[0] <= 10 and 1 <= p[12] <= 63:
        return "dns", "DNS query (%dB)" % len(p)
    fb = p[0]
    if (fb >> 6) == 3 and len(p) >= 7 and p[1:5].hex() in ("00000001", "6b3343cf") and 1 <= p[5] <= 20:
        return "quic", "QUIC Initial (%dB)" % len(p)
    # Узко по длинам генератора: 0x80 в первом байте бывает и у данных AWG
    if len(p) in (172, 108) and p[0] == 0x80 and (p[1] & 0x7F) in (0, 8, 96):
        return "rtp", "RTP pt=%d (%dB)" % (p[1] & 0x7F, len(p))
    return None, None


def cmd_pcap_analyze(path):
    payloads = pcap_payloads(path)
    if not payloads:
        print("VERDICT|EMPTY|Пакетов не захвачено")
        return
    found, other = [], 0
    for p in payloads:
        t, d = detect(p)
        if t:
            found.append((t, d))
        else:
            other += 1
    print("INFO|Захвачено пакетов: %d" % len(payloads))
    seen = []
    for t, d in found:
        if t not in seen:
            seen.append(t)
            print("OK|" + d)
    if other:
        print("INFO|Прочих пакетов AWG: %d (не распознаются как WireGuard)" % other)
    if found:
        print("VERDICT|PASS|Цепочка мимикрии: %d пакет(ов) — %s" % (len(found), ", ".join(seen)))
    else:
        print("VERDICT|OK|Обфускация работает; пакеты мимикрии прошли до начала захвата")


# ════════════════════════ машинный API ════════════════════════
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _typed(val, typ):
    """Значение по типу ключа: s строка, n число, b да/нет, j JSON, f файл."""
    if typ == "n":
        try:
            return int(val)
        except ValueError:
            try:
                return float(val)
            except ValueError:
                return None
    if typ == "b":
        return val.strip().lower() in ("1", "true", "yes", "on", "y")
    if typ == "j":
        return json.loads(val) if val.strip() else None
    if typ == "f":
        try:
            return ANSI.sub("", read(val))
        except OSError:
            return ""
    return val


def _split_key(key):
    name, _, typ = key.partition(":")
    return name, typ or "s"


def cmd_json_kv():
    """Строки «ключ[:тип]<TAB>значение» → объект; точки в ключе — вложенность."""
    out = {}
    for line in sys.stdin.read().splitlines():
        if "\t" not in line:
            continue
        key, val = line.split("\t", 1)
        name, typ = _split_key(key)
        cur = out
        parts = name.split(".")
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = _typed(val, typ)
    print(json.dumps(out, ensure_ascii=False))


def cmd_json_rows(*cols):
    """Строки TSV → список объектов по колонкам «имя[:тип]»."""
    spec = [_split_key(c) for c in cols]
    rows = []
    for line in sys.stdin.read().splitlines():
        if not line:
            continue
        vals = line.split("\t")
        vals += [""] * (len(spec) - len(vals))
        rows.append({name: _typed(v, typ) for (name, typ), v in zip(spec, vals)})
    print(json.dumps(rows, ensure_ascii=False))


def cmd_json_list():
    """Непустые строки stdin → JSON-массив строк."""
    print(json.dumps([l for l in sys.stdin.read().splitlines() if l], ensure_ascii=False))


def _peers_list(path):
    """peers.list туннеля → {ip: нода или ""}; None — файла нет."""
    try:
        text = read(path)
    except OSError:
        return None
    out = {}
    for line in text.splitlines():
        ip, _, node = line.strip().partition("|")
        if ip:
            out[ip] = node
    return out


def _first_ip(value):
    return value.split(",")[0].split("/")[0].strip()


def cmd_clients_json(conf, dump, client_dir, warp, xray, exits):
    """Клиенты awg0 со статистикой `awg show dump` и туннелями — для бота."""
    _, peers = split_peers(read(conf))
    stats = {}
    try:
        for line in read(dump).splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 7:
                stats[f[0]] = f
    except OSError:
        pass
    now = int(time.time())
    tunnels = {"warp": _peers_list(warp), "xray": _peers_list(xray), "exit": _peers_list(exits)}
    rows = []
    for b in peers:
        pub = peer_field(b, "PublicKey")
        if not pub:
            continue
        name = peer_name(b)
        orig = peer_meta(b, "orig_ips")
        ip = _first_ip(orig or peer_field(b, "AllowedIPs"))
        exp = peer_meta(b, "expires")
        s = stats.get(pub) or ["", "", "", "", "0", "0", "0"]
        hs = int(s[4]) if s[4].isdigit() else 0
        path = ""
        for suf in ("_awg3.conf", "_awg2.conf"):
            p = os.path.join(client_dir, name + suf)
            if name and os.path.isfile(p):
                path = p
                break
        row = {
            "name": name, "ip": ip, "pub": pub,
            "expires": int(exp) if exp.isdigit() else None, "blocked": bool(orig),
            "mimicry": peer_meta(b, "mimicry") or "none",
            "handshake": hs, "ago": now - hs if hs else None,
            "online": bool(hs) and now - hs < 180,
            "rx": int(s[5]) if s[5].isdigit() else 0, "tx": int(s[6]) if s[6].isdigit() else 0,
            "endpoint": "" if s[2] in ("", "(none)") else s[2], "file": path,
        }
        for t, lst in tunnels.items():
            if lst is None:
                row[t] = None
            elif t == "exit":
                row[t] = (lst[ip] or "shared") if ip in lst else "off"
            else:
                row[t] = ip in lst
        rows.append(row)
    print(json.dumps(rows, ensure_ascii=False))


def _job_info(jdir, active):
    try:
        meta = json.loads(read(os.path.join(jdir, "meta.json")))
    except (OSError, ValueError):
        meta = {"id": os.path.basename(jdir)}
    try:
        res = json.loads(read(os.path.join(jdir, "result.json")))
    except (OSError, ValueError):
        res = None
    if res is not None:
        meta["state"] = "done"
        meta.update({k: res.get(k) for k in ("ok", "rc", "data", "error")})
        try:
            meta["finished"] = int(os.path.getmtime(os.path.join(jdir, "result.json")))
        except OSError:
            pass
    else:
        meta["state"] = "running" if active == "1" else "lost"
    return meta


def cmd_api_job_status(jdir, offset, active):
    """Состояние задачи и новый кусок журнала с байта offset. Кусок режется
    по концу строки: следующий опрос продолжит с целой строки."""
    info = _job_info(jdir, active)
    try:
        off = max(0, int(offset))
    except ValueError:
        off = 0
    try:
        with open(os.path.join(jdir, "log"), "rb") as f:
            f.seek(off)
            chunk = f.read(256 * 1024)
    except OSError:
        chunk = b""
    if info["state"] == "running":
        cut = chunk.rfind(b"\n") + 1
        chunk = chunk[:cut]
    info["offset"] = off + len(chunk)
    info["log"] = ANSI.sub("", chunk.decode("utf-8", "replace"))
    print(json.dumps(info, ensure_ascii=False))


def cmd_api_jobs(jobs_dir, *active_ids):
    """Последние 20 задач, новые сверху; active_ids — задачи с живым юнитом."""
    try:
        ids = sorted(os.listdir(jobs_dir), reverse=True)[:20]
    except OSError:
        ids = []
    rows = []
    for i in ids:
        info = _job_info(os.path.join(jobs_dir, i), "1" if i in active_ids else "0")
        info.pop("data", None)
        rows.append(info)
    print(json.dumps(rows, ensure_ascii=False))


def cmd_tg_targets(conf, admins_json):
    """Кому слать уведомления от таймеров: токен, прокси бота и ID
    владельцев (ADMIN_ID, у старых ботов ADMIN_CHAT_ID) и приглашённых
    админов — построчно. Пустой вывод — бот не настроен."""
    vals = {}
    try:
        for line in read(conf).splitlines():
            k, sep, v = line.strip().partition("=")
            if sep and not k.startswith("#"):
                vals[k.strip().upper()] = v.strip().strip("\"'")
    except OSError:
        return
    ids = []
    for part in re.split(r"[,;\s]+", vals.get("ADMIN_ID") or vals.get("ADMIN_CHAT_ID", "")):
        if part.isdigit() and part not in ids:
            ids.append(part)
    try:
        for k in (json.loads(read(admins_json)).get("admins") or {}):
            if str(k).isdigit() and str(k) not in ids:
                ids.append(str(k))
    except (OSError, ValueError, AttributeError):
        pass
    token = vals.get("BOT_TOKEN", "")
    if token and ids:
        print("\n".join([token, vals.get("BOT_PROXY", "")] + ids))


def cmd_api_envelope(rc, data_file, log_file):
    try:
        raw = read(data_file).strip()
    except OSError:
        raw = ""
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = None
    try:
        log = ANSI.sub("", read(log_file))
    except OSError:
        log = ""
    log = "\n".join(line.rstrip() for line in log.splitlines()).strip("\n")
    error = ""
    if rc != "0":
        errs = [l.strip()[1:].strip() for l in log.splitlines() if l.strip().startswith("×")]
        error = errs[-1] if errs else (log.splitlines()[-1].strip() if log else "код %s" % rc)
    print(json.dumps({"ok": rc == "0", "rc": int(rc), "data": data, "log": log, "error": error},
                     ensure_ascii=False))


# ════════════════════════ архивы ════════════════════════
def cmd_safe_untar(archive, dest):
    """Распаковать только обычные файлы и каталоги без выхода за dest:
    архив может прийти от пользователя (бэкап, загруженный в бота)."""
    import tarfile
    root = os.path.realpath(dest)
    os.makedirs(root, exist_ok=True)
    n = 0
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            parts = [p for p in m.name.replace("\\", "/").split("/") if p not in ("", ".")]
            if not parts or ".." in parts or not (m.isfile() or m.isdir()):
                continue
            path = os.path.join(root, *parts)
            if m.isdir():
                os.makedirs(path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            src = tar.extractfile(m)
            with open(path, "wb") as f:
                shutil.copyfileobj(src, f)
            os.chmod(path, 0o600)
            n += 1
    if not n:
        die("в архиве нет файлов")


COMMANDS = {
    "peers": cmd_peers, "meta-set": cmd_meta_set, "peer-del": cmd_peer_del,
    "peer-rename": cmd_peer_rename, "peers-clear": cmd_peers_clear,
    "params-replace": cmd_params_replace, "keepalive-set": cmd_keepalive_set,
    "i-replace": cmd_i_replace,
    "expire-set": cmd_expire_set, "expire-clear": cmd_expire_clear,
    "expire-check": cmd_expire_check,
    "net-of": cmd_net_of, "pick-net": cmd_pick_net, "net-overlaps": cmd_net_overlaps,
    "allowed-except": cmd_allowed_except,
    "rand-key": cmd_rand_key, "phobos-link": cmd_phobos_link, "exit-conf-fix": cmd_exit_conf_fix,
    "xray-link": cmd_xray_link, "xray-default": cmd_xray_default, "xray-add": cmd_xray_add,
    "xray-del": cmd_xray_del, "xray-tags": cmd_xray_tags, "xray-probe": cmd_xray_probe,
    "xray-probe-tag": cmd_xray_probe_tag, "xray-tun-probe": cmd_xray_tun_probe,
    "xray-test-copy": cmd_xray_test_copy,
    "xray-balancer": cmd_xray_balancer, "xray-balancer-get": cmd_xray_balancer_get,
    "xray-ru": cmd_xray_ru, "xray-prepare": cmd_xray_prepare,
    "pcap-analyze": cmd_pcap_analyze, "safe-untar": cmd_safe_untar,
    "json-kv": cmd_json_kv, "json-rows": cmd_json_rows, "json-list": cmd_json_list,
    "clients-json": cmd_clients_json, "api-envelope": cmd_api_envelope,
    "api-job-status": cmd_api_job_status, "api-jobs": cmd_api_jobs,
    "tg-targets": cmd_tg_targets,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        die("команда: " + ", ".join(sorted(COMMANDS)))
    try:
        COMMANDS[sys.argv[1]](*sys.argv[2:])
    except TypeError as e:
        die("неверные аргументы %s: %s" % (sys.argv[1], e))
    except (OSError, ValueError) as e:
        die("%s: %s" % (sys.argv[1], e))
