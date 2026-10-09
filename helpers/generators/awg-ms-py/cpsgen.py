import sys, os, struct, secrets, signal, time

try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # чистое поведение при обрыве пайпа
except Exception:
    pass

"""
 ================================================================
 Порт payloadGen (github.com/Sketchystan1/payloadGen) на Python.
 Соответствие файлам оригинала:
   app.js       -> CONFIG, DOMAIN_POOL, chunk_payload, формат вывода
   generators.js-> генераторы пакетов и сборка TLS ClientHello
   crypto.js    -> HPKE (ECH) и защита QUIC Initial (RFC 9001)
 Структура пакетов и порядок полей повторяют оригинал байт в байт;
 отличается только источник случайности (secrets вместо WebCrypto).
 ================================================================
"""

_WARNED = set()

def _warn_once(msg):
    """ Генератор строит до 5 пакетов за запуск, причина деградации у них общая: один и тот же дефект не должен засорять stderr пять раз. """
    if msg in _WARNED:
        return
    _WARNED.add(msg)
    sys.stderr.write("[CPS] WARN: %s\n" % msg)

# == Utilities (generators.js: randomBytes/u16/u24/u32/concatBytes) ==
def rb(n):
    return secrets.token_bytes(max(0, int(n)))

def zeros(n):
    return b"\x00" * max(0, int(n))

def ri(max_exclusive):
    # randomIntExclusive: 0 <= x < max_exclusive
    if max_exclusive <= 1:
        return 0
    return secrets.randbelow(int(max_exclusive))

def rr(a, b):
    # включительный диапазон [a, b]
    if a > b:
        a, b = b, a
    return a + secrets.randbelow(b - a + 1)

def rc(items):
    return items[ri(len(items))]

def ru32():
    return int.from_bytes(rb(4), "big")

def u16(v):
    return struct.pack(">H", v & 0xFFFF)

def u24(v):
    return struct.pack(">I", v & 0xFFFFFF)[1:]

def u32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)

def enc_text(s):
    return str(s).encode("utf-8")

def to_hex(b):
    return b.hex()

def read_u16(b, off):
    return (b[off] << 8) | b[off + 1]

# == Динамические поля пакета мимикрии (теги <r>/<rc>/<rd>) ==
#
# Строка I, собранная только из <b 0x...>, — это замороженный снимок: модуль
# кладёт его в буфер один раз при setconf и шлёт БАЙТ В БАЙТ при каждой попытке
# рукопожатия (send.c: jp_spec_applymods + wg_socket_send_buffer_to_peer, раз в
# ~120 с). Повторяющийся один и тот же UDP-пакет — ровно тот статистический
# признак, против которого делалась 3.1.
#
# Теги <r N> / <rc N> / <rd N> модуль пересчитывает на КАЖДОЙ отправке
# (junk.c: random_byte_modifier / random_char_modifier / random_digit_modifier,
# вызываются из jp_spec_applymods перед каждым send), то есть поле становится
# заново случайным. Порядок тегов в строке сохраняется: jp_parse_tags кладёт их
# через list_add (в обратном порядке), а сборка идёт list_for_each_entry_reverse
# — на выходе порядок написания.
#
# Помечать можно ДАЛЕКО не всё. Поле годится, только если оно случайно в самом
# протоколе и от него ничего не считается:
#   • нельзя всё, что покрыто контрольной суммой или AEAD (STUN FINGERPRINT
#     CRC32, QUIC Initial — ключи выводятся из DCID, заголовок входит в AAD);
#   • нельзя поле, встречающееся в пакете дважды (SIP Call-ID в двух заголовках,
#     RTCP SSRC): теги независимы, и две копии разъедутся. Это ловится
#     автоматически — помечается только уникальное вхождение;
#   • в текстовых протоколах нельзя <r> (двоичный мусор внутри текста) — только
#     <rc>/<rd>.
# Длина поля тегом сохраняется, поэтому длины и Content-Length остаются верными.
#
# Ограничение движка: длина <r/rc/rd> не больше 1000 байт.
DYN_TAG_MAX = 1000

_DYN = []

def dyn_reset():
    del _DYN[:]

def dyn(value, tag="r"):
    """Помечает поле как заново случайное при каждой отправке. Возвращает его же."""
    token = value if isinstance(value, bytes) else enc_text(value)
    if 2 <= len(token) <= DYN_TAG_MAX:
        _DYN.append((token, tag))
    return value

def dyn_all_unique(payload):
    """Все ли помеченные поля встречаются в пакете ровно один раз."""
    return all(payload.count(token) == 1 for token, _ in _DYN)


def build_tagged_line(payload):
    """Строка I: статические куски <b 0x..> вперемешку с тегами помеченных полей."""
    holes = []
    for token, tag in _DYN:
        # Неуникальное вхождение пропускаем: разные вхождения одного поля
        # обязаны совпадать, а два тега дали бы разные значения.
        if payload.count(token) != 1:
            continue
        holes.append((payload.find(token), len(token), tag))
    holes.sort()
    out = []
    pos = 0
    for start, length, tag in holes:
        if start < pos:                 # перекрытие с уже вставленным тегом
            continue
        if start > pos:
            out.append("<b 0x%s>" % to_hex(payload[pos:start]))
        out.append("<%s %d>" % (tag, length))
        pos = start + length
    if pos < len(payload):
        out.append("<b 0x%s>" % to_hex(payload[pos:]))
    return "".join(out)

def quic_varint(value):
    # encodeQuicVarInt (RFC 9000 §16)
    if value < 0:
        raise ValueError("QUIC varint cannot encode a negative value")
    if value < 64:
        return bytes([value])
    if value < 16384:
        return bytes([0x40 | ((value >> 8) & 0x3F), value & 0xFF])
    if value < 1073741824:
        return bytes([0x80 | ((value >> 24) & 0x3F), (value >> 16) & 0xFF,
                      (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError("QUIC value is too large to encode in this utility")

def crc32_stun(data):
    # crc32 из generators.js (полином 0xEDB88320, тот же, что в zlib)
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return (~crc) & 0xFFFFFFFF

def ntp_timestamp(epoch_seconds=None):
    # encodeNtpTimestamp: секунды с 1900 + дробная часть в 2^-32
    ms = int((epoch_seconds if epoch_seconds is not None else time.time()) * 1000)
    seconds = (ms // 1000) + 2208988800
    fraction = int(((ms % 1000) / 1000.0) * 0x100000000) & 0xFFFFFFFF
    return u32(seconds) + u32(fraction)

def random_private_ipv4():
    pools = [
        [10, ri(256), ri(256), 10 + ri(200)],
        [172, 16 + ri(16), ri(256), 10 + ri(200)],
        [192, 168, ri(256), 10 + ri(200)],
    ]
    return ".".join(str(x) for x in rc(pools))

# == Константы (app.js: CONFIG / CHROME_BROWSER_DATA, generators.js: пулы) ==
DEFAULT_HOST = "yastatic.net"          # запасной хост, если домен не передали
DEFAULT_MTU = 1280                     # CONFIG.defaultMtu
MAX_OUTPUT_LINES = 5                   # CONFIG.maxOutputLines (I1-I5)

# Резервный пул на случай, когда домен не передали (например, вызов из бота).
# Список payloadGen (ya.ru, gosuslugi.ru, vk.com, ...) отсюда убран намеренно:
# он одинаков у всех пользователей того генератора, поэтому сам является
# признаком. Здесь — инфраструктурные хосты с постоянным фоновым трафиком.
# Тот же список продублирован в awg2 как CPS_RU_DOMAINS, где он ещё и
# проверяется на доступность перед генерацией.
RU_DOMAIN_POOL = [
    "yastatic.net", "mc.yandex.ru", "avatars.mds.yandex.net",
    "ok.ru", "st.mycdn.me", "vk.ru",
    "kinopoisk.ru", "hh.ru", "2gis.ru", "lenta.ru", "mos.ru", "citilink.ru",
]

CHROME_DEFAULT_VERSION = "147.0.7727.50"   # CHROME_BROWSER_DATA.defaultVersion

SSDP_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
]
SSDP_USER_AGENTS = [
    "Microsoft-Windows/10.0 UPnP/1.0 SSDP-Discovery/1.0",
    "macOS/14.7.6 UPnP/1.1 ControlPoint/1.0",
    "Linux/6.8 UPnP/1.1 Portable SDK for UPnP devices/1.14.18",
]

DNS_QUERY_TYPES = [0x0001, 0x001C, 0x0041]

TWILIO_STUN_SERVERS = ["global.stun.twilio.com"]
TWILIO_TURN_SERVERS = [
    "global.turn.twilio.com", "de01-1.turn.twilio.com", "de01-2.turn.twilio.com",
    "sg01-1.turn.twilio.com", "sg01-2.turn.twilio.com", "us1-1.turn.twilio.com",
    "us1-2.turn.twilio.com", "us2-1.turn.twilio.com", "us2-2.turn.twilio.com",
    "ie01-1.turn.twilio.com", "ie01-2.turn.twilio.com", "jp01-1.turn.twilio.com",
    "jp01-2.turn.twilio.com", "au01-1.turn.twilio.com", "br01-1.turn.twilio.com",
    "in01-1.turn.twilio.com",
]
TWILIO_REALM = "twilio.com"
GOOGLE_STUN_SERVERS = [
    "stun.l.google.com", "stun1.l.google.com", "stun2.l.google.com",
    "stun3.l.google.com", "stun4.l.google.com", "stun.services.googleapis.com",
    "stun.phonebox.google.com", "stun.stunprotocol.org",
]
CLOUDFLARE_WEBRTC_SERVERS = [
    "turn.cloudflare.com", "webrtc.cloudflare.net",
    "spectrum.cloudflare.com", "calls.cloudflare.com",
]
CLOUDFLARE_REALM = "cloudflare.com"
META_WEBRTC_SERVERS = [
    "turn.instagram.com", "stun.whatsapp.com", "edge-turn.whatsapp.com",
    "turn-messenger.whatsapp.com", "star.c10r.facebook.com",
    "turn.dnsalias.com", "edge-chat.facebook.com",
]
META_REALM = "facebook.com"

SIP_USER_AGENTS = [
    "Linphone/5.2.5 (belle-sip/5.3.90)", "Zoiper rv2.10.15-mod",
    "MicroSIP/3.21.6", "baresip 3.8.0", "Blink 6.0.4 (Windows)",
    "Asterisk PBX 20.7.0",
]
SIP_SERVER_NAMES = [
    "Kamailio (5.8.1)", "OpenSIPS (3.5.1)", "Asterisk PBX (20.7.0)",
    "FreeSWITCH (1.10.12)", "Yate SIP Router (7.0.0)",
]
SIP_DISPLAY_NAMES = [
    "Alice Carter", "Bob Smith", "Support Desk", "Sales Queue",
    "NOC Bridge", "Reception", "Operator", "Dispatch",
]
SIP_ACCEPT_LANGUAGES = [
    "en", "en-US", "en-US,en;q=0.9",
    "tr-TR,tr;q=0.9,en;q=0.7", "de-DE,de;q=0.8,en;q=0.6",
]
SIP_SUPPORTED_HEADERS = [
    "replaces, outbound, path, timer",
    "outbound, path, gruu, 100rel",
    "timer, replaces, resource-priority",
    "gruu, outbound, path, sec-agree",
]
SIP_ALLOW_HEADERS = [
    "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, INFO, MESSAGE, SUBSCRIBE",
    "INVITE, ACK, CANCEL, OPTIONS, BYE, UPDATE, MESSAGE",
    "INVITE, ACK, CANCEL, OPTIONS, BYE, PRACK, UPDATE",
]
SIP_ALLOW_EVENTS_HEADERS = [
    "presence, message-summary, refer",
    "dialog, presence, refer",
    "presence, kpml, talk",
]
SIP_DOMAIN_PREFIXES = ["sip", "voip", "pbx", "edge", "gw", "proxy", "media", "trunk"]
SIP_DOMAIN_BASES = ["biloxi", "atlanta", "voicehub", "carriernet", "softswitch",
                    "callbridge", "telecloud", "voiplab"]
SIP_DOMAIN_SUFFIXES = ["com", "net", "org", "io", "cloud"]
SIP_LOCAL_PORTS = [5060, 5062, 5070, 5080, 5160]
SIP_AUDIO_CODEC_PROFILES = [
    {"payloads": ["0 PCMU/8000", "8 PCMA/8000", "96 opus/48000/2",
                  "101 telephone-event/8000"], "formatList": "0 8 96 101"},
    {"payloads": ["0 PCMU/8000", "18 G729/8000", "101 telephone-event/8000"],
     "formatList": "0 18 101"},
    {"payloads": ["8 PCMA/8000", "97 iLBC/8000", "101 telephone-event/8000"],
     "formatList": "8 97 101"},
]

# QUIC v1 (RFC 9000/9001): версия на проводе и база первого байта Initial
QUIC_WIRE_VERSION = 0x00000001
QUIC_INITIAL_HEADER_BASE = 0xC0
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
CURL_QUIC_PROFILE_ID = "curl_h3"

# ================================================================
# Криптография (порт crypto.js). Всё опционально: без python3-cryptography
# генератор продолжает работать, но QUIC Initial уходит без шифрования,
# а ECH — без реального HPKE. Об этом честно пишется в stderr.
# ================================================================
_CRYPTO_OK = True
try:
    import hmac as _hmac
    import hashlib as _hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# BaseException, а не Exception: при поломанной сборке python3-cryptography
# (нет _cffi_backend, рассинхрон с pyo3 после частичного обновления) импорт
# падает с PanicException, а она наследуется напрямую от BaseException и мимо
# "except Exception" проходит насквозь. Тогда умирал ВЕСЬ генератор, и клиенты
# оставались без I1-I5 вообще — вместо честной деградации «QUIC без шифрования».
except BaseException:
    _CRYPTO_OK = False

def crypto_available():
    if not _CRYPTO_OK:
        _warn_once("нет python3-cryptography: QUIC Initial уйдёт без шифрования, "
                   "ECH — без HPKE. Ставится так: apt-get install -y python3-cryptography")
    return _CRYPTO_OK

def hkdf_extract(salt, ikm):
    return _hmac.new(salt, ikm, _hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    # RFC 5869 HKDF-Expand на SHA-256
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = _hmac.new(prk, block + info + bytes([counter]), _hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]

def hkdf_expand_label(secret, label, context, length):
    # RFC 8446 §7.1 HKDF-Expand-Label
    label_bytes = enc_text("tls13 " + label)
    info = u16(length) + bytes([len(label_bytes)]) + label_bytes + \
           bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)

def aes_gcm_encrypt(key, nonce, plaintext, aad):
    return AESGCM(key).encrypt(nonce, plaintext, aad)

def aes_ecb_encrypt_block(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (enc.update(block) + enc.finalize())[:16]

# -- HPKE (RFC 9180), режим base, DHKEM(X25519, HKDF-SHA256) --
HPKE_VERSION_LABEL = b"HPKE-v1"
HPKE_SUITE_PREFIX = b"HPKE"
HPKE_KEM_PREFIX = b"KEM"
HPKE_MODE_BASE = 0x00

def _hpke_aead_params(aead_id):
    if aead_id == 0x0001:
        return 16, 12, 16     # AES-128-GCM
    if aead_id == 0x0002:
        return 32, 12, 16     # AES-256-GCM
    raise ValueError("unsupported HPKE AEAD id: %s" % aead_id)

def _hpke_labeled_extract(salt, suite_id, label, ikm):
    return hkdf_extract(salt, HPKE_VERSION_LABEL + suite_id + enc_text(label) + ikm)

def _hpke_labeled_expand(prk, suite_id, label, info, length):
    return hkdf_expand(prk, u16(length) + HPKE_VERSION_LABEL + suite_id +
                       enc_text(label) + info, length)

def hpke_setup_base_sender(recipient_public_key, info, kem_id, kdf_id, aead_id):
    """
    Возвращает контекст отправителя: enc (эфемерный публичный ключ), key,
    base_nonce. Порт hpkeSetupBaseSender из crypto.js.
    """
    if kem_id != 0x0020 or kdf_id != 0x0001:
        raise ValueError("unsupported HPKE KEM/KDF: %s/%s" % (kem_id, kdf_id))
    key_len, nonce_len, tag_len = _hpke_aead_params(aead_id)
    suite_id = HPKE_SUITE_PREFIX + u16(kem_id) + u16(kdf_id) + u16(aead_id)
    kem_suite_id = HPKE_KEM_PREFIX + u16(kem_id)

    private_key = X25519PrivateKey.generate()
    enc = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = private_key.exchange(
        X25519PublicKey.from_public_bytes(recipient_public_key))

    eae_prk = _hpke_labeled_extract(b"", kem_suite_id, "eae_prk", shared)
    shared_secret = _hpke_labeled_expand(eae_prk, kem_suite_id, "shared_secret",
                                         enc + recipient_public_key, 32)
    psk_id_hash = _hpke_labeled_extract(b"", suite_id, "psk_id_hash", b"")
    info_hash = _hpke_labeled_extract(b"", suite_id, "info_hash", info)
    key_schedule_context = bytes([HPKE_MODE_BASE]) + psk_id_hash + info_hash
    secret = _hpke_labeled_extract(shared_secret, suite_id, "secret", b"")

    return {
        "enc": enc,
        "key": _hpke_labeled_expand(secret, suite_id, "key", key_schedule_context, key_len),
        "base_nonce": _hpke_labeled_expand(secret, suite_id, "base_nonce",
                                           key_schedule_context, nonce_len),
        "tag_length": tag_len,
    }

def hpke_seal(context, aad, plaintext):
    return aes_gcm_encrypt(context["key"], context["base_nonce"], plaintext, aad)

# ================================================================
# TLS ClientHello (generators.js: buildClientHelloBody + build*Extension)
# Порядок расширений задаётся отпечатком (extensionOrder) — именно он и есть
# JA3/JA4 клиента, поэтому переставлять их нельзя.
# ================================================================
GREASE_VALUES = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
]

def select_grease_value(excluded=None):
    filtered = [v for v in GREASE_VALUES if v != excluded] or GREASE_VALUES
    return rc(filtered)

def chrome_fingerprint(is_quic):
    # resolveTlsFingerprint: профиль Chrome (браузерный ClientHello)
    return {
        "useGrease": True,
        "useSecondaryGrease": True,
        "cipherSuites": [0x1301, 0x1302, 0x1303] if is_quic else [
            0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
            0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
        "extensionOrder": [
            "grease", "sni", "supported_groups", "alpn", "status_request",
            "signature_algorithms", "sct", "supported_versions", "key_share",
            "psk_modes", "quic_transport_parameters", "compress_certificate",
            "secondary_grease", "padding",
        ] if is_quic else [
            "grease", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket", "alpn",
            "status_request", "signature_algorithms", "sct", "supported_versions",
            "key_share", "psk_modes", "compress_certificate",
            "application_settings", "secondary_grease", "padding",
        ],
        "supportedGroups": [0x001D, 0x0017, 0x0018],
        "signatureAlgorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                                0x0501, 0x0806, 0x0601, 0x0807],
        "supportedVersions": [0x0304] if is_quic else [0x0304, 0x0303],
        "keyShares": [0x001D],
        "compressCertificateAlgorithms": [0x0002],
        "includeApplicationSettings": True,
        "paddingTarget": 512,
        "encryptedClientHello": None,
        "maxUdpPayloadSize": 1472,
        "activeConnectionIdLimit": 8,
    }

def curl_quic_fingerprint():
    # createCapturedCurlQuicFingerprint: снятый с curl --http3 ClientHello.
    # Без GREASE и с другим порядком transport parameters — это отдельный
    # отпечаток, а не вариация Chrome.
    return {
        "useGrease": False,
        "useSecondaryGrease": False,
        "cipherSuites": [0x1301],
        "extensionOrder": [
            "sni", "supported_versions", "supported_groups",
            "signature_algorithms", "alpn", "key_share", "psk_modes",
            "quic_transport_parameters", "compress_certificate",
            "encrypted_client_hello",
        ],
        "supportedGroups": [0x001D, 0x0017, 0x0018],
        "signatureAlgorithms": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806],
        "supportedVersions": [0x0304],
        "keyShares": [0x001D],
        "compressCertificateAlgorithms": [0x0002],
        "includeApplicationSettings": False,
        "paddingTarget": 0,
        "encryptedClientHello": None,
        "quicTransportParameterOrder": [0x03, 0x07, 0x05, 0x09, 0x01,
                                        0x08, 0x0F, 0x0E, 0x06, 0x04],
        "maxIdleTimeout": 30000,
        "maxUdpPayloadSize": 1472,
        "initialMaxData": 10485760,
        "initialMaxStreamDataBidiLocal": 5242880,
        "initialMaxStreamDataBidiRemote": 5242880,
        "initialMaxStreamDataUni": 5242880,
        "initialMaxStreamsBidi": 100,
        "initialMaxStreamsUni": 100,
        "activeConnectionIdLimit": 2,
    }

def resolve_tls_fingerprint(is_quic, profile_id=None):
    if is_quic and profile_id == CURL_QUIC_PROFILE_ID:
        return curl_quic_fingerprint()
    return chrome_fingerprint(is_quic)

def _fp_num(fingerprint, key, default_value):
    value = fingerprint.get(key)
    return value if isinstance(value, int) else default_value

def ext(ext_type, data):
    return u16(ext_type) + u16(len(data)) + data

def ext_server_name(host):
    host_bytes = enc_text(host)
    server_name = b"\x00" + u16(len(host_bytes)) + host_bytes
    return ext(0x0000, u16(len(server_name)) + server_name)

def ext_alpn(protocols):
    entries = b""
    for protocol in protocols:
        pb = enc_text(protocol)
        entries += bytes([len(pb)]) + pb
    return ext(0x0010, u16(len(entries)) + entries)

def ext_supported_versions(grease_value, versions):
    body = b""
    if grease_value is not None:
        body += u16(grease_value)
    for version in (versions or [0x0304, 0x0303]):
        body += u16(version)
    return u16(0x002B) + u16(len(body) + 1) + bytes([len(body)]) + body

def ext_supported_groups(grease_value, groups):
    body = b""
    if grease_value is not None:
        body += u16(grease_value)
    for group in (groups or [0x001D, 0x0017, 0x0018]):
        body += u16(group)
    return u16(0x000A) + u16(len(body) + 2) + u16(len(body)) + body

def ext_signature_algorithms(signature_algorithms=None):
    body = b""
    for algorithm in (signature_algorithms or [0x0403, 0x0804, 0x0401, 0x0503,
                                               0x0805, 0x0501, 0x0806, 0x0601, 0x0807]):
        body += u16(algorithm)
    return u16(0x000D) + u16(len(body) + 2) + u16(len(body)) + body

def ext_ec_point_formats():
    return u16(0x000B) + u16(2) + b"\x01\x00"

def ext_psk_modes():
    return u16(0x002D) + u16(2) + b"\x01\x01"

def key_share_value(group):
    if group == 0x0017:
        return b"\x04" + rb(64)
    if group == 0x0018:
        return b"\x04" + rb(96)
    return rb(32)

def ext_key_share(grease_value, groups):
    entries = b""
    if grease_value is not None:
        entries += u16(grease_value) + u16(1) + b"\x00"
    for group in (groups or [0x001D]):
        kb = key_share_value(group)
        entries += u16(group) + u16(len(kb)) + kb
    return u16(0x0033) + u16(len(entries) + 2) + u16(len(entries)) + entries

def ext_extended_master_secret():
    return u16(0x0017) + u16(0)

def ext_renegotiation_info():
    return u16(0xFF01) + u16(1) + b"\x00"

def ext_session_ticket():
    return u16(0x0023) + u16(0)

def ext_status_request():
    return ext(0x0005, b"\x01" + u16(0) + u16(0))

def ext_sct():
    return u16(0x0012) + u16(0)

def ext_compress_certificate(algorithms):
    encoded = b""
    for algorithm in (algorithms or [0x0002]):
        encoded += u16(algorithm)
    return ext(0x001B, bytes([len(encoded)]) + encoded)

def ext_application_settings(protocols):
    entries = b""
    for protocol in protocols:
        pb = enc_text(protocol)
        entries += bytes([len(pb)]) + pb
    return u16(0x4469) + u16(len(entries) + 2) + u16(len(entries)) + entries

def ext_encrypted_client_hello(config):
    # buildEncryptedClientHelloExtension: inner ClientHello несёт один байт
    # типа, outer — полный набор (kdf/aead/config_id/enc/payload).
    if config and config.get("clientHelloType") == 0x01:
        return u16(0xFE0D) + u16(1) + b"\x01"
    enc_key = config.get("enc") or b"" if config else b""
    payload = config.get("payload") or b"" if config else b""
    data = (bytes([config.get("clientHelloType", 0x00) if config else 0x00]) +
            u16(config.get("kdfId", 0x0001) if config else 0x0001) +
            u16(config.get("aeadId", 0x0001) if config else 0x0001) +
            bytes([config.get("configId", 0x00) if config else 0x00]) +
            u16(len(enc_key)) + enc_key +
            u16(len(payload)) + payload)
    return ext(0xFE0D, data)

def ext_quic_transport_parameters(source_connection_id, fingerprint):
    order = fingerprint.get("quicTransportParameterOrder") or [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E, 0x0F]
    values = {
        0x01: quic_varint(_fp_num(fingerprint, "maxIdleTimeout", 30000)),
        0x03: quic_varint(_fp_num(fingerprint, "maxUdpPayloadSize", 1472)),
        0x04: quic_varint(_fp_num(fingerprint, "initialMaxData", 15728640)),
        0x05: quic_varint(_fp_num(fingerprint, "initialMaxStreamDataBidiLocal", 6291456)),
        0x06: quic_varint(_fp_num(fingerprint, "initialMaxStreamDataBidiRemote", 6291456)),
        0x07: quic_varint(_fp_num(fingerprint, "initialMaxStreamDataUni", 6291456)),
        0x08: quic_varint(_fp_num(fingerprint, "initialMaxStreamsBidi", 100)),
        0x09: quic_varint(_fp_num(fingerprint, "initialMaxStreamsUni", 100)),
        0x0A: quic_varint(_fp_num(fingerprint, "ackDelayExponent", 3)),
        0x0B: quic_varint(_fp_num(fingerprint, "maxAckDelay", 25)),
        0x0E: quic_varint(_fp_num(fingerprint, "activeConnectionIdLimit", 8)),
        0x0F: source_connection_id,
    }
    parameters = b""
    for parameter_id in order:
        value = b"" if parameter_id == 0x0C else values[parameter_id]
        parameters += quic_varint(parameter_id) + quic_varint(len(value)) + value
    return ext(0x0039, parameters)

def ext_padding(padding_length):
    if padding_length <= 0:
        return b""
    return u16(0x0015) + u16(padding_length) + zeros(padding_length)

def ext_grease(grease_value):
    return u16(grease_value) + u16(0)

def ext_use_srtp():
    profiles = u16(2) + u16(0x0001) + b"\x00"
    return ext(0x000E, profiles)

def calculate_tls_padding_length(parts, target_size):
    # calculateTlsPaddingLength: формула оригинала, константа 4+2+32+1+32+2+32+2+2
    if not target_size:
        return 0
    current = sum(len(p) for p in parts)
    return max(0, target_size - (4 + 2 + 32 + 1 + 32 + 2 + 32 + 2 + 2) - current - 4)

def resolve_alpn_protocols(protocol, is_quic):
    if is_quic:
        return [protocol]
    if protocol == "h2":
        return ["h2", "http/1.1"]
    return [protocol]

def build_tls_extensions(host, opts):
    fingerprint = opts["fingerprint"]
    is_quic = opts.get("isQuic", False)
    grease_value = opts.get("greaseValue")
    parts = []

    for name in fingerprint["extensionOrder"]:
        if name == "grease" and grease_value is not None:
            parts.append(ext_grease(grease_value))
        elif name == "sni":
            parts.append(ext_server_name(host))
        elif name == "extended_master_secret":
            parts.append(ext_extended_master_secret())
        elif name == "renegotiation_info":
            parts.append(ext_renegotiation_info())
        elif name == "supported_groups":
            parts.append(ext_supported_groups(grease_value, fingerprint["supportedGroups"]))
        elif name == "ec_point_formats":
            parts.append(ext_ec_point_formats())
        elif name == "session_ticket":
            parts.append(ext_session_ticket())
        elif name == "alpn" and opts.get("alpnProtocol"):
            parts.append(ext_alpn(resolve_alpn_protocols(opts["alpnProtocol"], is_quic)))
        elif name == "status_request":
            parts.append(ext_status_request())
        elif name == "signature_algorithms":
            parts.append(ext_signature_algorithms(fingerprint["signatureAlgorithms"]))
        elif name == "sct":
            parts.append(ext_sct())
        elif name == "supported_versions" and opts.get("withTls13"):
            parts.append(ext_supported_versions(grease_value, fingerprint["supportedVersions"]))
        elif name == "key_share":
            parts.append(ext_key_share(grease_value, fingerprint["keyShares"]))
        elif name == "psk_modes":
            parts.append(ext_psk_modes())
        elif name == "quic_transport_parameters" and opts.get("withQuicTransportParameters"):
            parts.append(ext_quic_transport_parameters(
                opts.get("quicSourceConnectionId") or b"", fingerprint))
        elif name == "compress_certificate" and opts.get("withTls13") and \
                fingerprint["compressCertificateAlgorithms"]:
            parts.append(ext_compress_certificate(fingerprint["compressCertificateAlgorithms"]))
        elif name == "application_settings" and not is_quic and \
                opts.get("alpnProtocol") == "h2" and fingerprint["includeApplicationSettings"]:
            parts.append(ext_application_settings(["h2"]))
        elif name == "encrypted_client_hello" and fingerprint.get("encryptedClientHello"):
            parts.append(ext_encrypted_client_hello(fingerprint["encryptedClientHello"]))
        elif name == "secondary_grease" and opts.get("secondaryGreaseValue") is not None:
            parts.append(ext_grease(opts["secondaryGreaseValue"]))
        elif name == "padding":
            padding_length = calculate_tls_padding_length(parts, fingerprint["paddingTarget"])
            if padding_length > 0:
                parts.append(ext_padding(padding_length))

    return b"".join(parts)

def build_client_hello_body(host, opts):
    """
    Возвращает handshake-сообщение ClientHello целиком: 0x01 + длина + тело.
    Порт buildClientHelloBody.
    """
    is_quic = bool(opts.get("withQuicTransportParameters"))
    fingerprint = opts.get("fingerprintOverride") or \
        resolve_tls_fingerprint(is_quic, opts.get("tlsFingerprintProfile"))
    grease_value = opts["greaseValue"] if "greaseValue" in opts else (
        select_grease_value() if fingerprint["useGrease"] else None)
    secondary_grease = opts["secondaryGreaseValue"] if "secondaryGreaseValue" in opts else (
        select_grease_value(grease_value) if fingerprint["useSecondaryGrease"] else None)
    session_id = opts["sessionIdBytes"] if opts.get("sessionIdBytes") is not None else rb(32)
    client_random = opts.get("clientRandom") or rb(32)

    extensions = build_tls_extensions(host, {
        "withTls13": bool(opts.get("withTls13")),
        "alpnProtocol": opts.get("alpnProtocol"),
        "greaseValue": grease_value,
        "secondaryGreaseValue": secondary_grease,
        "isQuic": is_quic,
        "withQuicTransportParameters": bool(opts.get("withQuicTransportParameters")),
        "quicSourceConnectionId": opts.get("quicSourceConnectionId") or b"",
        "fingerprint": fingerprint,
    })

    cipher_suites = b""
    if grease_value is not None:
        cipher_suites += u16(grease_value)
    for suite in fingerprint["cipherSuites"]:
        cipher_suites += u16(suite)

    body = (u16(opts["legacyVersion"]) + client_random +
            bytes([len(session_id)]) + session_id +
            u16(len(cipher_suites)) + cipher_suites +
            b"\x01\x00" + u16(len(extensions)) + extensions)
    return b"\x01" + u24(len(body)) + body

# ================================================================
# ECHConfig (generators.js: parseEchConfig* / serializeEchConfig)
# ================================================================
def serialize_ech_config(definition):
    public_key = definition["publicKey"]
    public_name_bytes = enc_text(definition["publicName"])
    cipher_suites = b""
    for suite in definition["cipherSuites"]:
        cipher_suites += u16(suite["kdfId"]) + u16(suite["aeadId"])
    contents = (bytes([definition["configId"] & 0xFF]) +
                u16(definition["kemId"]) +
                u16(len(public_key)) + public_key +
                u16(len(cipher_suites)) + cipher_suites +
                bytes([min(255, definition.get("maximumNameLength") or len(public_name_bytes))]) +
                bytes([len(public_name_bytes)]) + public_name_bytes +
                u16(0))
    return u16(0xFE0D) + u16(len(contents)) + contents

def build_ech_config_descriptor(definition):
    suites = definition.get("cipherSuites") or [{"kdfId": 0x0001, "aeadId": 0x0001}]
    selected = select_supported_cipher_suite(suites) or {"kdfId": 0x0001, "aeadId": 0x0001}
    return {
        "configId": definition["configId"],
        "kemId": definition["kemId"],
        "kdfId": selected["kdfId"],
        "aeadId": selected["aeadId"],
        "publicKey": definition["publicKey"],
        "maximumNameLength": definition["maximumNameLength"],
        "publicName": definition["publicName"],
        "rawBytes": serialize_ech_config({
            "configId": definition["configId"],
            "kemId": definition["kemId"],
            "publicKey": definition["publicKey"],
            "maximumNameLength": definition["maximumNameLength"],
            "publicName": definition["publicName"],
            "cipherSuites": suites,
        }),
    }

def select_supported_cipher_suite(cipher_suites):
    for suite in cipher_suites or []:
        if suite.get("kdfId") == 0x0001 and suite.get("aeadId") in (0x0001, 0x0002):
            return suite
    return None

def parse_ech_config_list(data):
    configs = []
    if len(data) < 2:
        return configs
    total_length = read_u16(data, 0)
    end = min(len(data), 2 + total_length)
    offset = 2
    while offset + 4 <= end:
        config_start = offset
        version = read_u16(data, offset)
        content_length = read_u16(data, offset + 2)
        content_start = offset + 4
        content_end = content_start + content_length
        if content_end > end:
            break
        if version == 0xFE0D:
            config = parse_ech_config(data, config_start, content_start, content_end)
            if config:
                configs.append(config)
        offset = content_end
    return configs

def parse_ech_config(data, config_start, content_start, content_end):
    offset = content_start
    if offset + 5 > content_end:
        return None
    config_id = data[offset]
    offset += 1
    kem_id = read_u16(data, offset)
    offset += 2
    public_key_length = read_u16(data, offset)
    offset += 2
    if offset + public_key_length > content_end:
        return None
    public_key = data[offset:offset + public_key_length]
    offset += public_key_length
    if offset + 2 > content_end:
        return None
    cipher_suites_length = read_u16(data, offset)
    offset += 2
    suite_end = offset + cipher_suites_length
    if suite_end > content_end:
        return None
    cipher_suites = []
    while offset + 4 <= suite_end:
        cipher_suites.append({"kdfId": read_u16(data, offset),
                              "aeadId": read_u16(data, offset + 2)})
        offset += 4
    if offset + 2 > content_end:
        return None
    maximum_name_length = data[offset]
    offset += 1
    public_name_length = data[offset]
    offset += 1
    if offset + public_name_length > content_end:
        return None
    public_name = data[offset:offset + public_name_length].decode("utf-8", "replace")
    selected = select_supported_cipher_suite(cipher_suites)
    if not selected:
        return None
    return {
        "configId": config_id,
        "kemId": kem_id,
        "kdfId": selected["kdfId"],
        "aeadId": selected["aeadId"],
        "publicKey": public_key,
        "maximumNameLength": maximum_name_length,
        "publicName": public_name,
        "rawBytes": data[config_start:content_end],
    }

def select_supported_ech_config(configs):
    for config in configs or []:
        if config["kemId"] == 0x0020 and config["kdfId"] == 0x0001 and \
                config["aeadId"] in (0x0001, 0x0002):
            return config
    return None

def create_synthetic_ech_config(host):
    """
    Синтетический ECHConfig: ключ генерируем сами. Для наблюдателя структура
    расширения неотличима от настоящего ECH — расшифровать его всё равно может
    только владелец приватного ключа, и им никто не пользуется.
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return build_ech_config_descriptor({
        "configId": rb(1)[0],
        "kemId": 0x0020,
        "publicKey": public_key,
        "maximumNameLength": min(255, len(host)),
        "publicName": host,
        "cipherSuites": [{"kdfId": 0x0001, "aeadId": 0x0001}],
    })

def fetch_published_ech_config(host, timeout=2.0):
    """
    Настоящий ECHConfig из HTTPS RR через DoH (как fetchPublishedEchConfig).
    Включается флагом --ech-doh или AWG_CPS_ECH_DOH=1: запрос уходит наружу,
    поэтому по умолчанию выключен, а при любой ошибке/таймауте возвращается
    None и берётся синтетический конфиг.
    """
    import base64, json, re, urllib.parse, urllib.request
    url = "https://dns.google/resolve?name=%s&type=HTTPS" % urllib.parse.quote(host)
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:
        _warn_once("DoH-запрос ECHConfig не удался (%s) — берём синтетический ECH"
                   % type(exc).__name__)
        return None
    for answer in payload.get("Answer") or []:
        match = re.search(r"\bech=\"?([^\"\s]+)\"?", str(answer.get("data") or ""), re.I)
        if not match:
            continue
        try:
            raw = base64.b64decode(match.group(1) + "==")
        except Exception:
            continue
        config = select_supported_ech_config(parse_ech_config_list(raw))
        if config:
            return config
    return None

def resolve_ech_config(host, use_doh):
    if use_doh:
        config = fetch_published_ech_config(host)
        if config:
            return config
    return create_synthetic_ech_config(host)

# ================================================================
# QUIC Initial (generators.js: generateQuicPayload* + crypto.js)
# ================================================================
def build_quic_client_hello(host, options, scid):
    return build_client_hello_body(host, {
        "legacyVersion": 0x0303,
        "withTls13": True,
        "alpnProtocol": "h3",
        "withQuicTransportParameters": True,
        "quicSourceConnectionId": scid,
        "tlsFingerprintProfile": options.get("tlsFingerprintProfile"),
    })

def build_ech_quic_client_hello(host, options, scid):
    """
    ClientHello с настоящим ECH: внутренний ClientHello (реальный SNI)
    шифруется HPKE и кладётся во внешний, где SNI — public_name конфига.
    Порт buildDynamicEchQuicClientHello.
    """
    ech_config = options["echConfig"]
    base_fingerprint = resolve_tls_fingerprint(True, options.get("tlsFingerprintProfile"))

    inner_fingerprint = dict(base_fingerprint)
    inner_fingerprint["extensionOrder"] = list(base_fingerprint["extensionOrder"])
    if "encrypted_client_hello" not in inner_fingerprint["extensionOrder"]:
        inner_fingerprint["extensionOrder"].append("encrypted_client_hello")
    inner_fingerprint["encryptedClientHello"] = {"clientHelloType": 0x01}

    encoded_inner = build_client_hello_body(host, {
        "legacyVersion": 0x0303,
        "withTls13": True,
        "alpnProtocol": "h3",
        "withQuicTransportParameters": True,
        "quicSourceConnectionId": scid,
        "fingerprintOverride": inner_fingerprint,
        "sessionIdBytes": b"",
    })[4:]

    host_length = len(enc_text(host))
    max_name_length = ech_config["maximumNameLength"] or host_length
    padding_length = max(0, max_name_length - host_length)
    padded_length = len(encoded_inner) + padding_length
    padding_length += (32 - (padded_length % 32)) % 32
    padded_inner = encoded_inner + zeros(padding_length)

    context = hpke_setup_base_sender(
        ech_config["publicKey"],
        b"tls ech" + b"\x00" + ech_config["rawBytes"],
        ech_config["kemId"], ech_config["kdfId"], ech_config["aeadId"])

    outer_fingerprint = dict(base_fingerprint)
    outer_fingerprint["extensionOrder"] = list(base_fingerprint["extensionOrder"])
    if "encrypted_client_hello" not in outer_fingerprint["extensionOrder"]:
        outer_fingerprint["extensionOrder"].append("encrypted_client_hello")
    outer_fingerprint["encryptedClientHello"] = {
        "clientHelloType": 0x00,
        "kdfId": ech_config["kdfId"],
        "aeadId": ech_config["aeadId"],
        "configId": ech_config["configId"],
        "enc": context["enc"],
        "payload": zeros(len(padded_inner) + context["tag_length"]),
    }

    outer = build_client_hello_body(ech_config["publicName"] or host, {
        "legacyVersion": 0x0303,
        "withTls13": True,
        "alpnProtocol": "h3",
        "withQuicTransportParameters": True,
        "quicSourceConnectionId": scid,
        "fingerprintOverride": outer_fingerprint,
    })

    ech_payload = hpke_seal(context, outer[4:], padded_inner)
    return replace_ech_payload(outer, ech_payload)

def find_ech_payload_offset(client_hello):
    offset = 4 + 2 + 32
    session_id_length = client_hello[offset]
    offset += 1 + session_id_length
    cipher_suites_length = read_u16(client_hello, offset)
    offset += 2 + cipher_suites_length
    compression_methods_length = client_hello[offset]
    offset += 1 + compression_methods_length
    extensions_length = read_u16(client_hello, offset)
    offset += 2
    extensions_end = offset + extensions_length
    while offset + 4 <= extensions_end:
        extension_type = read_u16(client_hello, offset)
        extension_length = read_u16(client_hello, offset + 2)
        data_offset = offset + 4
        if extension_type == 0xFE0D:
            enc_length = read_u16(client_hello, data_offset + 1 + 2 + 2 + 1)
            payload_length_offset = data_offset + 1 + 2 + 2 + 1 + 2 + enc_length
            payload_length = read_u16(client_hello, payload_length_offset)
            return payload_length_offset + 2, payload_length
        offset = data_offset + extension_length
    raise ValueError("ECH extension was not found in ClientHello")

def replace_ech_payload(client_hello, ech_payload):
    offset, length = find_ech_payload_offset(client_hello)
    if length != len(ech_payload):
        raise ValueError("ECH payload length mismatch")
    data = bytearray(client_hello)
    data[offset:offset + length] = ech_payload
    return bytes(data)

def quic_crypto_frame(data, offset=0):
    return b"\x06" + quic_varint(offset) + quic_varint(len(data)) + data

def quic_initial_first_byte(packet_number_length):
    return QUIC_INITIAL_HEADER_BASE | ((packet_number_length - 1) & 0x03)

def resolve_quic_target_packet_size(options):
    if options.get("quicPadToMtu") and options.get("quicMtu"):
        return max(1200, int(options["quicMtu"]))
    if options.get("quicTargetPacketSize"):
        return max(1200, int(options["quicTargetPacketSize"]))
    return 1200

def calculate_quic_initial_padding(payload_length, dcid_length, scid_length,
                                   pn_length, target_packet_size, auth_tag_length):
    # RFC 9000 §14.1: датаграмма клиента с Initial обязана быть >= 1200 байт.
    # Длина поля length зависит от паддинга, поэтому считаем итеративно —
    # ровно как calculateQuicInitialPaddingLength в оригинале.
    target = max(1200, int(target_packet_size or 1200))
    header_prefix = 1 + 4 + 1 + dcid_length + 1 + scid_length + 1
    protected_length = pn_length + payload_length + max(0, int(auth_tag_length or 0))
    length_field_size = len(quic_varint(protected_length))
    previous = -1
    padding = 0
    while length_field_size != previous:
        previous = length_field_size
        padding = max(0, target - (header_prefix + length_field_size + protected_length))
        length_field_size = len(quic_varint(protected_length + padding))
    return max(0, target - (header_prefix + length_field_size + protected_length))

def pad_quic_initial_payload(payload, dcid, scid, packet_number, options, auth_tag_length):
    padding = calculate_quic_initial_padding(
        len(payload), len(dcid), len(scid), len(packet_number),
        resolve_quic_target_packet_size(options), auth_tag_length)
    return payload + zeros(padding) if padding > 0 else payload

def build_plain_quic_initial(dcid, scid, packet_number, payload):
    packet_length = len(packet_number) + len(payload)
    return (bytes([quic_initial_first_byte(len(packet_number))]) +
            u32(QUIC_WIRE_VERSION) +
            bytes([len(dcid)]) + dcid +
            bytes([len(scid)]) + scid +
            quic_varint(0) + quic_varint(packet_length) +
            packet_number + payload)

def build_protected_quic_initial(dcid, scid, packet_number, payload):
    # RFC 9001: ключи Initial выводятся из DCID, затем AEAD и header protection.
    initial_secret = hkdf_extract(QUIC_V1_INITIAL_SALT, dcid)
    client_secret = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(client_secret, "quic key", b"", 16)
    iv = hkdf_expand_label(client_secret, "quic iv", b"", 12)
    hp = hkdf_expand_label(client_secret, "quic hp", b"", 16)

    first_byte = quic_initial_first_byte(len(packet_number))
    packet_length = len(packet_number) + len(payload) + 16
    header = (bytes([first_byte]) + u32(QUIC_WIRE_VERSION) +
              bytes([len(dcid)]) + dcid +
              bytes([len(scid)]) + scid +
              quic_varint(0) + quic_varint(packet_length) + packet_number)

    nonce = bytearray(iv)
    for i, byte in enumerate(packet_number):
        nonce[len(nonce) - len(packet_number) + i] ^= byte
    encrypted = aes_gcm_encrypt(key, bytes(nonce), payload, header)

    sample_offset = 4 - len(packet_number)
    if sample_offset < 0 or len(encrypted) < sample_offset + 16:
        return header + encrypted
    mask = aes_ecb_encrypt_block(hp, encrypted[sample_offset:sample_offset + 16])
    protected = bytearray(header)
    protected[0] = first_byte ^ (mask[0] & 0x0F)
    for i in range(len(packet_number)):
        protected[len(protected) - len(packet_number) + i] = packet_number[i] ^ mask[i + 1]
    return bytes(protected) + encrypted

def generate_quic_payload(options):
    """
    QUIC Initial с ClientHello в CRYPTO-фрейме. С доступной криптографией
    пакет шифруется по RFC 9001 — тогда его содержимое для DPI неотличимо
    от шифротекста Chrome; без неё уходит нешифрованный Initial (fallback
    generateQuicPayload из оригинала).
    """
    dcid = rb(int(options.get("quicDcidLength", 8)))
    scid = rb(int(options.get("quicScidLength", 8)))
    packet_number = options.get("quicPacketNumber") or rb(int(options.get("quicPacketNumberLength", 4)))

    if options.get("echConfig") and crypto_available():
        try:
            client_hello = build_ech_quic_client_hello(options["host"], options, scid)
        except Exception as exc:
            _warn_once("сбой ECH (%s) — ClientHello уйдёт без него" % type(exc).__name__)
            client_hello = build_quic_client_hello(options["host"], options, scid)
    else:
        client_hello = build_quic_client_hello(options["host"], options, scid)

    crypto_frame = quic_crypto_frame(client_hello, 0)

    if not crypto_available():
        payload = pad_quic_initial_payload(crypto_frame, dcid, scid, packet_number, options, 0)
        return build_plain_quic_initial(dcid, scid, packet_number, payload)

    try:
        payload = pad_quic_initial_payload(crypto_frame, dcid, scid, packet_number, options, 16)
        return build_protected_quic_initial(dcid, scid, packet_number, payload)
    except Exception as exc:
        _warn_once("сбой шифрования QUIC (%s: %s) — Initial уйдёт без защиты"
                   % (type(exc).__name__, exc))
        payload = pad_quic_initial_payload(crypto_frame, dcid, scid, packet_number, options, 0)
        return build_plain_quic_initial(dcid, scid, packet_number, payload)

def generate_curl_quic_payload(options):
    # withCapturedCurlQuicProfile: curl шлёт пустой SCID, целевой размер 1250,
    # номер пакета 0x00 и ClientHello с ECH.
    merged = dict(options)
    merged.setdefault("tlsFingerprintProfile", CURL_QUIC_PROFILE_ID)
    merged["quicScidLength"] = merged.get("quicScidLength", 0)
    merged["quicTargetPacketSize"] = merged.get("quicTargetPacketSize", 1250)
    merged["quicPacketNumber"] = merged.get("quicPacketNumber", b"\x00")
    if crypto_available() and not merged.get("echConfig"):
        try:
            merged["echConfig"] = resolve_ech_config(merged["host"], merged.get("echDoh", False))
        except Exception as exc:
            _warn_once("не удалось подготовить ECHConfig (%s) — ClientHello без ECH"
                       % type(exc).__name__)
    return generate_quic_payload(merged)

# ================================================================
# DNS / SSDP / NTP / RTP / RTCP (generators.js)
# ================================================================
def encode_dns_name(name):
    trimmed = (name or DEFAULT_HOST).rstrip(".")
    out = b""
    for label in trimmed.split("."):
        label_bytes = enc_text(label)
        if not label_bytes or len(label_bytes) > 63:
            raise ValueError("each DNS label must be between 1 and 63 bytes")
        out += bytes([len(label_bytes)]) + label_bytes
    return out + b"\x00"

def build_dns_opt_record(udp_payload_size=1232):
    return b"\x00" + u16(0x0029) + u16(udp_payload_size) + u32(0) + u16(0)

def build_dns_question(query_id, flags, name_bytes, type_value, class_value,
                       additional_record=b""):
    additional_count = 1 if additional_record else 0
    return (u16(query_id) + u16(flags) + u16(1) + u16(0) + u16(0) +
            u16(additional_count) + name_bytes + u16(type_value) +
            u16(class_value) + additional_record)

def next_dns_query_type(options):
    """Тип запроса для очередного пакета цепочки — без повторов подряд.

    Живой stub-резолвер по одному имени спрашивает разное (A, AAAA, у
    браузеров ещё HTTPS), а повторяет только при потере ответа. Типы раздаются
    по кругу с перемешиванием на каждом проходе: типов три, пакетов пять, и
    два повтора выглядят как обычный ретрай (идентификатор запроса у каждого
    пакета свой).
    """
    queue = options.get("_dnsQueue")
    if not queue:
        queue = list(DNS_QUERY_TYPES)
        # Перемешивание Фишера-Йетса на нашем источнике случайности
        for i in range(len(queue) - 1, 0, -1):
            j = ri(i + 1)
            queue[i], queue[j] = queue[j], queue[i]
        # Стык проходов: типов три, пакетов пять, поэтому круг начинается
        # заново — и может начаться тем же типом, которым кончился прошлый.
        # Два одинаковых запроса ПОДРЯД — это уже не ретрай (тот приходит
        # через таймаут, а не встык), поэтому такой стык разводим.
        last = options.get("_dnsLast")
        if last is not None and len(queue) > 1 and queue[0] == last:
            queue[0], queue[-1] = queue[-1], queue[0]
        options["_dnsQueue"] = queue
    qtype = queue.pop(0)
    options["_dnsLast"] = qtype
    return qtype

def generate_dns_payload(options):
    # Идентификатор запроса резолвер выбирает случайно на каждый запрос — это
    # штатная защита от подделки ответа (RFC 5452), поэтому тег здесь не только
    # безопасен, но и правдоподобнее фиксированного значения.
    query_id = ri(65535)
    payload = build_dns_question(query_id, 0x0100, encode_dns_name(options["host"]),
                                 next_dns_query_type(options), 0x0001,
                                 build_dns_opt_record(1232))
    dyn(u16(query_id))
    return payload

def generate_ssdp_payload(options):
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        "MAN: \"ssdp:discover\"",
        "ST: " + rc(SSDP_SEARCH_TARGETS),
        "MX: %d" % (1 + ri(5)),
        "USER-AGENT: " + rc(SSDP_USER_AGENTS),
        "ACCEPT-LANGUAGE: en-US,en;q=0.9",
        "",
        "",
    ])
    return enc_text(message)

def generate_ntp_payload(options):
    now = time.time()
    payload = bytearray(48)
    payload[0] = 0x23          # LI=0, VN=4, Mode=3 (client)
    payload[1] = 0x00
    payload[2] = 0x06
    payload[3] = 0xEC
    payload[4:8] = u32(0x00000100)
    payload[8:12] = u32(0x00000100)
    payload[12:16] = enc_text("INIT")
    # Reference Timestamp — момент последней синхронизации клиента, у живого
    # клиента это минуты назад, а не ровно секунда. Секундный сдвиг был ещё и
    # вреден технически: дробные части обеих меток совпадали байт в байт, и
    # уникальности для тега не оставалось.
    # Сдвиг обязан быть дробным: ntp_timestamp считает дробь от миллисекунд, и
    # при целом числе секунд обе метки получили бы одинаковые младшие 4 байта.
    reference = ntp_timestamp(now - rr(30, 900) - ri(1000) / 1000.0)
    transmit = ntp_timestamp(now)
    payload[16:24] = reference
    payload[40:48] = transmit
    # Секунды не трогаем: случайные 4 байта дали бы дату вне текущей эпохи NTP,
    # то есть подделку виднее, чем повтор. Дробная часть (младшие 4 байта
    # метки) в реальных клиентах равномерно случайна — её и помечаем.
    dyn(reference[4:])
    dyn(transmit[4:])
    return bytes(payload)

def generate_rtp_payload(options=None):
    payload_type = rc([0x00, 0x08, 0x60])
    body = rb(96) if payload_type == 0x60 else rb(160)
    sequence = u16(ri(65535))
    timestamp = u32(ru32())
    ssrc = u32(ru32())
    # Внутри RTP ничего не считается от этих полей: заголовок без контрольной
    # суммы, тело — сжатый звук, для наблюдателя неотличимый от случайного.
    # Поэтому весь пакет, кроме двух байт версии/типа, может быть динамическим.
    dyn(sequence); dyn(timestamp); dyn(ssrc); dyn(body)
    return bytes([0x80, payload_type]) + sequence + timestamp + ssrc + body

def generate_rtcp_payload(options=None):
    ssrc = ru32()
    sender_report = (bytes([0x80, 0xC8]) + u16(0x0006) + u32(ssrc) +
                     ntp_timestamp() + u32(ru32()) + u32(1 + ri(64)) +
                     u32(160 + ri(4096)))
    cname = enc_text("webrtc@" + DEFAULT_HOST)
    sdes_value = (u32(ssrc) + bytes([0x01, len(cname)]) + cname + b"\x00" +
                  zeros((4 - ((4 + 2 + len(cname) + 1) % 4)) % 4))
    sdes = bytes([0x81, 0xCA]) + u16(((4 + len(sdes_value)) // 4) - 1) + sdes_value
    return sender_report + sdes

# ================================================================
# SIP (generators.js: generateSipPayload)
# ================================================================
def random_sip_user_part():
    prefix = rc(["100", "101", "200", "300", "400", "500",
                 "alice", "bob", "support", "sales", "noc", "ops"])
    return prefix + str(100 + ri(900))

def format_sip_address(display_name, user, host):
    return "\"%s\" <sip:%s@%s>" % (display_name, user, host)

def generate_random_sip_domain():
    base = rc(SIP_DOMAIN_BASES)
    suffix = rc(SIP_DOMAIN_SUFFIXES)
    if ri(3) == 0:
        return base + "." + suffix
    return "%s-%d.%s.%s" % (rc(SIP_DOMAIN_PREFIXES), 10 + ri(90), base, suffix)

def resolve_sip_host(options):
    # resolveSipHost: без флага sipCustomMessage домен всегда CONFIG.defaultHost
    if not options.get("sipCustomMessage"):
        return DEFAULT_HOST
    if options.get("hasCustomHost"):
        return options["host"]
    return generate_random_sip_domain()

def build_sip_invite_body(origin_user, host):
    media_ip = random_private_ipv4()
    audio_port = 12000 + ri(20000)
    session_id = 1000000000 + ri(900000000)
    codec_profile = rc(SIP_AUDIO_CODEC_PROFILES)
    fingerprint = ":".join(to_hex(rb(32))[i:i + 2] for i in range(0, 64, 2)).upper()
    lines = [
        "v=0",
        "o=%s %d %d IN IP4 %s" % (origin_user, session_id, session_id + 1, media_ip),
        "s=Call",
        "c=IN IP4 " + media_ip,
        "t=0 0",
        "m=audio %d RTP/AVP %s" % (audio_port, codec_profile["formatList"]),
        "a=rtcp:%d IN IP4 %s" % (audio_port + 1, media_ip),
        "a=sendrecv",
        "a=ptime:%d" % rc([20, 30, 40]),
        "a=maxptime:%d" % rc([60, 80, 120]),
        "a=rtcp-mux",
        # ICE-креденшелы генерируются заново на каждую сессию (RFC 5245 §15.4)
        # и состоят из ice-char = ALPHA / DIGIT / + / — буквы от <rc> подходят.
        "a=ice-ufrag:" + dyn(to_hex(rb(4)), "rc"),
        "a=ice-pwd:" + dyn(to_hex(rb(12)), "rc"),
        "a=fingerprint:sha-256 " + fingerprint,
        "a=setup:actpass",
        "a=msid-semantic: WMS " + origin_user,
        "a=rtcp-fb:* transport-cc",
    ]
    lines += ["a=rtpmap:" + p for p in codec_profile["payloads"]]
    lines += ["a=ssrc:%d cname:%s@%s" % (ru32(), origin_user, host)]
    return "\r\n".join(lines)

def generate_sip_payload(options):
    action = str(options.get("sipAction") or "OPTIONS").strip().upper()
    if action == "RANDOM":
        action = rc(["OPTIONS", "REGISTER", "INVITE", "TRYING"])
    if action not in ("REGISTER", "INVITE", "TRYING"):
        action = "OPTIONS"

    host = resolve_sip_host(options)
    local_ip = random_private_ipv4()
    local_port = rc(SIP_LOCAL_PORTS)
    from_user = random_sip_user_part()
    to_user = from_user if action == "REGISTER" else random_sip_user_part()
    from_display = rc(SIP_DISPLAY_NAMES)
    to_display = from_display if action == "REGISTER" else rc(SIP_DISPLAY_NAMES)
    # Идентификаторы транзакции SIP: branch, tag и Call-ID уникальны для каждого
    # запроса по самой спецификации (RFC 3261 §8.1.1.7, §19.3) — повтор одного и
    # того же Call-ID выглядел бы куда подозрительнее случайных букв. Тег <rc>,
    # а не <r>: протокол текстовый, двоичный мусор внутри заголовка недопустим.
    # Префикс z9hG4bK остаётся статикой — это обязательный магический маркер.
    branch = "z9hG4bK" + dyn(to_hex(rb(9)), "rc")
    tag = dyn(to_hex(rb(6)), "rc")
    call_id = dyn(to_hex(rb(12)), "rc") + "@" + host
    cseq = 1 + ri(50)
    user_agent = rc(SIP_USER_AGENTS)
    allow_header = rc(SIP_ALLOW_HEADERS)
    supported_header = rc(SIP_SUPPORTED_HEADERS)
    to_uri = format_sip_address(to_display, to_user, host)
    from_uri = format_sip_address(from_display, from_user, host)
    request_uri = "sip:" + host if action == "REGISTER" else "sip:%s@%s" % (to_user, host)
    via = "Via: SIP/2.0/UDP %s:%d;branch=%s;rport" % (local_ip, local_port, branch)
    contact = "Contact: <sip:%s@%s:%d;transport=udp>" % (from_user, local_ip, local_port)

    if action == "TRYING":
        lines = [
            "SIP/2.0 100 CONNECTING", via,
            "To: " + to_uri,
            "From: %s;tag=%s" % (from_uri, tag),
            "Call-ID: " + call_id,
            "CSeq: %d INVITE" % cseq,
            "Server: " + rc(SIP_SERVER_NAMES),
            "Content-Length: 0", "", "",
        ]
    elif action == "REGISTER":
        lines = [
            "REGISTER %s SIP/2.0" % request_uri, via,
            "Max-Forwards: 70",
            "From: %s;tag=%s" % (from_uri, tag),
            "To: " + to_uri,
            "Call-ID: " + call_id,
            "CSeq: %d REGISTER" % cseq,
            contact,
            "User-Agent: " + user_agent,
            "Allow: " + allow_header,
            "Supported: " + supported_header,
            "Allow-Events: " + rc(SIP_ALLOW_EVENTS_HEADERS),
            "Expires: %d" % rc([300, 600, 900, 1200, 1800, 3600]),
            "Content-Length: 0", "", "",
        ]
    elif action == "INVITE":
        body = build_sip_invite_body(from_user, host)
        lines = [
            "INVITE %s SIP/2.0" % request_uri, via,
            "Max-Forwards: 70",
            "From: %s;tag=%s" % (from_uri, tag),
            "To: " + to_uri,
            "Call-ID: " + call_id,
            "CSeq: %d INVITE" % cseq,
            contact,
            "User-Agent: " + user_agent,
            "Allow: " + allow_header,
            "Supported: " + supported_header,
            "Content-Type: application/sdp",
            "Content-Length: %d" % len(enc_text(body)),
            "", body,
        ]
    else:
        lines = [
            "OPTIONS %s SIP/2.0" % request_uri, via,
            "Max-Forwards: 70",
            "From: %s;tag=%s" % (from_uri, tag),
            "To: " + to_uri,
            "Call-ID: " + call_id,
            "CSeq: %d OPTIONS" % cseq,
            contact,
            "User-Agent: " + user_agent,
            "Allow: " + allow_header,
            "Supported: " + supported_header,
            "Accept: application/sdp",
            "Accept-Language: " + rc(SIP_ACCEPT_LANGUAGES),
            "Content-Length: 0", "", "",
        ]
    return enc_text("\r\n".join(lines))

# ================================================================
# DTLS (generators.js: generateDtlsPayload)
# ================================================================
def build_dtls_client_hello_body(host):
    session_id = rb(32)
    extensions = (ext_server_name(host) +
                  ext_supported_groups(None, [0x001D, 0x0017, 0x0018]) +
                  ext_ec_point_formats() +
                  ext_signature_algorithms() +
                  ext_use_srtp() +
                  ext_extended_master_secret())
    cipher_suites = b"".join(u16(c) for c in
                             [0xC02B, 0xC02F, 0xCCA9, 0xC02C, 0x009C, 0x009D])
    # ClientHello в DTLS ничем не подписан и не зашифрован (MAC появляется
    # только после смены шифра), а client_random и session_id по спецификации
    # случайны — оба поля можно отдать тегам. ECH здесь нет, так что связывания
    # с внешним ClientHello, которое сломалось бы, тоже нет.
    client_random = rb(32)
    dyn(client_random); dyn(session_id)
    return (b"\xFE\xFD" + client_random + bytes([len(session_id)]) + session_id +
            b"\x00" + u16(len(cipher_suites)) + cipher_suites + b"\x01\x00" +
            u16(len(extensions)) + extensions)

def generate_dtls_payload(options):
    body = build_dtls_client_hello_body(options["host"])
    handshake = (b"\x01" + u24(len(body)) + u16(0) + u24(0) + u24(len(body)) + body)
    return (b"\x16\xFE\xFD" + u16(0) + zeros(6) + u16(len(handshake)) + handshake)

# ================================================================
# STUN / TURN и WebRTC (generators.js: generateUnifiedStunTurnPayload)
# ================================================================
def build_stun_attribute(attr_type, value):
    padding = (4 - (len(value) % 4)) % 4
    return u16(attr_type) + u16(len(value)) + value + zeros(padding)

def build_stun_message_with_fingerprint(message_type, attrs):
    """
    STUN-сообщение с атрибутом FINGERPRINT (RFC 5389 §15.5).

    Отличие от payloadGen: там CRC32 считается по сообщению ВМЕСТЕ с четырьмя
    байтами заголовка самого FINGERPRINT, а RFC требует считать до атрибута,
    не включая его. С расчётом оригинала любой разбирающий STUN наблюдатель
    видит несходящуюся контрольную сумму — то есть ровно ту аномалию, ради
    сокрытия которой мимикрия и делается, поэтому здесь взят вариант RFC.
    Длина сообщения при этом, как и требуется, учитывает FINGERPRINT.
    """
    transaction_id = rb(12)
    attr_bytes = b"".join(attrs)
    total_length = len(attr_bytes) + 8      # + FINGERPRINT (4 байта заголовка + 4 значения)
    prefix = u16(message_type) + u16(total_length) + u32(0x2112A442) + transaction_id
    crc_value = (crc32_stun(prefix + attr_bytes) ^ 0x5354554E) & 0xFFFFFFFF
    return prefix + attr_bytes + build_stun_attribute(0x8028, u32(crc_value))

# Провайдеры ICE, из которых выбирает режим random. Список нужен и здесь, и в
# build_options: разыгрывать провайдера обязаны ОДИН раз на всю цепочку I1-I5.
STUN_PROVIDERS = ["google", "cloudflare", "meta", "twilio", "twilio_stun"]

def resolve_stun_turn_profile(provider):
    provider = str(provider or "").strip().lower()
    if provider == "random":
        provider = rc(STUN_PROVIDERS)
    if provider == "twilio_stun":
        return {"id": "twilio", "serverPool": TWILIO_STUN_SERVERS, "realm": TWILIO_REALM,
                "softwareName": "Twilio WebRTC ICE agent", "preferredMode": "binding",
                "autoAllocateProbability": 0.0, "supportsAllocate": False,
                "lifetimeRange": [300, 600]}
    if provider in ("twilio", "twilio_turn"):
        return {"id": "twilio", "serverPool": TWILIO_TURN_SERVERS, "realm": TWILIO_REALM,
                "softwareName": "Twilio WebRTC ICE agent", "preferredMode": "allocate",
                "autoAllocateProbability": 0.67, "supportsAllocate": True,
                "lifetimeRange": [300, 600]}
    if provider == "cloudflare":
        return {"id": "cloudflare", "serverPool": CLOUDFLARE_WEBRTC_SERVERS,
                "realm": CLOUDFLARE_REALM, "softwareName": "Cloudflare WebRTC client",
                "preferredMode": None, "autoAllocateProbability": 0.67,
                "supportsAllocate": True, "lifetimeRange": [600, 1200]}
    if provider == "meta":
        return {"id": "meta", "serverPool": META_WEBRTC_SERVERS, "realm": META_REALM,
                "softwareName": None, "preferredMode": None,
                "autoAllocateProbability": 0.75, "supportsAllocate": True,
                "lifetimeRange": [180, 600]}
    return {"id": "google", "serverPool": GOOGLE_STUN_SERVERS, "realm": "google.com",
            "softwareName": "Google STUN client", "preferredMode": None,
            "autoAllocateProbability": 0.0, "supportsAllocate": False,
            "lifetimeRange": [300, 600]}

def resolve_stun_turn_mode(options, profile):
    requested = str(options.get("iceMode") or "auto")
    if requested == "binding":
        return "binding"
    if requested == "allocate":
        return "allocate" if profile["supportsAllocate"] else "binding"
    if profile["preferredMode"] == "binding":
        return "binding"
    if profile["preferredMode"] == "allocate":
        return "allocate" if profile["supportsAllocate"] else "binding"
    if not profile["supportsAllocate"]:
        return "binding"
    return "allocate" if (ri(1000) / 1000.0) < profile["autoAllocateProbability"] else "binding"

# Приложения Meta, которыми может представиться профиль meta. Выбор — один на
# цепочку: WhatsApp не превращается в Instagram от пакета к пакету.
META_SOFTWARE_NAMES = ["WhatsApp/2", "Instagram/2", "Messenger WebRTC"]

def stun_software_name(profile, options=None):
    if profile["id"] != "meta":
        return profile["softwareName"]
    if options is None:
        return rc(META_SOFTWARE_NAMES)
    name = options.get("_metaSoftware")
    if not name:
        name = rc(META_SOFTWARE_NAMES)
        options["_metaSoftware"] = name
    return name

def twilio_username_token():
    """Временный креденшел Twilio: 20 hex-символов.

    Форма (длина и алфавит) как у настоящего, содержимое случайное: любой
    фиксированный литерал стал бы сигнатурой всех, кто пользуется профилем.
    """
    return to_hex(rb(10))

def build_stun_binding_username(profile, server_host):
    if profile["id"] == "meta":
        return enc_text("WA-%d:%s" % (1000000000 + ri(9000000000), server_host))
    if profile["id"] == "twilio":
        return enc_text("%s:%s" % (twilio_username_token(), server_host))
    return enc_text("%s:%s" % (to_hex(rb(4)), server_host))

def build_stun_allocate_username(profile, server_host):
    if profile["id"] == "meta":
        return enc_text("WA-%d@%s" % (1000000000 + ri(9000000000), server_host))
    suffix = str(ri(9000) + 1000)
    if profile["id"] == "twilio":
        return enc_text("%s%s@%s" % (twilio_username_token(), suffix, server_host))
    return enc_text("%s%s@%s" % (to_hex(rb(8)), suffix, server_host))

def generate_stun_payload(options):
    """
    STUN Binding или TURN Allocate под выбранного провайдера ICE.
    Реальный WebRTC-клиент шлёт ровно такие пакеты в начале звонка.
    """
    profile = resolve_stun_turn_profile(options.get("iceProvider") or "google")
    mode = resolve_stun_turn_mode(options, profile)
    server_host = options.get("iceServerHost") or rc(profile["serverPool"])

    # Свой домен пользователя и провайдерская маркировка вместе не живут:
    # клиент, который представляется Cloudflare, а ходит к чужому хосту, —
    # противоречие. Поэтому realm становится тем же доменом, а вендорские
    # имена уходят (SOFTWARE в STUN необязателен, RFC 5389 §15.10).
    if options.get("iceServerHost"):
        profile = dict(profile, id="generic", realm=server_host, softwareName=None)

    attrs = []

    if mode == "allocate":
        lifetime = profile["lifetimeRange"][0] + \
            ri(profile["lifetimeRange"][1] - profile["lifetimeRange"][0])
        attrs.append(build_stun_attribute(0x0014, enc_text(profile["realm"])))
        attrs.append(build_stun_attribute(0x000D, u32(lifetime)))
        attrs.append(build_stun_attribute(0x0019, u32(0x00000011) + zeros(4)))
        # REQUESTED-ADDRESS-FAMILY (0x0017, RFC 6156 §4.1.1): байт семейства,
        # затем три зарезервированных нуля.
        attrs.append(build_stun_attribute(
            0x0017, bytes([0x01 if ri(2) == 0 else 0x02, 0x00, 0x00, 0x00])))
        username = build_stun_allocate_username(profile, server_host)
    else:
        username = build_stun_binding_username(profile, server_host)

    software = stun_software_name(profile, options)
    if software:
        attrs.append(build_stun_attribute(0x8022, enc_text(software)))
    attrs.append(build_stun_attribute(0x0024, u32(ru32() | 0x40000000)))
    attrs.append(build_stun_attribute(0x8029 if ri(2) == 0 else 0x802A,
                                      u32(ru32()) + u32(ru32())))
    attrs.append(build_stun_attribute(0x0006, username))

    return build_stun_message_with_fingerprint(0x000A if mode == "allocate" else 0x0001, attrs)

def generate_webrtc_payload(options):
    """
    Связка первых пакетов WebRTC-сессии: STUN Binding, DTLS ClientHello,
    RTP и RTCP. Порт generateWebrtcCombinedPayload.
    """
    stun_options = dict(options)
    stun_options["iceMode"] = "binding"
    stun_payload = generate_stun_payload(stun_options)
    dtls_host = options.get("iceServerHost") or options.get("host") or "stun.l.google.com"
    return (stun_payload + generate_dtls_payload({"host": dtls_host}) +
            generate_rtp_payload() + generate_rtcp_payload())

# ================================================================
# Диспетчер профилей и вывод (app.js: appendChunkLines/chunkPayload)
# ================================================================
# Динамические поля (теги <r>/<rc>/<rd>) есть не у всех профилей — и это не
# недоделка, а свойство самих протоколов:
#   dns, ntp, rtp, sip, dtls — помечены (см. dyn() в соответствующих функциях);
#   webrtc — помечены только его DTLS/RTP-части, STUN внутри неприкосновенен;
#   stun   — весь пакет накрыт FINGERPRINT (CRC32 по всему сообщению), любое
#            динамическое поле сделало бы контрольную сумму несходящейся;
#   quic, curl_quic — ключи Initial выводятся из DCID, а заголовок целиком
#            входит в AAD (RFC 9001 §5.2): подменив байт, мы получаем пакет,
#            который не расшифрует никто, включая DPI, который как раз и лезет
#            в Initial за SNI. Повторный идентичный Initial выглядит обычной
#            ретрансмиссией, битый — аномалией. Поэтому статика;
#   ssdp   — M-SEARCH реального устройства и в жизни повторяется дословно.
PROTOCOL_GENERATORS = {
    "dns": generate_dns_payload,
    "quic": generate_quic_payload,
    "curl_quic": generate_curl_quic_payload,
    "stun": generate_stun_payload,
    "webrtc": generate_webrtc_payload,
    "sip": generate_sip_payload,
    "ntp": generate_ntp_payload,
    "rtp": generate_rtp_payload,
    "ssdp": generate_ssdp_payload,
    "dtls": generate_dtls_payload,
}

# Устаревшие имена профилей awg2 до перехода на payloadGen. TLS-запись поверх
# UDP не существует как протокол, поэтому профиль tls заменён на quic — это
# настоящий UDP-протокол с тем же Chrome-подобным ClientHello внутри.
PROFILE_ALIASES = {"tls": "quic"}

def chunk_payload(payload, mtu):
    if not payload:
        return [payload]
    return [payload[i:i + mtu] for i in range(0, len(payload), mtu)]

def build_options(profile, domain, domain_is_explicit, args):
    options = {"host": domain or DEFAULT_HOST}
    if profile in ("quic", "curl_quic"):
        options["quicMtu"] = args["mtu"]
        options["quicPadToMtu"] = False
        options["echDoh"] = args["ech_doh"]
    elif profile == "sip":
        # sipCustomMessage=True заставляет использовать наш домен, иначе
        # оригинал подставил бы CONFIG.defaultHost во все пять пакетов.
        options["sipCustomMessage"] = True
        options["hasCustomHost"] = True
        options["sipAction"] = args["sip_action"]
    elif profile in ("stun", "webrtc"):
        # random разыгрываем ЗДЕСЬ, один раз на цепочку, а не внутри
        # resolve_stun_turn_profile на каждый пакет. Атрибут SOFTWARE описывает
        # клиентскую реализацию, а не сервер: пять пакетов подряд, где клиент
        # называется то «Google STUN client», то «Twilio WebRTC ICE agent»,
        # то «Cloudflare WebRTC client», — это один браузер, объявивший себя
        # тремя разными. Такого не бывает, и заметно это без всякой статистики.
        provider = str(args["ice_provider"] or "").strip().lower()
        if provider == "random":
            provider = rc(STUN_PROVIDERS)
        options["iceProvider"] = provider
        options["iceMode"] = args["ice_mode"]
        # Имя приложения Meta фиксируем здесь же, а не лениво при первом
        # пакете: профиль webrtc собирает STUN на КОПИИ options
        # (dict(options)), и запомненное внутри копии значение до следующего
        # пакета не доживает — цепочка снова представлялась бы тремя разными
        # приложениями сразу.
        options["_metaSoftware"] = rc(META_SOFTWARE_NAMES)
        # Домен подставляем в ICE только если его ввёл пользователь: при
        # автогенерации правдоподобнее пул серверов самого провайдера.
        options["iceServerHost"] = domain if domain_is_explicit else ""
    return options

def main(argv):
    args = {
        "mtu": DEFAULT_MTU,
        # Бюджет длины всей цепочки в символах конфига (0 = без лимита).
        "budget": 0,
        "ech_doh": os.environ.get("AWG_CPS_ECH_DOH", "") not in ("", "0"),
        "sip_action": "OPTIONS",
        "ice_provider": "random",
        "ice_mode": "auto",
        # --static возвращает поведение до динамических тегов: строка целиком из
        # <b 0x..>. Нужен для сравнения в тестах и как аварийный откат, если
        # клиент окажется без поддержки <r>/<rc>.
        "static": False,
    }
    only_i1 = False
    positional = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--only-i1":
            only_i1 = True
        elif arg == "--static":
            args["static"] = True
        elif arg == "--ech-doh":
            args["ech_doh"] = True
        elif arg == "--full":
            # Флаг компактного режима старого генератора: размеры пакетов теперь
            # задаёт payloadGen, поэтому флаг принимается и ничего не меняет.
            pass
        elif arg == "--mtu" and index + 1 < len(argv):
            index += 1
            try:
                args["mtu"] = max(1200, min(1500, int(argv[index])))
            except ValueError:
                _warn_once("значение --mtu не число, беру %d" % DEFAULT_MTU)
        elif arg == "--budget" and index + 1 < len(argv):
            index += 1
            try:
                args["budget"] = max(0, int(argv[index]))
            except ValueError:
                _warn_once("значение --budget не число, лимит длины снят")
        elif arg == "--sip-action" and index + 1 < len(argv):
            index += 1
            args["sip_action"] = argv[index]
        elif arg == "--ice-provider" and index + 1 < len(argv):
            index += 1
            args["ice_provider"] = argv[index]
        elif arg == "--ice-mode" and index + 1 < len(argv):
            index += 1
            args["ice_mode"] = argv[index]
        elif arg.startswith("--"):
            _warn_once("неизвестный флаг %s пропущен" % arg)
        else:
            positional.append(arg)
        index += 1

    profile = positional[0] if positional else "quic"
    domain = positional[1].strip() if len(positional) > 1 else ""
    profile = PROFILE_ALIASES.get(profile, profile)
    if profile not in PROTOCOL_GENERATORS:
        _warn_once("неизвестный профиль %s, беру quic" % profile)
        profile = "quic"

    domain_is_explicit = bool(domain)
    if not domain:
        domain = rc(RU_DOMAIN_POOL)

    generator = PROTOCOL_GENERATORS[profile]
    options = build_options(profile, domain, domain_is_explicit, args)

    # Бюджет применяется ЦЕЛЫМИ пакетами. Обрезать пакет на середине нельзя:
    # получится не снимок протокола, а обрубок, по которому DPI отличает нас
    # быстрее, чем по отсутствию мимикрии вовсе. Поэтому сколько пакетов
    # поместится — зависит от профиля: DNS укладывает все пять в ~370 символов,
    # один QUIC Initial занимает ~2400. Первый пакет выдаётся всегда, иначе
    # слишком маленький бюджет молча оставил бы конфиг без мимикрии.
    budget = args["budget"]
    lines = []
    used = 0
    for _ in range(MAX_OUTPUT_LINES):
        if len(lines) >= MAX_OUTPUT_LINES:
            break
        # Помеченное поле выбрасывается из строки, если случайно встретилось в
        # пакете дважды: два тега разъехались бы, а копии обязаны совпадать.
        # Для коротких полей это не теория — Transaction ID в DNS занимает 2
        # байта, и примерно раз на 1600 пакетов они попадаются в теле ещё раз.
        # Тогда у пакета не остаётся ни одного динамического поля, и строка I
        # уходит в эфир БАЙТ В БАЙТ при каждом рукопожатии — ровно та статичная
        # сигнатура, против которой всё и делается. Пакет случайный, поэтому
        # достаточно сгенерировать заново.
        payload = None
        for _attempt in range(8):
            try:
                dyn_reset()
                payload = generator(options)
            except Exception as exc:
                _warn_once("сбой генерации %s (%s: %s)" % (profile, type(exc).__name__, exc))
                payload = None
                break
            if not _DYN or dyn_all_unique(payload):
                break
        if payload is None:
            break
        room = MAX_OUTPUT_LINES - len(lines)
        chunks = chunk_payload(payload, args["mtu"])
        if args["static"] or len(chunks) > 1:
            # Разрезанный на несколько строк пакет помечать нечем: смещения
            # полей уезжают в соседний кусок. Такое бывает только у QUIC при
            # маленьком --mtu, а там динамических полей всё равно нет.
            piece = ["<b 0x%s>" % to_hex(chunk) for chunk in chunks[:room]]
        else:
            piece = [build_tagged_line(payload)]
        cost = sum(len(item) for item in piece)
        if budget and lines and used + cost > budget:
            break
        lines.extend(piece)
        used += cost
        if only_i1:
            break

    if not lines:
        return 1
    for line in (lines[:1] if only_i1 else lines):
        print(line)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
