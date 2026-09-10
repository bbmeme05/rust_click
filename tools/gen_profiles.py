#!/usr/bin/env python3
"""Parse a MySQL dump of `ja3_info` rows and emit collected fingerprint profiles.

Groups observations by JA4 (order-insensitive, because Chrome permutes TLS
extensions) and picks the most frequent JA3 inside each group as the
representative. Signature algorithms and the HTTP/2 (Akamai) fingerprint are
recovered from the stored raw ClientHello / h2 capture.
"""
import base64, collections, hashlib, json, re, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/Users/zcy/Library/Containers/com.tencent.xinWeChat.dual/Data/Documents/xwechat_files/wxid_2zootahs45si22_fad0/msg/file/2026-08/ja3_info.sql"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ja3work/collected_profiles.json"
MAX_PROFILES = int(sys.argv[3]) if len(sys.argv) > 3 else 120

ROW_RE = re.compile(
    r"VALUES \((\d+), '(.*?)', '(.*?)', '(.*?)', '(.*)', (\d+), '(.*?)'\);\s*$", re.S
)
_GREASE = lambda x: (x & 0x0F0F) == 0x0A0A


def unescape(s):
    out, i = [], 0
    m = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "Z": "\x1a",
         "\\": "\\", "'": "'", '"': '"'}
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(m.get(s[i + 1], s[i + 1])); i += 2
        else:
            out.append(c); i += 1
    return "".join(out)


def _u16_list(data):
    """Decode a 2-byte-length-prefixed list of uint16 values, dropping GREASE."""
    if len(data) < 2:
        return []
    n = int.from_bytes(data[0:2], "big") // 2
    vals = [int.from_bytes(data[2 + 2 * i:4 + 2 * i], "big") for i in range(n)
            if 4 + 2 * i <= len(data)]
    return [v for v in vals if not _GREASE(v)]


def parse_raw(raw_b64):
    """Return ciphers, ordered extensions, curves, sigalgs, alpn, tls_version.

    GREASE values are stripped everywhere (JA3/JA4 both ignore them), and
    supported_versions is scanned for the highest non-GREASE version because
    Chrome sends GREASE first in that list.
    """
    b = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
    p = 5
    if b[p] != 1:
        raise ValueError("not a ClientHello")
    p += 4 + 2 + 32
    sid = b[p]; p += 1 + sid
    cl = int.from_bytes(b[p:p + 2], "big"); p += 2
    ciphers = [int.from_bytes(b[p + 2 * i:p + 2 * i + 2], "big") for i in range(cl // 2)]
    p += cl
    comp = b[p]; p += 1 + comp
    el = int.from_bytes(b[p:p + 2], "big"); p += 2
    end, exts = p + el, {}
    while p < end:
        et = int.from_bytes(b[p:p + 2], "big"); ed = int.from_bytes(b[p + 2:p + 4], "big")
        exts.setdefault(et, b[p + 4:p + 4 + ed]); p += 4 + ed
    ver = 0
    if 0x002B in exts and len(exts[0x002B]) >= 1:
        vl = exts[0x002B][0]; versions = []
        for i in range(vl // 2):
            v = int.from_bytes(exts[0x002B][1 + 2 * i:3 + 2 * i], "big")
            if not _GREASE(v):
                versions.append(v)
        ver = {0x0304: 13, 0x0303: 12, 0x0302: 11, 0x0301: 10}.get(max(versions, default=0), 0)
    alpn = ""
    if 0x0010 in exts and len(exts[0x0010]) >= 3:
        n = exts[0x0010][2]; alpn = exts[0x0010][3:3 + n].decode("latin1")
    return {"ciphers": [c for c in ciphers if not _GREASE(c)],
            "extensions": [e for e in exts.keys() if not _GREASE(e)],
            "sigalgs": _u16_list(exts.get(0x000D, b"")),
            "curves": _u16_list(exts.get(0x000A, b"")),
            "alpn": alpn, "tls_version": ver}


def ja4(parsed, sni=True):
    c = sorted(x for x in parsed["ciphers"] if not _GREASE(x))
    e = sorted(x for x in parsed["extensions"] if not _GREASE(x))
    sigs = sorted(x for x in parsed["sigalgs"] if not _GREASE(x))
    a = "t%02d%s%02d%02d%s" % (parsed["tls_version"], "d" if sni else "i", len(c), len(e), parsed["alpn"])
    b = hashlib.sha256(",".join("%04x" % x for x in c).encode()).hexdigest()[:12]
    ehash = [x for x in e if x not in (0x0000, 0x0010)]
    cc = hashlib.sha256((",".join("%04x" % x for x in ehash) + "_" +
                         ",".join("%04x" % x for x in sigs)).encode()).hexdigest()[:12]
    return "%s_%s_%s" % (a, b, cc)


groups = collections.defaultdict(lambda: {
    "count": 0, "ja3": collections.Counter(), "raw": None,
    "sigalgs": collections.Counter(), "curves": collections.Counter(),
    "ciphers": collections.Counter(), "extensions": collections.Counter(),
    "alpn": collections.Counter(), "tls_version": collections.Counter(),
    "h2": collections.Counter(), "ua": collections.Counter(), "os": collections.Counter(),
    "header_order": collections.Counter(), "sec_ch_ua": collections.Counter(),
    "sec_ch_ua_mobile": collections.Counter(), "sec_ch_ua_platform": collections.Counter(),
    "accept_language": collections.Counter(), "priority": collections.Counter(),
    "osv": collections.Counter(), "model": collections.Counter(), "chrome": collections.Counter(),
    "country": collections.Counter(),
})
rows = bad = 0
with open(SRC, errors="replace") as f:
    for line in f:
        m = ROW_RE.search(line.rstrip("\n"))
        if not m:
            bad += 1; continue
        try:
            data = json.loads(unescape(m.group(5)))
            parsed = parse_raw((data.get("tls") or {}).get("raw") or "")
        except Exception:
            bad += 1; continue
        rows += 1
        g = groups[ja4(parsed)]
        g["count"] += 1
        g["ja3"][(data.get("tls") or {}).get("ja3", "")] += 1
        g["sigalgs"][tuple(parsed["sigalgs"])] += 1
        g["curves"][tuple(parsed["curves"])] += 1
        g["ciphers"][tuple(parsed["ciphers"])] += 1
        g["extensions"][tuple(parsed["extensions"])] += 1
        g["alpn"][parsed["alpn"]] += 1
        g["tls_version"][parsed["tls_version"]] += 1
        h2obj = data.get("h2") or {}
        g["h2"][h2obj.get("akamai_fingerprint", "")] += 1
        hdrs = h2obj.get("headers") or []
        if hdrs:
            names = tuple(h.get("n", "") for h in hdrs if h.get("n"))
            g["header_order"][names] += 1
            byname = {h.get("n", ""): h.get("v", "") for h in hdrs}
            for key, field in (("sec-ch-ua", "sec_ch_ua"),
                               ("sec-ch-ua-mobile", "sec_ch_ua_mobile"),
                               ("sec-ch-ua-platform", "sec_ch_ua_platform"),
                               ("accept-language", "accept_language"),
                               ("priority", "priority")):
                if byname.get(key):
                    g[field][byname[key]] += 1
        g["ua"][data.get("ua", "")] += 1
        for k in ("os", "osv", "model", "chrome", "country"):
            v = data.get(k) or ""
            if v: g[k][v] += 1

def top(c, n=1, empty=None):
    return [x for x, _ in c.most_common(n)] or [empty]

profiles = []
for ja4k, g in sorted(groups.items(), key=lambda kv: -kv[1]["count"])[:MAX_PROFILES]:
    sig = top(g["sigalgs"])[0] or ()
    curves = top(g["curves"])[0] or ()
    ciphers = top(g["ciphers"])[0] or ()
    reps = top(g["ja3"])[0] or ""
    profiles.append({
        "id": "c%03d" % (len(profiles) + 1),
        "ja4": ja4k,
        "ja3": reps,
        "count": g["count"],
        "tls": {
            "ciphers": list(ciphers), "curves": list(curves), "sigalgs": list(sig),
            "extensions": list(top(g["extensions"])[0] or ()),
            "alpn": top(g["alpn"])[0] or "",
            "tls_version": top(g["tls_version"])[0] or 0,
        },
        "h2": top(g["h2"])[0] or "",
        "header_order": list(top(g["header_order"])[0] or ()),
        "headers": [h for h in [
            ("sec-ch-ua", top(g["sec_ch_ua"])[0] or ""),
            ("sec-ch-ua-mobile", top(g["sec_ch_ua_mobile"])[0] or ""),
            ("sec-ch-ua-platform", top(g["sec_ch_ua_platform"])[0] or ""),
            ("accept-language", top(g["accept_language"])[0] or ""),
            ("priority", top(g["priority"])[0] or ""),
        ] if h[1]],
        "ua": top(g["ua"])[0] or "",
        "os": top(g["os"])[0] or "", "osv": top(g["osv"])[0] or "",
        "model": top(g["model"])[0] or "", "chrome": top(g["chrome"])[0] or "",
        "country": top(g["country"])[0] or "",
    })

doc = {
    "source": "ja3_info.sql",
    "rows_parsed": rows, "rows_skipped": bad,
    "distinct_ja4": len(groups), "profiles_emitted": len(profiles),
    "note": "JA4 is the grouping key because Chrome permutes TLS extension order (JA3 varies per connection).",
    "profiles": profiles,
}
json.dump(doc, open(OUT, "w"), ensure_ascii=False, indent=1)
print("rows=%d bad=%d distinct_ja4=%d emitted=%d -> %s" % (rows, bad, len(groups), len(profiles), OUT))
print("\ntop 15:")
for p in profiles[:15]:
    print(" %5d %-8s %-46s curves=%s ciphers=%d sigs=%d" % (
        p["count"], p["id"], p["ja4"], p["tls"]["curves"], len(p["tls"]["ciphers"]), len(p["tls"]["sigalgs"])))
    print("        h2=%s" % p["h2"])
