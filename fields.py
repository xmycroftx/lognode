"""Canonical field naming for extracted log fields.

The templatizer lets a model choose capture-group names, so the same kind of
value arrives under a different key in every template: an address might be
`ip`, `addr`, `client`, `source_ip`, `remote_addr` or `host`. That makes the
JSONB unqueryable without knowing which template produced a row, and it is why
graph.observe_log has to guess with chains like
`kv.get("ip") or kv.get("client")`.

normalize_fields() renames by the VALUE'S SHAPE while preserving the ROLE the
original name carried, so direction is not lost:

    {"remote_addr": "10.0.0.2"}      -> {"remote_ip": "10.0.0.2", "ip": "10.0.0.2"}
    {"src": "10.0.0.1", "dst": "10.0.0.2"}
                                     -> {"src_ip": "...", "dst_ip": "...", "ip": "10.0.0.1"}
    {"hostname": "hub"}           -> {"host": "hub"}

A bare `ip` / `host` alias is added for the primary value so consumers that
expect one key keep working, without losing the role-qualified keys.
"""
import re

__all__ = ["normalize_fields", "classify_value"]

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
RE_IPV4      = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")
RE_IPV4_PORT = re.compile(rf"^({_OCTET}(?:\.{_OCTET}){{3}}):(\d{{1,5}})$")
RE_IPV6      = re.compile(r"^(?=.*:)[0-9A-Fa-f:]{2,45}(?:%[0-9A-Za-z]+)?$")
RE_MAC       = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
RE_UUID      = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                          r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
RE_URL       = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
RE_PATH      = re.compile(r"^(?:/[^/\s]*)+/?$")
RE_FQDN      = re.compile(r"^(?=.{1,253}$)(?!\d+$)[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?"
                          r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?)+$")
RE_HOSTNAME  = re.compile(r"^(?!\d+$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
RE_HEX       = re.compile(r"^(?:0[xX])?[0-9A-Fa-f]{6,}$")
RE_DURATION  = re.compile(r"^\d+(?:\.\d+)?\s?(?:ns|us|µs|ms|s|m|h)$")
RE_BYTES     = re.compile(r"^\d+(?:\.\d+)?\s?(?:B|KB|MB|GB|TB|KiB|MiB|GiB)$")
RE_INT       = re.compile(r"^-?\d+$")
RE_FLOAT     = re.compile(r"^-?\d+\.\d+$")

# key tokens that name a TYPE rather than a role -- stripped to find the role
TYPE_TOKENS = {
    "ip": "ip", "ipv4": "ip", "ipaddr": "ip", "ipaddress": "ip", "addr": "ip",
    "address": "ip", "ipv6": "ipv6",
    "host": "host", "hostname": "host", "fqdn": "host", "domain": "host",
    "server": None, "node": None,          # role words that are NOT type words
    "port": "port", "path": "path", "file": "path", "filename": "path",
    "dir": "path", "directory": "path",
    "url": "url", "uri": "url", "link": "url",
    "mac": "mac", "macaddr": "mac", "hwaddr": "mac",
    "uuid": "uuid", "guid": "uuid", "id": None,
    "pid": "pid", "user": "user", "username": "user", "uname": "user",
    "bytes": "bytes", "size": "bytes", "len": "bytes", "length": "bytes",
    "duration": "duration", "elapsed": "duration", "took": "duration",
    "latency": "duration", "ms": "duration", "time": None,
}
# words that carry direction/role and must survive normalisation
ROLE_WORDS = {
    "src", "source", "dst", "dest", "destination", "client", "server", "peer",
    "remote", "local", "from", "to", "origin", "target", "upstream",
    "downstream", "listen", "bind", "query", "reply", "request", "response",
}
_SPLIT = re.compile(r"[_\-.\s]+")


HOST_ROLE_WORDS = {"server", "client", "peer", "node", "target", "origin",
                   "remote", "upstream", "downstream", "src", "source",
                   "dst", "dest", "destination"}


def role_implies_host(key: str) -> bool:
    """True when the key names a machine role, so a bare word is a hostname."""
    return any(p in HOST_ROLE_WORDS for p in _SPLIT.split(key.lower()) if p)


def classify_value(value):
    """Return a canonical type name for a scalar value, or None."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    if RE_IPV4.match(v):     return "ip"
    if RE_IPV4_PORT.match(v): return "ip_port"
    if RE_MAC.match(v):      return "mac"
    if RE_UUID.match(v):     return "uuid"
    if RE_URL.match(v):      return "url"
    if RE_PATH.match(v):     return "path"
    if RE_DURATION.match(v): return "duration"
    if RE_BYTES.match(v):    return "bytes"
    # IPv6 must come after MAC/duration: both can look colon-ish / hex-ish
    if ":" in v and RE_IPV6.match(v) and v.count(":") >= 2: return "ipv6"
    # "1.363894" is a decimal, not an FQDN. Anything made only of digits and
    # dots is a number however many dots it has.
    if RE_FQDN.match(v) and not re.fullmatch(r"[\d.]+", v): return "host"
    if RE_HEX.match(v):      return "hex"
    if RE_INT.match(v) or RE_FLOAT.match(v): return "num"
    if RE_HOSTNAME.match(v): return "host_or_word"
    return None


def _role_of(key: str) -> str:
    """Strip type tokens from a key, keep the role words, e.g. remote_addr -> remote."""
    parts = [p for p in _SPLIT.split(key.lower()) if p]
    kept = []
    for p in parts:
        if p in TYPE_TOKENS:
            if TYPE_TOKENS[p] is None and p in ROLE_WORDS:
                kept.append(p)
            continue
        kept.append(p)
    return "_".join(kept)


def _key_type_hint(key: str):
    for p in _SPLIT.split(key.lower()):
        t = TYPE_TOKENS.get(p)
        if t:
            return t
    return None


def normalize_fields(kv: dict) -> dict:
    """Rename extracted fields to canonical, role-preserving names.

    Never drops information: an unrecognised field keeps its original key, and a
    collision keeps the original key alongside the canonical one.
    """
    if not kv:
        return kv
    out = {}
    primaries = {}   # canonical type -> first value seen, for the bare alias

    for key, value in kv.items():
        vtype = classify_value(value)
        hint = _key_type_hint(key)

        # Deliberately NOT upgrading a bare number using the key's own type word.
        # The key already carries that information, so renaming only destroys it:
        # prompt_ms -> prompt_duration loses "milliseconds", and dst_port is
        # already canonical. Only a value that identifies its OWN type is renamed.
        if vtype in ("host", "host_or_word"):
            # Require the KEY to suggest a host. Value shape alone is not enough:
            # dotted strings are everywhere (versions, package names, decimals,
            # java/obj-c class names), and "com.apple.authd" under key "name" is a
            # process, not a hostname. Tested against real rows -- inferring from
            # shape alone produced client_id -> client_host and name -> name_host.
            vtype = "host" if (hint == "host" or role_implies_host(key)) else None
        if vtype in ("num", "hex"):
            # Deliberately NOT canonicalised. Appending _num to every integer is
            # noise and destroys meaning: reconnect_time reads better than
            # reconnect_num, and errno better than errno_num. Only numbers whose
            # KEY names a specific type (port/pid/bytes/duration) are renamed,
            # which is handled above.
            vtype = None
        if vtype == "ip_port":
            m = RE_IPV4_PORT.match(str(value))
            role = _role_of(key)
            out[f"{role}_ip" if role else "ip"] = m.group(1)
            out[f"{role}_port" if role else "port"] = m.group(2)
            primaries.setdefault("ip", m.group(1))
            primaries.setdefault("port", m.group(2))
            continue

        if not vtype:
            out[key] = value                      # unknown shape: leave alone
            continue

        role = _role_of(key)
        canon = f"{role}_{vtype}" if role else vtype
        if canon in out and out[canon] != value:
            out[key] = value                      # collision: keep both
        else:
            out[canon] = value
        primaries.setdefault(vtype, value)

    # bare aliases so consumers expecting a single key keep working
    for t in ("ip", "host", "port", "path", "user", "url", "mac", "uuid"):
        if t in primaries and t not in out:
            out[t] = primaries[t]
    return out
