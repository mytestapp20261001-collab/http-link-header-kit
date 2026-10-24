#!/usr/bin/env python3
"""Bounded offline audit. No network access or external state changes."""
import argparse
import json
import math
import re
import sys
import stat
from pathlib import Path

MAX_BYTES = 262144
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

class InputError(ValueError):
    pass

class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse messages may contain raw options, paths, or caller secrets.
        raise InputError("invalid command-line arguments")

def require(condition, message):
    if not condition:
        raise InputError(message)

def schema(data, required, optional=()):
    require(isinstance(data, dict), "input must be an object")
    require(set(required) <= data.keys(), "missing required input field")
    require(data.keys() <= set(required) | set(optional), "unknown input field")

def integer(value, minimum=0, maximum=253402300799):
    require(type(value) is int and minimum <= value <= maximum, "integer outside supported range")
    return value

def string(value, limit=8192):
    require(isinstance(value, str) and len(value) <= limit, "string outside supported length")
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "invalid Unicode scalar")
    return value

def header(value):
    string(value)
    require(not any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value), "header contains control characters")
    return value

def result(findings, **fields):
    return {"schema_version": 1, "ok": not findings, "findings": findings, **fields}

def issue(code, **extra):
    return {"code": code, **extra}

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj

def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--input", default="-", help="JSON file, or - for stdin (maximum 256 KiB)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = None
    try:
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            require(stat.S_ISREG(Path(args.input).stat().st_mode), "input path must be a regular file")
            with open(args.input, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "input exceeds 256 KiB")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError("non-finite JSON number")))
        out = audit(data)
    except InputError as exc:
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": str(exc)}}
        code = 2
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError):
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": "unreadable, malformed, or excessively nested input"}}
        code = 2
    else:
        code = 0 if out["ok"] else 1
    print(json.dumps(out, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2 if args is not None and args.pretty else None))
    return code

def split_quoted(value, delimiter=","):
    parts, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == delimiter and not quoted:
            parts.append(value[start:index].strip(" \t")); start = index + 1
    require(not quoted and not escaped, "unterminated quoted string")
    parts.append(value[start:].strip(" \t"))
    return parts

def parameter_value(raw):
    if raw.startswith('"'):
        require(len(raw) >= 2 and raw.endswith('"'), "invalid quoted value")
        out, escaped = [], False
        for char in raw[1:-1]:
            if escaped:
                out.append(char); escaped = False
            elif char == "\\":
                escaped = True
            else:
                require(char != '"', "unescaped quote")
                out.append(char)
        require(not escaped, "unterminated quoted escape")
        return "".join(out)
    require(bool(TOKEN.fullmatch(raw)), "invalid token value")
    return raw

import hashlib
from urllib.parse import urlsplit, urljoin


def uri_metadata(reference, base):
    """Resolve an ASCII HTTP(S) reference without losing empty ?/# delimiters."""
    import ipaddress

    def checked_parts(value):
        string(value, 4096)
        require(value.isascii() and not any(
            ord(c) <= 32 or c in '<>"\\{}|^`' or ord(c) == 127 for c in value
        ), 'unsupported URI-reference characters')
        require(not re.search(r'%(?![0-9A-Fa-f]{2})', value), 'malformed URI percent escape')
        parts = urlsplit(value)
        # RFC 3986 sections 3.3 and 4.2: path-noscheme starts with a
        # segment without a literal colon. urllib.parse is only a splitter.
        if not parts.scheme and not parts.netloc and not parts.path.startswith('/'):
            require(':' not in parts.path.split('/', 1)[0],
                    'colon in first relative-path segment')
        return parts, '?' in value.split('#', 1)[0], '#' in value

    def dot_segments(path):
        # RFC 3986 section 5.2.4. Repeated slashes and trailing slashes survive.
        output = ''
        while path:
            if path.startswith('../'):
                path = path[3:]
            elif path.startswith('./'):
                path = path[2:]
            elif path.startswith('/./'):
                path = path[2:]
            elif path == '/.':
                path = '/'
            elif path.startswith('/../'):
                path = path[3:]
                output = output.rpartition('/')[0]
            elif path == '/..':
                path = '/'
                output = output.rpartition('/')[0]
            elif path in ('.', '..'):
                path = ''
            else:
                end = path.find('/', 1 if path.startswith('/') else 0)
                if end < 0:
                    output += path
                    path = ''
                else:
                    output += path[:end]
                    path = path[end:]
        return output

    def authority(parts):
        require(parts.scheme in ('http', 'https') and bool(parts.netloc),
                'resolved URI must have an HTTP(S) authority')
        require(parts.netloc.count('@') <= 1, 'ambiguous URI userinfo')
        host = parts.hostname
        require(bool(host) and '%' not in host, 'encoded, scoped, or missing host unsupported')
        hostport = parts.netloc.rsplit('@', 1)[-1]
        port = parts.port
        if hostport.startswith('['):
            close = hostport.find(']')
            suffix = hostport[close + 1:]
            require(close >= 0 and (not suffix or re.fullmatch(r':[0-9]+', suffix)),
                    'invalid bracketed authority')
            host = str(ipaddress.IPv6Address(host))
        else:
            require('[' not in hostport and ']' not in hostport and ':' not in host,
                    'invalid IP literal')
            if ':' in hostport:
                require(bool(re.fullmatch(r'[0-9]+', hostport.rsplit(':', 1)[1])),
                        'invalid explicit port')
            try:
                host = str(ipaddress.IPv4Address(host))
            except ValueError:
                bare = host[:-1] if host.endswith('.') else host
                labels = bare.split('.')
                require(1 <= len(bare) <= 253 and all(
                    re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in labels
                ), 'invalid DNS host')
                require(not re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]*)', labels[-1]),
                        'ambiguous numeric host unsupported')
                for label in labels:
                    if label.startswith('xn--'):
                        require(label.encode('ascii').decode('idna').encode('idna').decode('ascii') == label,
                                'invalid IDNA host')
        return host, port if port is not None else (443 if parts.scheme == 'https' else 80)

    try:
        b, base_query, _ = checked_parts(base)
        authority(b)
        parsed, ref_query, ref_fragment = checked_parts(reference)
        require(not parsed.scheme or parsed.scheme in ('http', 'https'),
                'only HTTP(S) targets are supported')
        require(not reference.startswith('//') or bool(parsed.netloc),
                'empty reference authority unsupported')
        if parsed.scheme:
            authority(parsed)
            scheme, netloc = parsed.scheme, parsed.netloc
            path, query, has_query = dot_segments(parsed.path), parsed.query, ref_query
        elif parsed.netloc:
            scheme, netloc = b.scheme, parsed.netloc
            path, query, has_query = dot_segments(parsed.path), parsed.query, ref_query
        else:
            scheme, netloc = b.scheme, b.netloc
            if not parsed.path:
                path = b.path
                query, has_query = (parsed.query, True) if ref_query else (b.query, base_query)
            else:
                merged = parsed.path if parsed.path.startswith('/') else (
                    (b.path.rsplit('/', 1)[0] + '/' if '/' in b.path else '/') + parsed.path)
                path, query, has_query = dot_segments(merged), parsed.query, ref_query
        # RFC 3986 Link references never inherit the base fragment. This differs
        # from the HTTP Location fragment-inheritance rule in RFC 9110.
        resolved = (scheme + '://' + netloc + path + ('?' + query if has_query else '') +
                    ('#' + parsed.fragment if ref_fragment else ''))
        require(len(resolved) <= 8192, 'resolved URI exceeds supported length')
        u = urlsplit(resolved)
        host, port = authority(u)
    except (ValueError, TypeError, UnicodeError):
        # InputError subclasses ValueError; keep all error text payload-free.
        raise InputError('invalid URI-reference') from None
    return {'scheme': u.scheme, 'host': host, 'port': port,
            'uri_sha256': hashlib.sha256(resolved.encode('ascii')).hexdigest(),
            'path_sha256': hashlib.sha256(u.path.encode('ascii')).hexdigest(),
            'has_query': has_query, 'has_fragment': ref_fragment,
            'has_userinfo': '@' in u.netloc,
            'reference_form': 'absolute' if parsed.scheme else 'relative'}

def split_links(value):
    pieces=[]; start=0; angle=False; quote=False; escape=False
    for i,c in enumerate(value):
        if escape: escape=False
        elif quote and c=='\\': escape=True
        elif c=='"' and not angle: quote=not quote
        elif not quote:
            if c=='<':
                require(not angle,'nested angle bracket'); angle=True
            elif c=='>':
                require(angle,'unexpected closing angle bracket'); angle=False
            elif c==',' and not angle:
                pieces.append(value[start:i].strip(' \t')); start=i+1
    require(not angle and not quote and not escape,'unterminated Link target or quote')
    pieces.append(value[start:].strip(' \t'))
    require(all(pieces),'empty Link list entry unsupported')
    return pieces


def audit(data):
    schema(data,('base_url','link_headers'))
    base=string(data['base_url'],4096)
    uri_metadata(base,base)
    try: require(bool(urlsplit(base).scheme),'base_url must be absolute')
    except ValueError as exc: raise InputError('invalid base URL') from exc
    fields=data['link_headers']
    require(isinstance(fields,list) and 1<=len(fields)<=20,'link_headers requires 1..20 values')
    pieces=[]
    for field in fields: pieces.extend(split_links(header(field)))
    require(len(pieces)<=100,'at most 100 link values supported')
    findings=[]; links=[]
    for index,piece in enumerate(pieces):
        require(piece.startswith('<') and '>' in piece,'Link target must be in angle brackets')
        end=piece.index('>'); target=piece[1:end]; rest=piece[end+1:].strip(' \t')
        require(not rest or rest.startswith(';'),'unexpected data after Link target')
        params={}
        if rest:
            for raw in split_quoted(rest[1:],';'):
                key,sep,val=raw.partition('='); key=key.strip(' \t').lower()
                require(bool(TOKEN.fullmatch(key)),'invalid Link parameter name')
                value=parameter_value(val.strip(' \t')) if sep else None
                params.setdefault(key,[]).append(value)
        require(sum(map(len,params.values()))<=64,'too many Link parameters')
        for key,values in params.items():
            if len(values)>1 and key in ('rel','media','title','title*','type','anchor'):
                findings.append(issue('duplicate_parameter_first_used',link=index,parameter=key))
        rel=params.get('rel',[None])[0]
        relationships=[]
        if not rel:
            findings.append(issue('missing_relation',link=index))
        else:
            if rel != rel.strip(' ') or '\t' in rel:
                findings.append(issue('invalid_relation_whitespace',link=index))
            for relation in (item for item in rel.split(' ') if item):
                if re.fullmatch(r'[A-Za-z][A-Za-z0-9.-]*',relation):
                    relationships.append({'registered_form':relation.lower()})
                elif relation and re.match(r'[A-Za-z][A-Za-z0-9+.-]*:',relation):
                    require(not any(c.isspace() for c in relation),'invalid extension relation')
                    relationships.append({'extension_uri_sha256':hashlib.sha256(relation.lower().encode('utf-8')).hexdigest()})
                else:
                    findings.append(issue('invalid_relation_token',link=index))
        meta=uri_metadata(target,base)
        if meta['has_userinfo']: findings.append(issue('target_contains_userinfo',link=index))
        anchor=params.get('anchor',[None])[0]
        if 'anchor' in params and anchor is None:
            findings.append(issue('anchor_requires_value',link=index))
        context=uri_metadata(anchor,base) if anchor is not None else uri_metadata(base,base)
        if 'title*' in params:
            findings.append(issue('extended_title_decoding_not_implemented',link=index))
        links.append({'index':index,'target':meta,'context':context,'relations':relationships,
                      'parameter_counts':{k:len(v) for k,v in sorted(params.items())}})
    return result(findings, links=links, link_count=len(links), raw_values_echoed=False)

if __name__ == '__main__':
    raise SystemExit(main())
