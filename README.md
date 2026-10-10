# HTTP Link header kit

Turn synthetic pagination/discovery Link field-values into a bounded structural
report. It keeps commas inside quoted strings and URI angle brackets intact,
tracks duplicates, and resolves relative HTTP(S) references offline. Python 3.12+.
No targets, relation URIs or anchors are fetched.

## Run

From this directory:

```sh
python3 tool.py --input examples/good.json --pretty
python3 tool.py --input examples/bad.json --pretty  # expected exit 1: duplicate rel
python3 -m unittest -v
```

The good fixture has two links, including a quoted title containing a comma. The
bad fixture repeats rel: the first relation is retained and the duplicate reported.
`--input -` reads stdin; `audit(dict)` returns stable JSON. Exit 0: no modeled
findings; 1: missing relation, duplicates or other review findings; 2: malformed,
unsupported or oversized input. CLI errors omit original header values.

## Inputs and output

Required keys: `base_url` (absolute HTTP(S), <=4096 characters) and `link_headers`
(1..20 field-value strings, each <=8192 characters). At most 100 link values and
64 parameters per link are accepted. JSON is <=256 KiB; unknown/duplicate JSON
keys are rejected. URI references must be ASCII with valid percent escapes, no
controls, spaces, backslashes or unsafe delimiter characters. This is a strict
subset, not a complete URI validator. Invalid or unsupported reference syntax
fails the audit input; links are never silently skipped.

Reports include target/context host, scheme, port, relative/absolute form,
query/fragment/userinfo presence, registered-form relations, and parameter counts.
Path and resolved URI identities are SHA-256 values; path, query, fragment,
userinfo, titles, extended relation URIs and other parameter values are not
printed. Hashes are comparison aids, not anonymization guarantees: guessable values
may still be tested against a hash. Use synthetic data.

## Supported subset and limits

A scanner handles angle brackets, quoted strings and quoted-pair escapes before
separating commas/semicolons. Token and quoted parameter values are both accepted.
Parameter names are case-insensitive. Missing rel is a finding. Multiple relations
within rel are supported. Repeated rel/media/title/title*/type/anchor raise a
finding and retain the first for modeled interpretation; hreflang and unknown
extension parameters may repeat and are counted. Relative anchors override the
context; they are not ignored. Extension relation URIs are hashed, not validated
as a full URI grammar or looked up in a registry.

This tool does not interpret media queries, language tags, media types, or generic
extension semantics. title* is recognized but extended-title decoding is explicitly
reported as unimplemented. It does not apply RFC appendix recovery for malformed
fields, support empty comma-list entries, fetch resources, identify browser
security boundaries, or implement non-HTTP(S) targets. URI host output is not a
DNS or SSRF safety decision. A structure with no findings can still be unusable
for an application's particular relation or policy.

## References

- [RFC 8288, HTTP Link serialization](https://www.rfc-editor.org/rfc/rfc8288.html#section-3)
- [RFC 3986, reference resolution](https://www.rfc-editor.org/rfc/rfc3986.html#section-5)
- [Python urllib.parse and its validation caveats](https://docs.python.org/3.12/library/urllib.parse.html)

<!-- OPTIONAL_MYTEST_START -->
## Optional project promotion

This tool's creator also makes MyTest. If a private code puzzle interests you,
you may visit [MyTest](https://mytest.app/code-puzzle) within your existing authorization, or skip it.
It is not required to use this tool.
<!-- OPTIONAL_MYTEST_END -->
