import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
import tool

ROOT = Path(__file__).parent

def fixture(name="good"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())

class CLITests(unittest.TestCase):
    def run_tool(self, raw):
        return subprocess.run([sys.executable, str(ROOT / "tool.py")], input=raw, capture_output=True, text=True)

    def test_cli_fixture_exit_codes(self):
        for name, code in [("good", 0), ("bad", 1)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--input", str(ROOT / "examples" / (name + ".json"))], capture_output=True, text=True)
            self.assertEqual(run.returncode, code, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["ok"], code == 0)
            self.assertEqual(run.stderr, "")

    def test_cli_argument_errors_are_json_and_redacted(self):
        secret = "PRIVATE_ARGUMENT_MARKER"
        for arguments in [("--unknown", secret), ("--input",),
                          ("--pretty=" + secret,), (secret,)]:
            run = subprocess.run([sys.executable, str(ROOT / "tool.py"), *arguments],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stderr, "")
            self.assertNotIn(secret, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_cli_help_remains_text_and_success(self):
        run = subprocess.run([sys.executable, str(ROOT / "tool.py"), "--help"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stderr, "")
        self.assertIn("--input", run.stdout)

    def test_large_json_integer_is_safe_error(self):
        run=self.run_tool('{"number":'+'9'*5000+'}')
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')
        self.assertEqual(json.loads(run.stdout)['error']['code'],'invalid_input')

    def test_nonregular_input_file(self):
        run=subprocess.run([sys.executable,str(ROOT/'tool.py'),'--input',str(ROOT)],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertEqual(run.stderr,'')

    def test_bad_json(self):
        for raw in ['{', '{"x":1,"x":2}', '[]', '{"x":NaN}', '"' + 'x' * (tool.MAX_BYTES + 1) + '"']:
            run = self.run_tool(raw)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"]["code"], "invalid_input")

    def test_unknown_field_and_boolean_number(self):
        obj = fixture(); obj["unrecognized"] = 1
        with self.assertRaises(tool.InputError): tool.audit(obj)

    def test_output_is_deterministic(self):
        raw=json.dumps(fixture())
        self.assertEqual(self.run_tool(raw).stdout, self.run_tool(raw).stdout)

import hashlib
class LinkTests(unittest.TestCase):
    def test_quoted_comma_keeps_two_links(self):
        self.assertEqual(tool.audit(fixture())['link_count'],2)
    def test_uri_comma_is_not_separator(self):
        d=fixture(); d['link_headers']=['</x,y>; rel=next']
        self.assertEqual(tool.audit(d)['link_count'],1)
    def test_relative_resolution_and_query_not_echoed(self):
        d=fixture(); d['link_headers']=['<../next?q=PRIVATE_TOKEN>; rel=next']
        out=tool.audit(d); target=out['links'][0]['target']
        self.assertEqual(target['uri_sha256'],hashlib.sha256(b'https://api.example/next?q=PRIVATE_TOKEN').hexdigest())
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(out))
    def test_anchor_context(self):
        d=fixture(); d['link_headers']=['</next>; rel=next; anchor="../context"']
        self.assertEqual(tool.audit(d)['links'][0]['context']['uri_sha256'],hashlib.sha256(b'https://api.example/context').hexdigest())
    def test_duplicate_rel_first_wins(self):
        out=tool.audit(fixture('bad')); self.assertFalse(out['ok'])
        self.assertEqual(out['links'][0]['relations'],[{'registered_form':'next'}])
    def test_hreflang_can_repeat(self):
        d=fixture(); d['link_headers']=['</next>; rel=next; hreflang=en; hreflang=fr']
        self.assertTrue(tool.audit(d)['ok'])
    def test_multiple_space_and_case_relations(self):
        d=fixture(); d['link_headers']=['</next>; rel="NEXT  prev"']
        self.assertTrue(tool.audit(d)['ok']); self.assertEqual(len(tool.audit(d)['links'][0]['relations']),2)
    def test_escaped_quote(self):
        d=fixture(); d['link_headers']=['</next>; rel=next; title="a\\\"b,c"']
        self.assertTrue(tool.audit(d)['ok'])
    def test_extension_relation_not_followed(self):
        d=fixture(); d['link_headers']=['</next>; rel="https://rel.example/type"']
        self.assertTrue(tool.audit(d)['ok'])
    def test_missing_relation(self):
        d=fixture(); d['link_headers']=['</next>; title=x']
        self.assertFalse(tool.audit(d)['ok'])
    def test_empty_target_resolves_to_base(self):
        d=fixture(); d['link_headers']=['<>; rel=self']
        self.assertTrue(tool.audit(d)['ok'])
    def test_target_userinfo_is_reported_not_echoed(self):
        d=fixture(); d['link_headers']=['<https://u:PRIVATE_TOKEN@api.example/x>; rel=next']
        out=tool.audit(d); self.assertFalse(out['ok']); self.assertNotIn('PRIVATE_TOKEN',json.dumps(out))
    def test_port_zero_not_replaced(self):
        self.assertEqual(tool.uri_metadata('http://api.example:0/x','http://api.example/')['port'],0)
    def test_invalid_syntax(self):
        for value in ['</x>; rel="next','</x rel=next','</x>; rel=next,','</x>; rel=next garbage','</bad%GG>; rel=next','<https://[bad]/>; rel=next','<ftp://api.example/>; rel=next']:
            d=fixture(); d['link_headers']=[value]
            with self.assertRaises(tool.InputError): tool.audit(d)
    def test_limits(self):
        d=fixture(); d['link_headers']=['</x>; rel=next']*21
        with self.assertRaises(tool.InputError): tool.audit(d)

    def test_empty_query_fragment_resolution(self):
        base='https://api.example/a/b?old#prior'
        cases={'?':'https://api.example/a/b?', '#':'https://api.example/a/b?old#',
               '?#':'https://api.example/a/b?#', '':'https://api.example/a/b?old',
               '../next':'https://api.example/next','b//c':'https://api.example/a/b//c',
               'https://api.example/a/../x':'https://api.example/x'}
        for reference,expected in cases.items():
            self.assertEqual(tool.uri_metadata(reference,base)['uri_sha256'],hashlib.sha256(expected.encode()).hexdigest())
    def test_invalid_authority_forms(self):
        for reference in ['http:relative','https:/path','https://a..b/','https://-x.example/','https://[::1]tail/','https://127.1/','https://xn--/']:
            with self.assertRaises(tool.InputError): tool.uri_metadata(reference,'https://api.example/')
if __name__=='__main__': unittest.main()
