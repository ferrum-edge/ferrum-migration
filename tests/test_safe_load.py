import os
import tempfile
import unittest

from helpers import migrate  # noqa: F401  (ensures src/ is importable)

from ferrum_migration.errors import InputError
from ferrum_migration.limits import Limits
from ferrum_migration.redact import is_secret_reference, safe_label, sanitize_parser_message
from ferrum_migration.safe_load import load_structured, read_input


class SafeLoadTest(unittest.TestCase):
    def load(self, text, fmt="yaml", multi=False, limits=None):
        return load_structured(text, fmt, limits or Limits(), allow_multi=multi)

    def test_duplicate_yaml_keys_rejected(self):
        with self.assertRaises(InputError) as caught:
            self.load("a: 1\nb: 2\na: 3\n")
        self.assertIn("duplicate", str(caught.exception))
        self.assertIn("line 3", str(caught.exception))

    def test_nested_duplicate_keys_rejected(self):
        with self.assertRaises(InputError):
            self.load("outer:\n  k: 1\n  k: 2\n")

    def test_merge_keys_rejected(self):
        with self.assertRaises(InputError):
            self.load("base: &b {x: 1}\nother:\n  <<: *b\n  y: 2\n")

    def test_alias_expansion_bomb_rejected(self):
        lines = ['a: &a ["x","x","x","x","x","x","x","x","x","x"]']
        previous = "a"
        for name in "bcdef":
            lines.append(f"{name}: &{name} [" + ",".join([f"*{previous}"] * 10) + "]")
            previous = name
        with self.assertRaises(InputError):
            self.load("\n".join(lines) + "\n", limits=Limits(max_nodes=100_000))

    def test_alias_count_limit(self):
        text = "a: &a 1\nb: [" + ",".join(["*a"] * 100) + "]\n"
        with self.assertRaises(InputError):
            self.load(text)

    def test_depth_limit(self):
        with self.assertRaises(InputError):
            self.load("[" * 100 + "]" * 100)

    def test_multi_document_policy(self):
        with self.assertRaises(InputError):
            self.load("a: 1\n---\nb: 2\n")
        self.assertEqual(len(self.load("a: 1\n---\nb: 2\n", multi=True)), 2)

    def test_unsafe_and_unusual_tags_rejected(self):
        for text in ("x: !!binary aGVsbG8=\n", "x: !!python/object:os.system {}\n", "x: !!set {a: null}\n"):
            with self.assertRaises(InputError):
                self.load(text)

    def test_timestamps_stay_strings(self):
        self.assertEqual(self.load("when: 2026-11-23\n")[0], {"when": "2026-11-23"})

    def test_json_duplicates_and_nan(self):
        with self.assertRaises(InputError):
            self.load('{"a": 1, "a": 2}', "json")
        with self.assertRaises(InputError):
            self.load('{"a": NaN}', "json")

    def test_toml_duplicates(self):
        with self.assertRaises(InputError):
            self.load("a = 1\na = 2\n", "toml")

    def test_syntax_errors_do_not_echo_content(self):
        secret = "test-only-secret-value-9f8e7d"
        with self.assertRaises(InputError) as caught:
            self.load(f'token: "{secret}"\nkey: value: oops\n')
        self.assertNotIn(secret, str(caught.exception))
        with self.assertRaises(InputError) as caught:
            self.load('{"password": "' + secret + '", }', "json")
        self.assertNotIn(secret, str(caught.exception))
        with self.assertRaises(InputError) as caught:
            self.load(f'password = "{secret}"\npassword2 = \n', "toml")
        self.assertNotIn(secret, str(caught.exception))

    def test_read_input_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "big.yaml")
            with open(path, "wb") as handle:
                handle.write(b"a: " + b"x" * 100 + b"\n")
            with self.assertRaises(InputError):
                read_input(path, Limits(max_input_bytes=50))
            with open(path, "wb") as handle:
                handle.write(b"a: 1\x00\n")
            with self.assertRaises(InputError):
                read_input(path, Limits())
            with open(path, "wb") as handle:
                handle.write(b"a: \xff\xfe\n")
            with self.assertRaises(InputError):
                read_input(path, Limits())
            with self.assertRaises(InputError):
                read_input(directory, Limits())
            with open(path, "wb") as handle:
                handle.write("﻿a: 1\n".encode("utf-8"))
            self.assertEqual(read_input(path, Limits()), "a: 1\n")


class RedactionTest(unittest.TestCase):
    def test_quoted_spans_withheld(self):
        message = sanitize_parser_message("found unexpected 'sekrit-123' near \"token-abc\"")
        self.assertNotIn("sekrit", message)
        self.assertNotIn("token-abc", message)

    def test_safe_label(self):
        self.assertEqual(safe_label("orders-api"), "orders-api")
        self.assertEqual(safe_label("-----BEGIN PRIVATE KEY-----abc"), "<redacted>")
        self.assertEqual(safe_label("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"), "<redacted>")
        self.assertNotIn("\n", safe_label("a\nb"))

    def test_secret_reference(self):
        self.assertTrue(is_secret_reference("prefix:{vault://env/x}"))
        self.assertFalse(is_secret_reference("plain"))


if __name__ == "__main__":
    unittest.main()
