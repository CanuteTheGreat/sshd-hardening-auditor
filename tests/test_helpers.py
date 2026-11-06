"""Direct tests of sshd_audit's small predicates and parsers, imported by their real module name (mutmut
maps tests to mutants through it): boolean/number/time checks, MaxStartups, GSSAPI algorithm prefixes,
`Include` expansion (relative and absolute, comments, several patterns, the nesting limit) and RSA host
key sizes."""
import base64
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sshd_audit as sa  # noqa: E402


class TestPredicates(unittest.TestCase):
    def test_bool_true(self):
        for v in ("yes", "YES", " true ", "TRUE", "True", "1"):
            self.assertTrue(sa._bool_true(v), v)
        for v in ("no", "false", "0", "", "2", "maybe", None):
            self.assertFalse(sa._bool_true(v), v)

    def test_bool_false(self):
        for v in ("no", "NO", " false ", "FALSE", "False", "0"):
            self.assertTrue(sa._bool_false(v), v)
        for v in ("yes", "true", "1", "", "2", "maybe", None):
            self.assertFalse(sa._bool_false(v), v)

    def test_int_at_most_and_at_least(self):
        at_most, at_least = sa._int_at_most(3), sa._int_at_least(3)
        self.assertEqual([at_most(v) for v in ("2", "3", " 3 ", "4", "x", "", None)],
                         [True, True, True, False, False, False, False])
        self.assertEqual([at_least(v) for v in ("2", "3", " 3 ", "4", "x", "", None)],
                         [False, True, True, True, False, False, False])

    def test_between_includes_both_ends_and_rejects_junk(self):
        f = sa._between(1, 10)
        self.assertEqual([f(v) for v in ("0", "1", "5", "10", "11", "x", "", None)],
                         [False, True, True, True, False, False, False, False])
        g = sa._between(60, 120, sa._seconds)
        self.assertEqual([g(v) for v in ("59", "60", "1m30", "2m", "121", "1x", None)],
                         [False, True, True, True, False, False, False])

    def test_seconds_formats(self):
        self.assertIsNone(sa._seconds(None))
        self.assertIsNone(sa._seconds(""))
        self.assertIsNone(sa._seconds("  "))
        self.assertEqual(sa._seconds("90"), 90)
        self.assertEqual(sa._seconds("90s"), 90)
        self.assertEqual(sa._seconds("1m30s"), 90)
        self.assertEqual(sa._seconds("1m30"), 90)
        self.assertEqual(sa._seconds("2H"), 7200)
        self.assertEqual(sa._seconds("1d"), 86400)
        self.assertEqual(sa._seconds("1w"), 604800)
        self.assertEqual(sa._seconds("1w1d1h1m1s"), 604800 + 86400 + 3600 + 60 + 1)
        for bad in ("m", "s5", "1x", "1m-5", "abc", "1.5m"):
            self.assertIsNone(sa._seconds(bad), bad)

    def test_maxstartups(self):
        ok = sa._maxstartups_ok
        self.assertFalse(ok(None))
        self.assertTrue(ok("10"))
        self.assertTrue(ok(" 10 "))
        self.assertFalse(ok("11"))
        self.assertFalse(ok("x"))
        self.assertTrue(ok("10:30:60"))
        self.assertTrue(ok("5:100:20"))
        self.assertFalse(ok("11:30:60"))
        self.assertFalse(ok("10:29:60"))
        self.assertFalse(ok("10:30:61"))
        self.assertFalse(ok("10:30"))
        self.assertFalse(ok("10:30:60:1"))
        self.assertFalse(ok("10:x:60"))

    def test_gssapi_kex_names_match_by_prefix(self):
        pol = sa.ALGORITHM_POLICY["kexalgorithms"]
        prefixes = [p for p in pol if p.endswith("-")]
        self.assertTrue(prefixes)
        for p in prefixes:
            self.assertEqual(sa._alg_policy("kexalgorithms", p + "gssapi-mech"), pol[p], p)
        self.assertIsNone(sa._alg_policy("kexalgorithms", "curve25519-sha256"))
        self.assertIsNone(sa._alg_policy("kexalgorithms", "ecdh-sha2-nistp256x"))
        exact = [p for p in pol if not p.endswith("-")][0]
        self.assertEqual(sa._alg_policy("kexalgorithms", exact), pol[exact])


class TestIncludes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def w(self, name, text):
        path = os.path.join(self.d, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_relative_and_absolute_includes_and_several_patterns(self):
        a, b = self.w("a.conf", "A 1\n"), self.w("b.conf", "B 2\n")
        self.w("c.conf", "C 3\n")
        text = "Top 0\nInclude a.conf b.conf\ninclude %s\nTail 9\n" % b
        self.assertEqual(sa._expand_includes(text, 0, self.d), ["Top 0", "A 1", "B 2", "B 2", "Tail 9"])
        self.assertEqual(sa._expand_includes("Include *.conf\n", 0, self.d), ["A 1", "B 2", "C 3"])
        self.assertEqual(sa._expand_includes("Include %s\n" % a, 0, "/nonexistent"), ["A 1"])
        self.assertEqual(sa._expand_includes("Include missing.conf\nX 1\n", 0, self.d), ["X 1"])

    def test_comment_after_include_is_not_a_pattern_and_line_is_kept_verbatim(self):
        self.w("a.conf", "A 1\n")
        self.w("b.conf", "B 2\n")
        self.assertEqual(sa._expand_includes("Include a.conf # b.conf # c.conf\n", 0, self.d), ["A 1"])
        self.assertEqual(sa._expand_includes("# Include a.conf\n  Keep  me # note\n", 0, self.d),
                         ["# Include a.conf", "  Keep  me # note"])
        self.assertEqual(sa._expand_includes("Includes a.conf\nInclude\n", 0, self.d), ["Includes a.conf", "Include"])

    def chain(self, n):
        for k in range(n):
            self.w("f%d.conf" % k, "L%d\nInclude f%d.conf\n" % (k, k + 1))
        self.w("f%d.conf" % n, "L%d\n" % n)
        return os.path.join(self.d, "f0.conf")

    def test_nesting_is_allowed_to_depth_16_with_relative_includes_all_the_way(self):
        start = self.chain(16)
        self.assertEqual(sa._read_with_includes(start, 0, self.d), ["L%d" % k for k in range(17)])
        self.assertEqual(sa._read_with_includes(start, base_dir=self.d), ["L%d" % k for k in range(17)])

    def test_nesting_deeper_than_16_is_an_error_naming_the_file(self):
        start = self.chain(17)
        with self.assertRaises(ValueError) as cm:
            sa._read_with_includes(start, 0, self.d)
        self.assertEqual(str(cm.exception), "Include nesting too deep at %s" % os.path.join(self.d, "f17.conf"))
        with self.assertRaises(ValueError):
            sa._read_with_includes(self.w("x.conf", "X\n"), 17, self.d)
        self.assertEqual(sa._read_with_includes(self.w("y.conf", "Y\n"), 16, self.d), ["Y"])

    def test_self_include_is_an_error(self):
        path = self.w("loop.conf", "Include loop.conf\n")
        with self.assertRaises(ValueError):
            sa._read_with_includes(path, 0, self.d)


class TestRsaBits(unittest.TestCase):
    @staticmethod
    def blob(*fields):
        return base64.b64encode(b"".join(struct.pack(">I", len(f)) + f for f in fields)).decode()

    def test_bits_of_the_modulus(self):
        n2048 = (1 << 2047) | 12345
        n4096 = (1 << 4095) | 1
        e = (65537).to_bytes(3, "big")
        self.assertEqual(sa._rsa_bits_from_pub(self.blob(b"ssh-rsa", e, b"\x00" + n2048.to_bytes(256, "big"))), 2048)
        self.assertEqual(sa._rsa_bits_from_pub(self.blob(b"ssh-rsa", e, n4096.to_bytes(512, "big"))), 4096)
        self.assertEqual(sa._rsa_bits_from_pub(self.blob(b"ssh-rsa", e, b"\x01\x00")), 9)

    def test_truncated_key_is_an_index_error(self):
        with self.assertRaises(IndexError):
            sa._rsa_bits_from_pub(self.blob(b"ssh-rsa", b"\x01\x00\x01"))


if __name__ == "__main__":
    unittest.main()
