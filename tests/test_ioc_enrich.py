import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from ioc_enrich import classify, parse, refang  # noqa: E402


class TestIocEnrich(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(refang("hxxps://evil[.]example[.]com"), "https://evil.example.com")

    def test_classify(self):
        self.assertEqual(classify("8.8.8.8"), "ipv4")
        self.assertEqual(classify("example.com"), "domain")
        self.assertEqual(classify("https://example.com/a"), "url")
        self.assertEqual(classify("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256")
        self.assertEqual(classify("not an ioc"), "unknown")

    def test_parse_dedupes_and_flags_private(self):
        records = parse(["10.0.0.5\n", "10.0.0.5\n", "# comment\n", "\n", "Example[.]com\n", "example.com\n"])
        self.assertEqual(len(records), 2)
        self.assertTrue(records[0]["private"])
        self.assertEqual(records[1]["type"], "domain")


if __name__ == "__main__":
    unittest.main()
