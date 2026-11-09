"""Contract checks for the architecture-independent SubBoost LuCI package."""
import json
from pathlib import Path
import unittest

PACKAGE = Path(__file__).resolve().parents[1] / "luci-app-subboost"


class LuCIPackageTests(unittest.TestCase):
    def test_package_uses_luci_toolchain(self):
        content = (PACKAGE / "Makefile").read_text()
        self.assertIn("feeds/luci/luci.mk", content)
        self.assertIn("LUCI_DEPENDS:=+luci-base", content)

    def test_luci_menu_and_acl(self):
        menu = json.loads((PACKAGE / "root/usr/share/luci/menu.d/luci-app-subboost.json").read_text())
        acl = json.loads((PACKAGE / "root/usr/share/rpcd/acl.d/luci-app-subboost.json").read_text())
        self.assertEqual(menu["admin/services/subboost"]["action"]["path"], "subboost/settings")
        self.assertIn("nikki-rs", acl["luci-app-subboost"]["write"]["uci"])
        self.assertIn("subboost", acl["luci-app-subboost"]["write"]["uci"])

    def test_uci_and_nikki_integration(self):
        config = (PACKAGE / "root/etc/config/subboost").read_text()
        view = (PACKAGE / "htdocs/luci-static/resources/view/subboost/settings.js").read_text()
        self.assertIn("config settings 'main'", config)
        self.assertIn("subboost_source", view)
        self.assertIn("uci.add('nikki-rs', 'subscription')", view)
        self.assertIn("uci.apply()", view)
        self.assertIn("'clash-rs'", view)
        self.assertIn("validHttpUrl", view)


    def test_target_url_canonicalization_and_idempotent_sync(self):
        import shutil
        import subprocess
        if not shutil.which("node"):
            self.skipTest("node unavailable")
        source = (PACKAGE / "htdocs/luci-static/resources/view/subboost/settings.js").read_text()
        functions = source[source.index("function validHttpUrl(value)"):source.index("function feedback(message, level)")]
        script = functions + r"""
const assert = require('node:assert/strict');
const url = 'https://test.example/prefix/api/subscriptions/TOKEN/config.yaml';
assert.equal(forNikkiRs(url), url + '?target=clash-rs');
assert.equal(forNikkiRs(url + '?target=nikki-rs'), url + '?target=clash-rs');
assert.equal(forNikkiRs('https://test.example/other.yaml'), 'https://test.example/other.yaml');
assert(sameNikkiRsSubscription(url + '?q=2&target=nikki-rs',
  url + '?target=clash-rs&q=2'));
assert(!sameNikkiRsSubscription(url, url.replace('TOKEN', 'SECOND')));
assert(!sameNikkiRsSubscription(url, 'ftp://test.example/api/subscriptions/TOKEN/config.yaml'));
"""
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
