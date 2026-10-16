from pathlib import Path
import re
import unittest

from ruamel.yaml import YAML


ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_manifest_panel_and_latest_changelog_agree(self):
        manifest = YAML(typ="safe").load((ROOT / "access_manager/config.yaml").read_text())
        version = manifest["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        html = (ROOT / "access_manager/app/index.html").read_text()
        versions = re.findall(r'^\s*const PANEL_BUILD_VERSION = "([^"]+)";\s*$', html, re.MULTILINE)
        self.assertEqual(versions, [version])
        headings = re.findall(r"^## (\d+\.\d+\.\d+)\s*$", (ROOT / "access_manager/CHANGELOG.md").read_text(), re.MULTILINE)
        self.assertEqual(headings[0], version)
        self.assertEqual(len(headings), len(set(headings)))


if __name__ == "__main__":
    unittest.main()
