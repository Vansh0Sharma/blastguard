"""Distribution tooling tests; no model/client or submitted shell execution."""

import hashlib
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "distribution", Path(__file__).resolve().parents[1] / "scripts/verify_distribution.py"
)
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)


def check_release_workflow(text):
    """Narrow, dependency-free guard for this workflow, not a YAML validator.

    Require canonical top-level keys and an exact manual-only trigger block.
    Ban runner expressions everywhere (stricter than checking their scope):
    temporary storage must use the shell's RUNNER_TEMP in a job step instead.
    """
    lines = [line.rstrip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    distribution.require(not any("\t" in line for line in lines), "Use space-indented YAML")
    # Also catches implicit `if: runner.os ...`, bracket access, and expressions
    # split across lines; matrix.runner is a different, allowed context.
    distribution.require(
        re.search(r"(?<![\w.])runner\s*(?:\.|\[)", "\n".join(lines), re.IGNORECASE) is None,
        "Use RUNNER_TEMP in a step, not the runner expression context",
    )
    top = [(index, line) for index, line in enumerate(lines) if not line.startswith(" ")]
    distribution.require(all(re.fullmatch(r"[A-Za-z][\w-]*:.*", line) for _, line in top),
                         "Unsupported workflow key syntax; review the static guard")
    keys = [line.split(":", 1)[0] for _, line in top]
    distribution.require(len(keys) == len(set(keys)), "Duplicate workflow key")
    distribution.require("on" in keys, "Missing workflow_dispatch trigger")
    position = keys.index("on")
    start = top[position][0]
    end = top[position + 1][0] if position + 1 < len(top) else len(lines)
    distribution.require(lines[start:end] == ["on:", "  workflow_dispatch:"],
                         "Release verification must have only workflow_dispatch")


class ReleaseWorkflowTests(unittest.TestCase):
    MANUAL = "on:\n  workflow_dispatch:\njobs:\n  native:\n    steps:\n      - run: echo checked\n"

    def test_repository_workflow_is_manual_only_without_runner_expressions(self):
        workflow = distribution.SOURCE / ".github/workflows/release-verification.yml"
        if not workflow.exists() and (distribution.SOURCE / "Cargo.toml.orig").is_file():
            # Workflows intentionally are NOT shipped in crates. All fixture
            # regression cases below still run in extracted-package validation.
            self.skipTest("Source package excludes workflows; validate the repository copy separately")
        check_release_workflow(workflow.read_text(encoding="utf-8"))

    def test_guard_allows_manual_workflow_and_shell_runner_temp(self):
        check_release_workflow(self.MANUAL.replace(
            "echo checked", 'mkdir "$RUNNER_TEMP/fixture"',
        ).replace("    steps:", "    runs-on: ${{ matrix.runner }}\n    steps:"))

    def test_guard_rejects_runner_context_in_non_step_scopes(self):
        for field in (
            "env:\n  BUILD: ${{ runner.temp }}\n",
            "concurrency: ${{ runner.os }}\n",
            "defaults:\n  run:\n    working-directory: ${{ runner.temp }}\n",
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "runner expression"):
                check_release_workflow(field + self.MANUAL)
        for field in (
            "env:\n      BUILD: ${{ runner.temp }}",
            "strategy:\n      matrix:\n        path: ['${{ runner.temp }}']",
            "concurrency: ${{ runner.os }}",
            "defaults:\n      run:\n        working-directory: ${{ runner.temp }}",
            "if: runner.os == 'Linux'",
            "name: ${{ runner['os'] }}",
            "env:\n      BUILD: ${{\n        runner.temp\n        }}",
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "runner expression"):
                check_release_workflow(self.MANUAL.replace("    steps:", f"    {field}\n    steps:"))

    def test_guard_rejects_missing_manual_trigger_and_automatic_events(self):
        for event in ("push", "pull_request", "pull_request_target", "release",
                      "schedule", "workflow_run", "create", "delete"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                check_release_workflow(self.MANUAL.replace("  workflow_dispatch:", f"  workflow_dispatch:\n  {event}:"))
        for trigger in (
            "", "on: push\n", "on: [workflow_dispatch, push]\n",
            "on: {workflow_dispatch: null, release: null}\n",
            "on:\n  push:\n    tags: ['v*']\n",
            "on:\n  push:\n    branches: ['dependabot/**']\n",
            "on:\n  workflow_dispatch:\non: push\n",
            '"on":\n  workflow_dispatch:\n',
            "? on\n: push\n",
        ):
            with self.subTest(trigger=trigger), self.assertRaises(ValueError):
                check_release_workflow(self.MANUAL.replace("on:\n  workflow_dispatch:\n", trigger))


def macho_fixture(uuid=b"0" * 16, cpu=0x100000c):
    # Data-only fixture, never executed. Two 4 KiB signed pages and one simple
    # linker-style CodeDirectory. UUID and first hash are the only exceptions.
    sig_start, sig_size = 8192, 184
    data = bytearray(sig_start + sig_size)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, cpu, 0, 2, 4, 184, 0, 0)
    for offset, name, start, size in (
        (32, b"__TEXT", 0, 4096), (104, b"__LINKEDIT", 4096, 4096 + sig_size),
    ):
        struct.pack_into("<II16sQQQQIIII", data, offset, 0x19, 72, name, 0, size,
                         start, size, 1, 1, 0, 0)
    struct.pack_into("<II16s", data, 176, 0x1b, 24, uuid)
    struct.pack_into("<4I", data, 200, 0x1d, 16, sig_start, sig_size)
    struct.pack_into(">5I", data, sig_start, 0xfade0cc0, sig_size, 1, 0, 24)
    struct.pack_into(">9I4B", data, sig_start + 24, 0xfade0c02, 160, 0x20400,
                     0x20002, 96, 88, 0, 2, sig_start, 32, 2, 0, 12)
    data[sig_start + 112:sig_start + 120] = b"fixture\0"
    return seal_fixture(data)


def seal_fixture(data):
    for index in range(2):
        start = 8192 + 120 + index * 32
        data[start:start + 32] = hashlib.sha256(data[index * 4096:(index + 1) * 4096]).digest()
    return data


def unsigned_intel_fixture(uuid=b"0" * 16):
    # Construct unsigned data directly: never strip a real or fixture signature.
    # Modern x86_64 load commands, bounded linkedit tables, final string table.
    data = bytearray(4160)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x1000007, 3, 2, 6, 288, 0x200085, 0)
    for offset, name, start, size in ((32, b"__TEXT", 0, 4096), (104, b"__LINKEDIT", 4096, 64)):
        struct.pack_into("<II16sQQQQIIII", data, offset, 0x19, 72, name, 0, size,
                         start, size, 1, 1, 0, 0)
    struct.pack_into("<II16s", data, 176, 0x1b, 24, uuid)
    struct.pack_into("<6I", data, 200, 0x2, 24, 4112, 1, 4136, 24)
    struct.pack_into("<20I", data, 224, 0xb, 80, 0, 0, 0, 1, 1, 0,
                     0, 0, 0, 0, 0, 0, 4128, 2, 0, 0, 0, 0)
    struct.pack_into("<4I", data, 304, 0x26, 16, 4096, 16)
    return data


def unsigned_intel_sections_fixture(uuid=b"0" * 16, zero_type=1, zero_size=8192):
    # Data only, never executed. TEXT has two file-backed sections, DATA one,
    # BSS one virtual-only section after the other VM segments. LINKEDIT follows
    # DATA in the file, without allocating bytes for BSS (including GB zero-fill).
    base = 0x100000000
    commands = []
    for name, vm, memory_size, start, size, protection, sections in (
        (b"__TEXT", base, 4096, 0, 4096, 5,
         ((b"__text", base + 1024, 256, 1024, 0x80000400),
          (b"__const", base + 2048, 256, 2048, 0))),
        (b"__DATA", base + 4096, 4096, 4096, 4096, 3,
         ((b"__data", base + 4096, 128, 4096, 0),)),
        (b"__LINKEDIT", base + 8192, 4096, 8192, 64, 1, ()),
        (b"__BSS", base + 12288, zero_size, 0, 0, 3,
         ((b"__bss", base + 12288, zero_size, 0, zero_type),)),
    ):
        command = struct.pack("<II16s4Q4I", 0x19, 72 + 80 * len(sections), name,
                              vm, memory_size, start, size, protection, protection, len(sections), 0)
        for section_name, address, extent, file_offset, flags in sections:
            command += struct.pack("<16s16sQQ8I", section_name, name, address, extent,
                                   file_offset, 0, 0, 0, flags, 0, 0, 0)
        commands.append(command)
    commands.extend((
        struct.pack("<II16s", 0x1b, 24, uuid),
        struct.pack("<6I", 0x2, 24, 8208, 1, 8232, 24),
        struct.pack("<20I", 0xb, 80, 0, 0, 0, 1, 1, 0,
                    0, 0, 0, 0, 0, 0, 8224, 2, 0, 0, 0, 0),
        struct.pack("<4I", 0x26, 16, 8192, 16),
        struct.pack("<IIQQ", 0x80000028, 24, 1024, 0),
    ))
    table = b"".join(commands)
    data = bytearray(8256)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x1000007, 3, 2, len(commands), len(table), 0x200085, 0)
    data[32:32 + len(table)] = table
    return data


class DistributionTests(unittest.TestCase):
    def compare(self, first, second, target="aarch64-apple-darwin"):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("one", "two")]
            for path, data in zip(paths, (first, second)):
                path.write_bytes(data)
            result = distribution.compare_builds(*paths, target)
            self.assertEqual([path.read_bytes() for path in paths], [first, second])
            return result

    def test_exact_bytes_are_compared_without_normalization(self):
        first = macho_fixture()
        report = self.compare(first, first)
        self.assertEqual(report["status"], "exact_match")
        self.assertFalse(report["reproducibility_claim"])
        self.assertEqual(report["sha256"], [hashlib.sha256(first).hexdigest()] * 2)

    def test_uuid_and_its_valid_signature_hash_are_unresolved_not_reproducible(self):
        for target, cpu in (("aarch64-apple-darwin", 0x100000c), ("x86_64-apple-darwin", 0x1000007)):
            report = self.compare(macho_fixture(cpu=cpu), macho_fixture(b"1" * 16, cpu), target)
            self.assertEqual(report["status"], "macho_metadata_only_unresolved")
            self.assertFalse(report["reproducibility_claim"])
            self.assertEqual(set(report["differing_bytes"]), {"LC_UUID", "LC_CODE_SIGNATURE_UUID_page_hash"})
            self.assertEqual(len(report["differing_bytes"]["LC_UUID"]), 16)

    def test_naturally_unsigned_intel_allows_only_uuid_differences(self):
        first, second = unsigned_intel_fixture(), unsigned_intel_fixture(b"1" * 16)
        report = self.compare(first, second, "x86_64-apple-darwin")
        self.assertEqual(report["status"], "macho_metadata_only_unresolved")
        self.assertFalse(report["reproducibility_claim"])
        self.assertEqual(set(report["differing_bytes"]), {"LC_UUID"})
        self.assertEqual(report["regions"], {"LC_UUID": (184, 200)})
        self.assertEqual(self.compare(first, first, "x86_64-apple-darwin")["status"], "exact_match")
        for offset in (1024, 4096, 4159):  # text, function starts, string table
            changed = unsigned_intel_fixture(b"1" * 16)
            changed[offset] ^= 1
            self.assertEqual(self.compare(first, changed, "x86_64-apple-darwin")["status"], "unexpected_difference")

    def test_unsigned_is_not_a_fallback_for_arm_or_unsupported_intel_headers(self):
        for offset, value in ((0, 0xcafebabe), (0, 0xcffaedfe), (8, 8), (12, 6), (28, 1)):
            changed = unsigned_intel_fixture(b"1" * 16)
            struct.pack_into("<I", changed, offset, value)
            self.assertEqual(self.compare(unsigned_intel_fixture(), changed, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")
        arm = unsigned_intel_fixture()
        struct.pack_into("<II", arm, 4, 0x100000c, 0)
        self.assertEqual(self.compare(arm, arm)["status"], "unsupported_or_invalid_macho")
        self.assertEqual(self.compare(unsigned_intel_fixture(), unsigned_intel_fixture())["status"], "unsupported_or_invalid_macho")

    def test_unsigned_intel_rejects_malformed_commands_and_linkedit_bounds(self):
        for offset, value in (
            (16, 7), (20, 280), (180, 0), (304, 0x77), (304, 0x1b),
            (144, 0), (152, 0xffffffff), (208, 4113), (208, 32),
            (212, 0xffffffff), (216, 4100), (220, 0xffffffff),
            (236, 0xffffffff), (280, 32), (284, 0xffffffff),
            (312, 32), (312, 4112), (316, 0xffffffff),
        ):
            with self.subTest(offset=offset, value=value):
                changed = unsigned_intel_fixture(b"1" * 16)
                struct.pack_into("<I", changed, offset, value)
                self.assertEqual(self.compare(unsigned_intel_fixture(), changed, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")
        # An unreferenced signature-like tail cannot masquerade as unsigned.
        tail = unsigned_intel_fixture() + b"\xfa\xde\x0c\xc0" + bytes(180)
        struct.pack_into("<Q", tail, 152, len(tail) - 4096)
        self.assertEqual(self.compare(tail, tail, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")

    def test_present_intel_signature_must_validate_even_for_identical_files(self):
        original = macho_fixture(cpu=0x1000007)
        for offset, value in ((212, 0), (208, 0), (8192, 0), (8192 + 120, 0)):
            changed = bytearray(original)
            struct.pack_into("<I", changed, offset, value)
            self.assertEqual(self.compare(original, changed, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")
            self.assertEqual(self.compare(changed, changed, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")
        changed = bytearray(original)
        struct.pack_into("<I", changed, 200, 0x77)  # disguised signature command
        self.assertEqual(self.compare(changed, changed, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")

    def test_unsigned_intel_checks_variable_load_command_bounds(self):
        def with_command(command):
            data = unsigned_intel_fixture()
            struct.pack_into("<II", data, 16, 7, 288 + len(command))
            data[320:320 + len(command)] = command
            return data

        good = (
            struct.pack("<III4s", 0xe, 16, 12, b"/a\0\0"),
            struct.pack("<6I8s", 0xc, 32, 24, 0, 0, 0, b"/lib\0\0\0\0"),
            struct.pack("<6I", 0x32, 24, 1, 0xf0000, 0xf0000, 0),
        )
        for command in good:
            data = with_command(command)
            self.assertEqual(self.compare(data, data, "x86_64-apple-darwin")["status"], "exact_match")
        bad = (
            struct.pack("<III4s", 0xc, 16, 12, b"/a\0\0"),
            struct.pack("<III4s", 0xe, 16, 100, b"/a\0\0"),
            struct.pack("<III4s", 0xe, 16, 12, b"aaaa"),
            struct.pack("<6I", 0x32, 24, 2, 0xf0000, 0xf0000, 0),
            struct.pack("<6I", 0x32, 24, 1, 0xf0000, 0xf0000, 100),
        )
        for command in bad:
            data = with_command(command)
            self.assertEqual(self.compare(data, data, "x86_64-apple-darwin")["status"], "unsupported_or_invalid_macho")

    def assert_unsigned_sections_rejected_before_matching(self, data):
        different_uuid = bytearray(data)
        different_uuid[648:664] = b"1" * 16
        for second in (data, different_uuid):
            with self.subTest(uuid_differs=second != data):
                report = self.compare(data, second, "x86_64-apple-darwin")
                self.assertEqual(report["status"], "unsupported_or_invalid_macho")
                self.assertFalse(report["reproducibility_claim"])

    def test_unsigned_section_and_entrypoint_fixtures_remain_uuid_only(self):
        for section_type, size in ((1, 8192), (0xc, (1 << 32) + 8192), (0x12, 8192)):
            with self.subTest(zero_fill_type=section_type):
                first = unsigned_intel_sections_fixture(zero_type=section_type, zero_size=size)
                second = unsigned_intel_sections_fixture(b"1" * 16, section_type, size)
                self.assertEqual(self.compare(first, first, "x86_64-apple-darwin")["status"], "exact_match")
                report = self.compare(first, second, "x86_64-apple-darwin")
                self.assertEqual(report["status"], "macho_metadata_only_unresolved")
                self.assertEqual(report["regions"], {"LC_UUID": (648, 664)})
                self.assertFalse(report["reproducibility_claim"])
        # A valid metadata change or code change still is not a UUID exception.
        first = unsigned_intel_sections_fixture()
        for field, fmt, value in ((1024, "<B", 1), (792, "<Q", 1025)):
            changed = unsigned_intel_sections_fixture(b"1" * 16)
            struct.pack_into(fmt, changed, field, value)
            self.assertEqual(self.compare(first, changed, "x86_64-apple-darwin")["status"], "unexpected_difference")

    def test_unsigned_section_ranges_reject_identical_and_uuid_different_malformed_pairs(self):
        # Section records start at 104, 184 (TEXT), 336 (DATA), and 560 (BSS).
        for field, fmt, value in (
            (152, "<I", 8257), (152, "<I", 0xffffffff), (152, "<I", 8256),
            (144, "<Q", 0xffffffffffffffff), (144, "<Q", 8256),
            (152, "<I", 4096),  # within EOF but outside the containing TEXT
            (232, "<I", 8257), (384, "<I", 8257),  # later section and segment
            (384, "<I", 1024),  # DATA must not point into another segment
            (152, "<I", 1025),  # file/VM mapping disagreement
            (152, "<I", 100),  # section content cannot alias load commands
            (136, "<Q", 0xffffffffffffffff), (120, "<16s", b"__DATA"),
            (168, "<I", 0xff),  # unknown section type cannot imply zero-fill
        ):
            with self.subTest(field=field, value=value):
                changed = unsigned_intel_sections_fixture()
                struct.pack_into(fmt, changed, field, value)
                self.assert_unsigned_sections_rejected_before_matching(changed)
        # Empty ranges still cannot point beyond EOF.
        changed = unsigned_intel_sections_fixture()
        struct.pack_into("<QI", changed, 144, 0, 8257)
        self.assert_unsigned_sections_rejected_before_matching(changed)

    def test_unsigned_zero_fill_is_virtual_only_but_must_fit_segment(self):
        for section_type in (1, 0xc, 0x12):
            for field, fmt, value in (
                (600, "<Q", 8193), (600, "<Q", 0xffffffffffffffff),
                (592, "<Q", 0xffffffffffffffff),
                (512, "<Q", 0xffffffffffffffff),  # wrapping segment VM range
                (592, "<Q", 0),  # before the containing VM segment
            ):
                with self.subTest(section_type=section_type, field=field, value=value):
                    changed = unsigned_intel_sections_fixture(zero_type=section_type)
                    struct.pack_into(fmt, changed, field, value)
                    self.assert_unsigned_sections_rejected_before_matching(changed)
        # Thread-local REGULAR is file-backed, unlike THREAD_LOCAL_ZEROFILL.
        changed = unsigned_intel_sections_fixture()
        struct.pack_into("<I", changed, 168, 0x11)
        struct.pack_into("<I", changed, 152, 8257)
        self.assert_unsigned_sections_rejected_before_matching(changed)

    def test_unsigned_entrypoint_rejects_identical_and_uuid_different_malformed_pairs(self):
        for entry in (0, 31, 807, 4096, 8255, 8256, 8257, 0xffffffffffffffff):
            with self.subTest(entry=entry):
                changed = unsigned_intel_sections_fixture()
                struct.pack_into("<Q", changed, 792, entry)
                self.assert_unsigned_sections_rejected_before_matching(changed)
        for field, value in ((88, 1), (92, 1), (100, 1), (64, 1024)):
            with self.subTest(field=field):
                changed = unsigned_intel_sections_fixture()
                struct.pack_into("<I", changed, field, value)
                self.assert_unsigned_sections_rejected_before_matching(changed)
        for entry in (1024, 4095):  # within executable file-backed TEXT
            valid = unsigned_intel_sections_fixture()
            struct.pack_into("<Q", valid, 792, entry)
            self.assertEqual(self.compare(valid, valid, "x86_64-apple-darwin")["status"], "exact_match")

    def test_present_invalid_signature_cannot_use_valid_unsigned_section_layout(self):
        for start, size in ((0, 0), (8256, 0), (8256, 184), (1024, 0xffffffff)):
            with self.subTest(start=start, size=size):
                changed = unsigned_intel_sections_fixture()
                struct.pack_into("<II", changed, 16, 10, 792)  # add one 16-byte command
                struct.pack_into("<4I", changed, 808, 0x1d, 16, start, size)
                self.assert_unsigned_sections_rejected_before_matching(changed)

    def test_unsigned_intel_cli_warns_without_claim_and_blocks_code_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, summary = (root / name for name in ("one", "two", "summary"))
            first.write_bytes(unsigned_intel_fixture())
            changed = unsigned_intel_fixture(b"1" * 16)
            second.write_bytes(changed)
            command = [sys.executable, "-B", str(distribution.SOURCE / "scripts/verify_distribution.py"),
                       "compare-builds", str(first), str(second), "--target", "x86_64-apple-darwin", "--summary", str(summary)]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b'"reproducibility_claim": false', result.stdout)
            self.assertIn(b"::warning::Reproducibility UNRESOLVED", result.stdout)
            self.assertNotIn(b"LC_CODE_SIGNATURE_UUID_page_hash", result.stdout)
            self.assertIn("NOT a reproducibility pass", summary.read_text())
            changed[1024] ^= 1
            second.write_bytes(changed)
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"::error::BLOCKED", result.stdout)

    def test_exact_match_does_not_bypass_macho_validation(self):
        for data in (b"", b"not Mach-O", macho_fixture()[:-1]):
            self.assertEqual(self.compare(data, data)["status"], "unsupported_or_invalid_macho")
        changed = macho_fixture()
        changed[8192 + 152] ^= 1
        self.assertEqual(self.compare(changed, changed)["status"], "unsupported_or_invalid_macho")

    def test_non_metadata_changes_block_even_with_recomputed_signature(self):
        for offset in (300, 5000, 8192 + 112):  # text, linkedit, identifier
            changed = macho_fixture(b"1" * 16)
            changed[offset] ^= 1
            seal_fixture(changed)
            self.assertEqual(self.compare(macho_fixture(), changed)["status"], "unexpected_difference")

    def test_signature_corruption_and_changed_security_flags_block(self):
        for offset in (8192 + 120, 8192 + 152, 8192 + 24 + 12):
            changed = macho_fixture(b"1" * 16)
            changed[offset] ^= 1
            self.assertEqual(self.compare(macho_fixture(), changed)["status"], "unsupported_or_invalid_macho")

    def test_missing_duplicate_truncated_and_redirected_commands_block(self):
        for offset, value in ((16, 5), (20, 192), (180, 0), (200, 0x1b),
                              (208, 300), (212, 0xffffffff), (144, 0), (4, 0x1000007)):
            changed = macho_fixture(b"1" * 16)
            struct.pack_into("<I", changed, offset, value)
            seal_fixture(changed)
            self.assertEqual(self.compare(macho_fixture(), changed)["status"], "unsupported_or_invalid_macho")
        for data in (b"", b"\xcf\xfa\xed\xfe", macho_fixture()[:-1], macho_fixture() + b"extra"):
            self.assertEqual(self.compare(macho_fixture(), data)["status"], "unexpected_difference")

    def test_unknown_signature_formats_and_out_of_bounds_hash_tables_block(self):
        for offset, value in ((8200, 2), (8204, 1), (8208, 0xffffffff),
                              (8224, 0x20500), (8240, 1), (8244, 0xffffffff),
                              (8232, 0), (8236, 0xffffffff)):
            changed = macho_fixture(b"1" * 16)
            struct.pack_into(">I", changed, offset, value)
            self.assertEqual(self.compare(macho_fixture(), changed)["status"], "unsupported_or_invalid_macho")

    def test_comparison_refuses_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, link = root / "binary", root / "link"
            binary.write_bytes(macho_fixture())
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                distribution.compare_builds(binary, link, "aarch64-apple-darwin")
            with patch.object(distribution, "MAX_FILE_BYTES", 1):
                with self.assertRaises(ValueError):
                    distribution.compare_builds(binary, binary, "aarch64-apple-darwin")

    def test_linux_and_unknown_formats_have_no_difference_exception(self):
        self.assertEqual(self.compare(b"ELF one", b"ELF two", "x86_64-unknown-linux-gnu")["status"], "unexpected_difference")
        self.assertEqual(self.compare(b"unknown", b"changed")["status"], "unsupported_or_invalid_macho")
        with self.assertRaises(ValueError):
            self.compare(b"same", b"same", "unsupported")

    def test_cli_diagnostic_is_visible_and_unexpected_difference_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, summary = (root / name for name in ("one", "two", "summary"))
            first.write_bytes(macho_fixture())
            second.write_bytes(macho_fixture(b"1" * 16))
            command = [sys.executable, "-B", str(distribution.SOURCE / "scripts/verify_distribution.py"),
                       "compare-builds", str(first), str(second), "--target", "aarch64-apple-darwin", "--summary", str(summary)]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b"::warning::Reproducibility UNRESOLVED", result.stdout)
            self.assertIn("NOT a reproducibility pass", summary.read_text())
            changed = macho_fixture(b"1" * 16)
            changed[300] ^= 1
            second.write_bytes(seal_fixture(changed))
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"::error::BLOCKED", result.stdout)

    def test_inventory_accepts_only_reviewed_files_and_cargo_generated_metadata(self):
        names = sorted(distribution.source_files() | {"Cargo.toml.orig"})
        distribution.check_inventory(names)
        distribution.check_inventory(names + [".cargo_vcs_info.json"])
        for extra in (".env", "target/debug/blastguard", ".github/workflows/ci.yml", names[0]):
            with self.assertRaises(ValueError):
                distribution.check_inventory(names + [extra])
        with self.assertRaises(ValueError):
            distribution.check_inventory([name for name in names if name != "policy-packs/v1/strict.toml"])

    def test_archive_paths_are_not_normalized_into_safe_paths(self):
        for name in ("", ".", "..", "../escape", "/tmp/escape", "root/../escape",
                     "root//file", "root/./file", "root\\file", "C:/file", "root/\nfile"):
            with self.subTest(kind=repr(name)):
                with self.assertRaises(ValueError):
                    distribution.safe_name(name)

    def test_archive_rejects_links_duplicate_and_oversized_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as archive:
                member = tarfile.TarInfo("root/file")
                member.type = kind
                member.linkname = "../../escape"
                archive.addfile(member)
            data.seek(0)
            with tarfile.open(fileobj=data) as archive:
                with self.assertRaises(ValueError):
                    distribution.checked_members(archive, "root")
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo("root/file"), io.BytesIO())
        data.seek(0)
        with tarfile.open(fileobj=data) as archive:
            with self.assertRaises(ValueError):
                distribution.checked_members(archive, "root")
        with patch.object(distribution, "MAX_FILE_BYTES", -1):
            data.seek(0)
            with tarfile.open(fileobj=data) as archive:
                with self.assertRaises(ValueError):
                    distribution.checked_members(archive, "root")

    def test_existing_destination_and_source_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "existing"
            destination.mkdir()
            sentinel = destination / "keep"
            sentinel.write_bytes(b"unchanged")
            with self.assertRaises(FileExistsError):
                distribution.write_members({"keep": (b"replacement", 0o644)}, destination)
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            (root / "link").symlink_to(sentinel)
            with self.assertRaises(ValueError):
                distribution.regular_bytes(root / "link")

    def test_submitted_shell_is_one_data_argument_not_a_shell_invocation(self):
        command = "printf marker > never-created; $(touch never-created)"
        with patch.object(distribution.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 20, b"{}", b"")
            distribution.run_binary(Path("/trusted/blastguard"), ["analyze", "--command", command], Path("/tmp"), 20)
            arguments, options = run.call_args
            self.assertEqual(arguments[0], ["/trusted/blastguard", "analyze", "--command", command])
            self.assertNotIn("shell", options)
            self.assertEqual(options["env"], {"PATH": "/usr/bin:/bin"})

    def test_candidate_archive_is_repeatable_for_identical_inputs_and_smokes_extracted_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "input"
            binary.write_bytes(b"fixture, not executable")
            with patch.object(distribution, "smoke") as smoke:
                for output in (root / "one", root / "two"):
                    distribution.candidate(binary, "aarch64-apple-darwin", "0.1.2", output)
                self.assertEqual(smoke.call_count, 2)
                for call in smoke.call_args_list:
                    self.assertEqual(call.args[0].name, "blastguard")
                    self.assertNotEqual(call.args[0], binary)
            name = "blastguard-v0.1.2-aarch64-apple-darwin.tar.gz"
            first = (root / "one" / name).read_bytes()
            self.assertEqual(first, (root / "two" / name).read_bytes())
            self.assertEqual(
                (root / "one" / "SHA256SUMS").read_text(),
                f"{hashlib.sha256(first).hexdigest()}  {name}\n",
            )
            with tarfile.open(root / "one" / name) as archive:
                files = distribution.checked_members(archive, name.removesuffix(".tar.gz"))
            self.assertEqual(set(files), {"blastguard", "LICENSE", "NOTICE", "INSTALL.txt"})
            self.assertEqual(files["blastguard"][1], 0o755)
            with self.assertRaises(FileExistsError):
                distribution.candidate(binary, "aarch64-apple-darwin", "0.1.2", root / "one")


if __name__ == "__main__":
    unittest.main()
