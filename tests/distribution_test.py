"""Distribution tooling tests; no model/client or submitted shell execution."""

import hashlib
import importlib.util
import io
from pathlib import Path
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
