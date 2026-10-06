"""Local distribution checks only: no publication, shell evaluation, or installer."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import tempfile


SOURCE = Path(__file__).resolve().parent.parent
TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)
MAX_FILE_BYTES = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    path = PurePosixPath(name)
    require(
        bool(path.parts) and not path.is_absolute() and str(path) == name
        and not any(part in (".", "..") for part in path.parts)
        and "\\" not in name and ":" not in name
        and all(32 <= ord(char) < 127 for char in name),
        "Invalid archive/inventory path",
    )
    return path


def source_files():
    names = (SOURCE / "scripts/package-files.txt").read_text(encoding="utf-8").splitlines()
    require(len(names) == len(set(names)), "Duplicate inventory entry")
    for name in names:
        safe_name(name)
    return set(names)


def check_inventory(names):
    require(len(names) == len(set(names)), "Duplicate package member")
    for name in names:
        safe_name(name)
    actual = set(names) - {".cargo_vcs_info.json"}
    require(actual == source_files() | {"Cargo.toml.orig"}, "Package inventory mismatch")


def regular_bytes(path):
    require(not path.is_symlink() and path.is_file(), "Expected a regular, non-symlink file")
    require(path.stat().st_size <= MAX_FILE_BYTES, "File exceeds verification limit")
    return path.read_bytes()


def source_bytes(name):
    current = SOURCE
    for part in safe_name(name).parts:
        current = current / part
        require(not current.is_symlink(), "Symlink in source inventory")
    return regular_bytes(current)


def copy_source(destination):
    # A plain source snapshot, not a new Git repository or a linked worktree.
    # Read all approved files before creating anything; no local state is copied.
    files = {name: source_bytes(name) for name in sorted(source_files())}
    destination.mkdir(parents=False, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(data)
    print(f"Source snapshot: {len(files)} approved files; no Git/local state")


def checked_members(archive, prefix):
    files = {}
    total = 0
    for member in archive.getmembers():
        path = safe_name(member.name)
        require(len(path.parts) > 1 and path.parts[0] == prefix, "Wrong archive root")
        require(member.isfile(), "Archive contains a link or non-regular member")
        name = str(PurePosixPath(*path.parts[1:]))
        require(name not in files, "Duplicate archive member")
        require(0 <= member.size <= MAX_FILE_BYTES, "Archive member exceeds limit")
        total += member.size
        require(total <= 2 * MAX_FILE_BYTES, "Archive exceeds total limit")
        stream = archive.extractfile(member)
        require(stream is not None, "Missing archive member data")
        with stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        require(len(data) == member.size, "Truncated archive member")
        files[name] = (data, member.mode)
    return files


def write_members(files, destination):
    # Never extract tar paths/links directly; destination must be newly created.
    destination.mkdir(parents=False, exist_ok=False)
    for name, (data, mode) in sorted(files.items()):
        path = destination / safe_name(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(data)
        path.chmod(0o755 if mode & 0o111 else 0o644)


def extract_crate(archive_path, destination, version):
    with tarfile.open(archive_path, "r:gz") as archive:
        files = checked_members(archive, f"blastguard-{version}")
    check_inventory(list(files))
    for name in source_files():
        packaged = "Cargo.toml.orig" if name == "Cargo.toml" else name
        require(files[packaged][0] == source_bytes(name), "Packaged source differs from reviewed input")
    if ".cargo_vcs_info.json" in files:
        vcs = json.loads(files[".cargo_vcs_info.json"][0])
        require(vcs.get("git", {}).get("dirty") is False, "Package VCS state is dirty or unknown")
    write_members(files, destination)
    print(f"Crate inspection/extraction: {len(files)} regular files; inventory and source bytes match")


def run_binary(binary, arguments, directory, expected):
    # No shell=True, shell wrapper, eval, or command-string execution.
    result = subprocess.run(
        [str(binary), *arguments], cwd=directory, env={"PATH": "/usr/bin:/bin"},
        capture_output=True, timeout=20, check=False,
    )
    require(result.returncode == expected, "Unexpected smoke-test exit status")
    require(not result.stderr, "Unexpected smoke-test diagnostic")
    return result.stdout.decode("utf-8")


def smoke(binary, version):
    binary = binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="blastguard-static-smoke-") as directory:
        cwd = Path(directory)
        output = run_binary(binary, ["--version"], cwd, 0)
        require(output.strip() == f"blastguard {version}", "Wrong executable version")
        print(f"--version: blastguard {version} (exit 0)")
        run_binary(binary, ["policy", "list"], cwd, 0)
        packs = json.loads(run_binary(binary, ["policy", "list", "--json"], cwd, 0))
        require(packs.get("schema_version") == "blastguard.policy.list/1.0", "Wrong policy schema")
        require({pack["name"] for pack in packs["packs"]} == {"balanced", "strict", "ci"}, "Missing packs")
        print("policy list: balanced, strict, ci (exit 0)")
        cases = (
            ("cargo test", "allow", 0),
            ("printf marker > blastguard-should-not-exist", "allow", 0),
            ("printf marker > blastguard-should-not-exist; printf '' | base64 -d | sh", "block", 20),
        )
        for command, decision, code in cases:
            analysis = json.loads(run_binary(binary, [
                "analyze", "--command", command, "--cwd", str(cwd), "--json",
            ], cwd, code))
            require(analysis.get("schema_version") == "1.0", "Wrong analysis schema")
            require(analysis.get("decision") == decision, "Wrong analysis decision")
            require(not list(cwd.iterdir()), "Analyzed input mutated the smoke directory")
            print(f"static analysis: {decision} (exit {code}); no command execution")


def candidate(binary, target, version, output):
    base = f"blastguard-v{version}-{target}"
    files = {
        "blastguard": (regular_bytes(binary), 0o755),
        "LICENSE": (source_bytes("LICENSE"), 0o644),
        "NOTICE": (source_bytes("NOTICE"), 0o644),
        "INSTALL.txt": (source_bytes("docs/INSTALL.txt"), 0o644),
    }
    output.mkdir(parents=False, exist_ok=False)
    archive_path = output / f"{base}.tar.gz"
    # Stable archive headers do not imply a reproducible compiler/toolchain.
    with archive_path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    member = tarfile.TarInfo(f"{base}/{name}")
                    member.size = len(data)
                    member.mode = mode
                    member.mtime = 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    archive.addfile(member, io.BytesIO(data))
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum = f"{digest}  {archive_path.name}\n"
    (output / "SHA256SUMS").write_text(checksum, encoding="ascii")
    archive_path.with_name(archive_path.name + ".sha256").write_text(checksum, encoding="ascii")
    require(hashlib.sha256(archive_path.read_bytes()).hexdigest() == digest, "Checksum verification failed")
    with tarfile.open(archive_path, "r:gz") as archive:
        extracted = checked_members(archive, base)
    require(extracted == files, "Candidate archive content/mode mismatch")
    with tempfile.TemporaryDirectory(prefix="blastguard-candidate-") as temporary:
        destination = Path(temporary) / base
        write_members(extracted, destination)
        smoke(destination / "blastguard", version)
    print(f"Candidate only: {archive_path.name}; SHA-256 {digest}; extraction/smoke passed")


def macho_metadata(data, target):
    """Recognize observed thin Mach-O: linker ad-hoc or naturally unsigned Intel.

    Read-only: do not normalize, rewrite UUIDs, strip, or re-sign anything.
    This is a narrow difference classifier, not a general code-signing verifier.
    Unknown formats must fail closed and receive explicit owner review.
    """
    def unpack(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), "Truncated Mach-O")
        return struct.unpack_from(fmt, data, offset)

    cpu = {"aarch64-apple-darwin": 0x100000c, "x86_64-apple-darwin": 0x1000007}
    magic, architecture, subtype, kind, count, size, _, reserved = unpack("<8I", 0)
    require(magic == 0xfeedfacf and architecture == cpu.get(target) and kind == 2,
            "Unsupported Mach-O header")
    end = 32 + size
    require(0 < count <= 4096 and end <= len(data), "Invalid load commands")
    cursor, uuid, signature = 32, None, None
    segments = {}
    commands = {}
    for _ in range(count):
        command, length = unpack("<II", cursor)
        require(length >= 8 and length % 8 == 0 and cursor + length <= end,
                "Invalid load command bounds")
        commands.setdefault(command, []).append((cursor, length))
        if command == 0x1b:  # LC_UUID
            require(uuid is None and length == 24, "Invalid UUID command")
            uuid = (cursor + 8, cursor + 24)
        elif command == 0x1d:  # LC_CODE_SIGNATURE
            require(signature is None and length == 16, "Invalid signature command")
            signature = unpack("<II", cursor + 8)
        elif command == 0x19:  # LC_SEGMENT_64
            require(length >= 72, "Invalid segment")
            name = data[cursor + 8:cursor + 24].rstrip(b"\0")
            start, extent = unpack("<QQ", cursor + 40)
            sections, = unpack("<I", cursor + 64)
            require(length == 72 + 80 * sections and name not in segments
                    and start + extent <= len(data), "Invalid segment bounds")
            segments[name] = (start, start + extent)
        cursor += length
    require(cursor == end and uuid is not None,
            "Missing or malformed Mach-O metadata")
    require(b"__TEXT" in segments and b"__LINKEDIT" in segments,
            "Missing required segments")
    require(segments[b"__TEXT"][0] == 0 and segments[b"__TEXT"][1] >= end
            and end <= segments[b"__LINKEDIT"][0] < len(data)
            and segments[b"__LINKEDIT"][1] == len(data), "Invalid linkedit segment")
    occupied = sorted(span for span in segments.values() if span[0] != span[1])
    require(all(left[1] <= right[0] for left, right in zip(occupied, occupied[1:])),
            "Overlapping Mach-O segments")

    if signature is None:
        # Apple ld naturally emits unsigned x86_64 executables. This is NOT a
        # fallback for a malformed/present signature, nor permission to strip one.
        require(target == "x86_64-apple-darwin" and subtype == 3 and reserved == 0,
                "Missing required Mach-O signature")
        # Recognize only the observed modern Intel executable layout. A renamed
        # signature command or orphaned signature tail must not become unsigned.
        fixed = {0x2: 24, 0xb: 80, 0x1b: 24, 0x2a: 16, 0x80000028: 24,
                 0x26: 16, 0x29: 16, 0x80000033: 16, 0x80000034: 16}
        require(set(commands) <= set(fixed) | {0x19, 0xc, 0xe, 0x32},
                "Unsupported unsigned Mach-O load command")
        for code, length in fixed.items():
            entries = commands.get(code, [])
            require(len(entries) <= 1 and all(size == length for _, size in entries),
                    "Invalid unsigned Mach-O load command")
        text_executable = False
        for offset, _ in commands[0x19]:  # LC_SEGMENT_64, already bounded above
            name = data[offset + 8:offset + 24]
            vm_start, vm_size, file_start, file_size, maximum, initial, sections, flags = unpack(
                "<4Q4I", offset + 24)
            # Python integers do not wrap. Also reject ranges that would overflow
            # the format's uint64 address space, and unsupported high-VM mapping.
            require(vm_size <= 0xffffffffffffffff - vm_start and file_size <= vm_size
                    and not flags & 1, "Invalid unsigned Mach-O segment mapping")
            vm_end, file_end = vm_start + vm_size, file_start + file_size
            if name.rstrip(b"\0") == b"__TEXT":
                text_executable = bool(maximum & initial & 4)  # VM_PROT_EXECUTE
            for index in range(sections):
                section = offset + 72 + 80 * index
                section_segment = data[section + 16:section + 32]
                address, extent, start = unpack("<QQI", section + 32)
                section_flags, = unpack("<I", section + 64)
                section_type = section_flags & 0xff
                require(section_segment == name and section_type <= 0x16
                        and vm_start <= address <= vm_end and extent <= vm_end - address,
                        "Invalid unsigned Mach-O section mapping")
                # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL occupy VM
                # only: their offset does not describe file-backed content.
                if section_type in (0x1, 0xc, 0x12):
                    continue
                require(end <= start <= len(data) and extent <= len(data) - start
                        and file_start <= start <= file_end and extent <= file_end - start
                        and address - vm_start == start - file_start,
                        "Invalid unsigned Mach-O section file bounds")
        if 0x80000028 in commands:  # LC_MAIN: file (__TEXT) offset, not a VM address
            entry, = unpack("<Q", commands[0x80000028][0][0] + 8)
            require(text_executable and end <= entry < len(data)
                    and segments[b"__TEXT"][0] <= entry < segments[b"__TEXT"][1],
                    "Invalid unsigned Mach-O entry point")
        for code, minimum, string_field in ((0xc, 24, 8), (0xe, 12, 8)):
            for offset, length in commands.get(code, []):
                require(length >= minimum, "Truncated unsigned Mach-O string command")
                string_offset, = unpack("<I", offset + string_field)
                require(minimum <= string_offset < length
                        and b"\0" in data[offset + string_offset:offset + length],
                        "Invalid unsigned Mach-O string command")
        for offset, length in commands.get(0x32, []):
            require(length >= 24, "Truncated unsigned Mach-O build version")
            platform, _, _, tools = unpack("<4I", offset + 8)
            require(platform == 1 and length == 24 + tools * 8,
                    "Unsupported unsigned Mach-O build version")
        require(0x2 in commands, "Unsigned Mach-O missing symbol table")
        symoff, symbols, stroff, strings = unpack("<4I", commands[0x2][0][0] + 8)
        link_start = segments[b"__LINKEDIT"][0]
        require(link_start <= symoff <= symoff + 16 * symbols <= stroff
                and symoff % 8 == 0 and strings > 0 and stroff + strings == len(data),
                "Invalid unsigned Mach-O symbol/string bounds")
        # Linkedit payloads must be bounded, disjoint, and end with the string
        # table. Reject corrupt offsets even when the only differing byte is UUID.
        spans = [(symoff, symoff + 16 * symbols), (stroff, len(data))]
        for code in (0x26, 0x29, 0x80000033, 0x80000034):
            if code in commands:
                offset, length = unpack("<II", commands[code][0][0] + 8)
                require((offset == 0 and length == 0)
                        or link_start <= offset <= offset + length <= symoff,
                        "Invalid unsigned Mach-O linkedit bounds")
                spans.append((offset, offset + length))
        if 0xb in commands:
            symbols_info = unpack("<18I", commands[0xb][0][0] + 8)
            require(all(symbols_info[i] + symbols_info[i + 1] <= symbols for i in (0, 2, 4))
                    and not any(symbols_info[6:12] + symbols_info[14:18]),
                    "Unsupported unsigned Mach-O dynamic symbol table")
            offset, entries = symbols_info[12:14]
            require((offset == 0 and entries == 0)
                    or (symoff + 16 * symbols <= offset <= offset + 4 * entries <= stroff
                        and offset % 4 == 0), "Invalid unsigned Mach-O indirect symbol bounds")
            spans.append((offset, offset + 4 * entries))
        spans = sorted(span for span in spans if span[0] != span[1])
        require(all(left[1] <= right[0] for left, right in zip(spans, spans[1:])),
                "Overlapping unsigned Mach-O linkedit payloads")
        return {"LC_UUID": uuid}

    sig_start, sig_size = signature
    require(sig_start >= end and sig_start + sig_size == len(data) and sig_size >= 108
            and segments[b"__LINKEDIT"][0] <= sig_start, "Invalid signature bounds")

    # Only one CodeDirectory, SHA-256/4 KiB pages, no CMS, entitlements or
    # special slots. Never exempt the entire LC_CODE_SIGNATURE payload.
    magic, length, count, slot, cd_offset = unpack(">5I", sig_start)
    require((magic, length, count, slot) == (0xfade0cc0, sig_size, 1, 0)
            and 20 <= cd_offset <= sig_size - 88, "Unsupported signature envelope")
    cd = sig_start + cd_offset
    magic, length, version, flags, hashes, identifier, special, slots, limit = unpack(">9I", cd)
    hash_size, hash_type, platform, page = unpack("4B", cd + 36)
    require((magic, version, flags) == (0xfade0c02, 0x20400, 0x20002)
            and (hash_size, hash_type, platform, page) == (32, 2, 0, 12)
            and special == 0 and limit == sig_start
            and slots == (sig_start + 4095) // 4096,
            "Unsupported CodeDirectory")
    require(88 <= identifier < hashes and hashes + 32 * slots == length
            and cd_offset + length <= sig_size
            and b"\0" in data[cd + identifier:cd + hashes], "Invalid CodeDirectory bounds")
    require(not any(data[sig_start + 20:cd]) and not any(data[cd + length:]),
            "Unexpected signature padding")
    for index in range(slots):
        digest = hashlib.sha256(data[index * 4096:min((index + 1) * 4096, sig_start)]).digest()
        start = cd + hashes + index * 32
        require(data[start:start + 32] == digest, "Invalid signature page hash")
    require(uuid[0] // 4096 == (uuid[1] - 1) // 4096, "UUID crosses a signature page")
    hash_start = cd + hashes + (uuid[0] // 4096) * 32
    return {"LC_UUID": uuid, "LC_CODE_SIGNATURE_UUID_page_hash": (hash_start, hash_start + 32)}


def compare_builds(first, second, target):
    require(target in TARGETS, "Unsupported comparison target")
    inputs = (regular_bytes(first), regular_bytes(second))
    report = {
        "schema_version": "blastguard.repeat-build/1.0",
        "target": target,
        "sha256": [hashlib.sha256(data).hexdigest() for data in inputs],
        "sizes": [len(data) for data in inputs],
        "status": "unexpected_difference",
        "reproducibility_claim": False,
    }
    regions = None
    if target.endswith("-apple-darwin") and len(inputs[0]) == len(inputs[1]):
        try:
            regions = [macho_metadata(data, target) for data in inputs]
        except (ValueError, struct.error):
            report["status"] = "unsupported_or_invalid_macho"
            return report
    # Equality is not a bypass for invalid Mach-O or corrupt signature hashes.
    if inputs[0] == inputs[1]:
        report["status"] = "exact_match"
        return report
    if regions is not None:
        if regions[0] == regions[1]:
            differences = {name: [] for name in regions[0]}
            for offset, (left, right) in enumerate(zip(*inputs)):
                if left == right:
                    continue
                name = next((name for name, (start, end) in regions[0].items()
                             if start <= offset < end), None)
                if name is None:
                    report["first_unexpected_offset"] = offset
                    return report
                differences[name].append({"offset": offset, "first": f"{left:02x}", "second": f"{right:02x}"})
            report["status"] = "macho_metadata_only_unresolved"
            report["regions"] = regions[0]
            report["differing_bytes"] = differences
    return report


def report_comparison(report, summary=None):
    status = report["status"]
    messages = {
        "exact_match": "Exact repeat-build bytes match for this pair only; no general reproducibility claim.",
        "macho_metadata_only_unresolved": "Reproducibility UNRESOLVED: UUID (and, when present, its verified signature-page hash) differences only. Non-blocking diagnostic, NOT a reproducibility pass. Explicit owner review required before public binaries.",
        "unexpected_difference": "BLOCKED: unexpected repeat-build differences; owner investigation required.",
        "unsupported_or_invalid_macho": "BLOCKED: invalid or unsupported Mach-O/signature; owner investigation required.",
    }
    message = messages[status]
    serialized = json.dumps(report, indent=2, sort_keys=True)
    print(serialized)
    print(message)
    if summary is not None:
        # Only fixed labels, integer offsets, hashes, and bytes are rendered.
        with summary.open("a", encoding="utf-8") as output:
            output.write(f"## Repeat-build diagnostic: {report['target']}\n\n{message}\n\n```json\n{serialized}\n```\n")
        if status != "exact_match":
            level = "warning" if status == "macho_metadata_only_unresolved" else "error"
            print(f"::{level}::{message}")
    require(status in ("exact_match", "macho_metadata_only_unresolved"), "Repeat-build gate blocked")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    copy = commands.add_parser("copy-source")
    copy.add_argument("destination", type=Path)
    inventory = commands.add_parser("check-list")
    inventory.add_argument("listing", type=Path)
    extract = commands.add_parser("extract-crate")
    extract.add_argument("archive", type=Path)
    extract.add_argument("destination", type=Path)
    probe = commands.add_parser("smoke")
    probe.add_argument("binary", type=Path)
    bundle = commands.add_parser("candidate")
    bundle.add_argument("binary", type=Path)
    bundle.add_argument("--target", choices=TARGETS, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("compare-builds")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    compare.add_argument("--target", choices=TARGETS, required=True)
    compare.add_argument("--summary", type=Path)
    for command in (extract, probe, bundle):
        command.add_argument("--version", required=True)
    args = parser.parse_args()
    if hasattr(args, "version"):
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version), "Invalid release version")
    if args.operation == "copy-source":
        copy_source(args.destination)
    elif args.operation == "check-list":
        names = args.listing.read_text(encoding="utf-8").splitlines()
        check_inventory(names)
        print(f"Package inventory: {len(names)} approved entries")
    elif args.operation == "extract-crate":
        extract_crate(args.archive, args.destination, args.version)
    elif args.operation == "smoke":
        smoke(args.binary, args.version)
    elif args.operation == "candidate":
        candidate(args.binary, args.target, args.version, args.output)
    elif args.operation == "compare-builds":
        report_comparison(compare_builds(args.first, args.second, args.target), args.summary)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        # Do not echo arbitrary tool diagnostics, paths, or malformed archive data.
        raise SystemExit("Distribution verification failed; check the trusted inputs and prerequisites.") from None
