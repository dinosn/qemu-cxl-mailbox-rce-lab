from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PINNED_COMMIT = "562bae590f194fb590beb5c65da44fc35ab9f64a"

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "artifacts",
    "build",
    "qemu-src",
    "runs",
    "__pycache__",
}

FORBIDDEN_SOURCE_SUFFIXES = {
    ".7z",
    ".bin",
    ".core",
    ".gz",
    ".img",
    ".iso",
    ".qcow",
    ".qcow2",
    ".raw",
    ".sock",
    ".tar",
    ".tgz",
    ".zip",
}


def repository_files() -> list[Path]:
    """Return files tracked by this repo, or source candidates before git init."""
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == ROOT:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
        return sorted(ROOT / item.decode() for item in tracked if item)

    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts)
    )


class RepositoryTests(unittest.TestCase):
    def test_pinned_revision_is_consistent(self) -> None:
        required = [
            ROOT / "README.md",
            ROOT / "docs" / "FINDING.md",
            ROOT / "evidence" / "VALIDATION.md",
            ROOT / "Dockerfile",
        ]
        for path in required:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertTrue(path.is_file(), f"missing {path.relative_to(ROOT)}")
                self.assertIn(PINNED_COMMIT, path.read_text(encoding="utf-8"))

    def test_scope_boundaries_are_explicit(self) -> None:
        text = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "README.md",
                "docs/FINDING.md",
                "evidence/VALIDATION.md",
            )
        ).lower()
        for phrase in (
            "qemu process",
            "qtest/tcg",
            "booted kvm guest",
            "container-host escape",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_source_only_policy(self) -> None:
        for path in repository_files():
            relative = path.relative_to(ROOT)
            with self.subTest(path=relative):
                self.assertNotIn(
                    path.suffix.lower(),
                    FORBIDDEN_SOURCE_SUFFIXES,
                    f"binary/archive-like file must not be committed: {relative}",
                )
                self.assertLess(
                    path.stat().st_size,
                    1_048_576,
                    f"unexpected tracked file over 1 MiB: {relative}",
                )

    def test_no_environment_or_credential_markers(self) -> None:
        local_home = "/" + "Users" + "/"
        private_prefix = "192" + ".168."
        local_username = "kr" + "asn"
        token_patterns = (
            re.compile(r"gh" + r"p_[A-Za-z0-9]{20,}"),
            re.compile(r"github" + r"_pat_[A-Za-z0-9_]{20,}"),
        )

        for path in repository_files():
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            relative = path.relative_to(ROOT)
            with self.subTest(path=relative):
                self.assertNotIn(local_home, text)
                self.assertNotIn(private_prefix, text)
                self.assertNotIn(local_username, text.lower())
                self.assertIsNone(
                    re.search(r"root@(?:[0-9]{1,3}\.){3}[0-9]{1,3}", text)
                )
                for pattern in token_patterns:
                    self.assertIsNone(pattern.search(text))

    def test_ci_is_static_only(self) -> None:
        workflow = (ROOT / ".github/workflows/validate.yml").read_text(
            encoding="utf-8"
        )
        executable_lines = "\n".join(
            line for line in workflow.splitlines() if not line.lstrip().startswith("#")
        )
        for forbidden in ("docker build", "docker compose", "./lab test", "qemu-system"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, executable_lines)


if __name__ == "__main__":
    unittest.main()
