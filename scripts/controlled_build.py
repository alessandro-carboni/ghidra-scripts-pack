"""Isolated PE builds, bounded output-access retries and portable metadata only."""

import errno
import os
from pathlib import Path
import re
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def sanitize_text(value, root=ROOT, compiler_path=None):
    text = re.sub(r"/{2,}", "/", str(value).replace("\\", "/"))
    repository = str(root).replace("\\", "/").rstrip("/")
    if compiler_path:
        executable = str(compiler_path).replace("\\", "/")
        text = re.sub(re.escape(executable), "${COMPILER}", text, flags=re.IGNORECASE)
    text = re.sub(re.escape(repository) + r"/+", "", text, flags=re.IGNORECASE)
    text = re.sub(re.escape(repository), "${REPOSITORY}", text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)[a-z]:/+Users/+[^/\s\"']+", "${USER_HOME}", text)
    text = re.sub(r"/(?:home|Users)/[^/\s\"']+", "${USER_HOME}", text)
    portable_root = re.sub(r"(?i)[a-z]:/Users/[^/]+|/(?:home|Users)/[^/]+", "${USER_HOME}", repository)
    text = text.replace(portable_root + "/", "")
    return text


def portable_flags(flags, root=ROOT):
    return [sanitize_text(flag, root) for flag in flags]


def assert_portable_metadata(value, root=ROOT):
    """Reject leakage rather than silently changing scientific content on serialization."""
    if isinstance(value, dict):
        for key, child in value.items():
            assert_portable_metadata(key, root)
            assert_portable_metadata(child, root)
    elif isinstance(value, list):
        for child in value:
            assert_portable_metadata(child, root)
    elif isinstance(value, str):
        normalized = value.replace("\\", "/")
        if str(root).replace("\\", "/").lower() in normalized.lower() or re.search(r"(?i)[a-z]:/+Users/+|/(?:home|Users)/[^/]+/", normalized):
            raise ValueError("Machine-specific path in dataset metadata")


def pe_architecture(path):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a valid PE executable")
    offset = struct.unpack_from("<I", data, 60)[0]
    if offset + 6 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature/header")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    if machine not in (0x14C, 0x8664, 0xAA64):
        raise ValueError("unsupported PE architecture")
    return {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}[machine]


class CommandFailure(RuntimeError):
    def __init__(self, result):
        self.returncode = result.returncode
        super().__init__((result.stdout or "") + (result.stderr or ""))


class BuildFailure(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__(record["diagnostic"])


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False, **kwargs)
    if result.returncode:
        raise CommandFailure(result)
    return result.stdout.strip()


def transient_output_error(error, stage, phase):
    if isinstance(error, OSError):
        return isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EBUSY, errno.ETXTBSY} or getattr(error, "winerror", None) in {5, 32, 33}
    if phase != "compile" or not isinstance(error, CommandFailure):
        return False
    message = str(error).replace("\\", "/").lower()
    # LNK1104 for a missing input library is NOT an output-access retry.
    names_output = str(stage).replace("\\", "/").lower() in message or re.search(r"[\"']" + re.escape(stage.name.lower()) + r"[\"']", message)
    return bool(names_output and re.search(r"lnk1104|lnk1168|permission denied|access is denied|sharing violation", message))


def clean_stage(directory, build_directory):
    directory = directory.resolve()
    expected = build_directory.resolve() / ".staging"
    if directory.parent != expected or not directory.name.startswith("attempt-"):
        raise ValueError("Refusing cleanup outside the isolated staging directory")
    directory.mkdir(parents=True, exist_ok=True)
    for path in directory.iterdir():
        if path.is_symlink() or path.resolve().parent != directory:
            raise ValueError("Unexpected path in staging directory")
        if path.is_file() and path.suffix.lower() in {".exe", ".obj", ".o", ".exp", ".lib", ".pdb", ".ilk", ".idb", ".manifest"}:
            path.unlink()


def build_pe(compiler, build_id, optimization, final, flags_for_output, validate_behavior, *, root=ROOT, runner=run, replace=os.replace, sleep=time.sleep, attempts=3):
    """Publish only a successful, validated executable; preserve prior output on failure."""
    final = Path(final).resolve()
    build_directory = final.parent
    if not final.is_relative_to(Path(root).resolve()) or not 1 <= attempts <= 3:
        raise ValueError("Invalid controlled build directory/retry limit")
    diagnostics = []
    for attempt in range(1, attempts + 1):
        stage_dir = build_directory / ".staging" / f"attempt-{attempt}"
        stage = stage_dir / final.name
        phase = "prepare_output"
        try:
            clean_stage(stage_dir, build_directory)
            flags = flags_for_output(stage)
            print(f"BUILD {build_id}: attempt {attempt}/{attempts}; isolated staging output", flush=True)
            phase = "compile"
            runner([compiler["path"], *flags], cwd=stage_dir, env=compiler["env"])
            phase = "validate_pe"
            architecture = pe_architecture(stage)
            phase = "execute"
            transcript = runner([str(stage)]).splitlines()
            phase = "validate_behavior"
            validate_behavior(transcript)
            phase = "publish"
            replace(stage, final)
            return dict(architecture=architecture, behavior=transcript, status="success", attempts=attempt, attempt_diagnostics=diagnostics, flags=portable_flags(flags, root))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            transient = transient_output_error(error, stage, phase)
            diagnostic = sanitize_text(str(error), root, compiler["path"])
            record = dict(attempt=attempt, phase=phase, error_kind=type(error).__name__, diagnostic=diagnostic, transient=transient)
            diagnostics.append(record)
            print(f"BUILD {build_id}: attempt {attempt} failed ({phase}, retry={transient and attempt < attempts}): {diagnostic}", flush=True)
            # Incomplete staging output is never registered or published. A prior
            # successful final file may remain, but this failed build is excluded.
            try:
                if stage.exists():
                    stage.unlink()
            except OSError:
                pass  # Locked staging file remains isolated and never counts as success.
            if not transient or attempt == attempts:
                raise BuildFailure(dict(build_id=build_id, compiler=compiler["compiler"], compiler_version=compiler["version"], optimization=optimization, status="failed", error_kind=type(error).__name__, diagnostic=diagnostic, attempts=attempt, attempt_diagnostics=diagnostics)) from error
            sleep(0.25)
    raise AssertionError("bounded build loop exhausted unexpectedly")
