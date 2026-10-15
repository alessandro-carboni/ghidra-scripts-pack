import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from scripts.controlled_build import BuildFailure, CommandFailure, assert_portable_metadata, build_pe, clean_stage, portable_flags, sanitize_text


def pe_bytes():
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, 0x14C)
    return bytes(data)


class ControlledBuildTests(unittest.TestCase):
    def build(self, root, runner, validator=lambda rows: None, replace=os.replace):
        compiler = dict(compiler="mock", version="mock 1", path="mock-cc", env={})
        return build_pe(compiler, "test-O0", "O0", root / "test/test.exe", lambda output: ["-o", str(output)], validator, root=root, runner=runner, replace=replace, sleep=lambda _: None)

    def test_publish_only_after_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            final = root / "test/test.exe"
            final.parent.mkdir()
            final.write_bytes(b"old")

            def runner(command, **kwargs):
                self.assertEqual(final.read_bytes(), b"old")
                if command[0] == "mock-cc":
                    self.assertNotEqual(Path(command[-1]), final)
                    Path(command[-1]).write_bytes(pe_bytes())
                    return ""
                return "observed 0 1"

            def validate(rows):
                self.assertEqual(final.read_bytes(), b"old")
                self.assertEqual(rows, ["observed 0 1"])

            result = self.build(root, runner, validate)
            self.assertEqual(final.read_bytes(), pe_bytes())
            self.assertEqual(result["status"], "success")
            self.assertNotIn(str(root), json.dumps(result))

    def test_failed_validation_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def runner(command, **kwargs):
                if command[0] == "mock-cc":
                    Path(command[-1]).write_bytes(pe_bytes())
                return "bad behavior"

            def invalid(rows):
                raise ValueError("oracle mismatch")

            with self.assertRaises(BuildFailure) as raised:
                self.build(root, runner, invalid)
            self.assertEqual(raised.exception.record["attempts"], 1)
            self.assertFalse((root / "test/test.exe").exists())
            self.assertFalse(list((root / "test/.staging").rglob("*.exe")))

    def test_success_exit_without_valid_pe_is_not_success(self):
        for contents in (None, b"not a PE"):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temp:

                def runner(command, **kwargs):
                    if contents is not None:
                        Path(command[-1]).write_bytes(contents)
                    return ""

                with self.assertRaises(BuildFailure) as raised:
                    self.build(Path(temp), runner)
                self.assertEqual(raised.exception.record["attempts"], 1)
                self.assertFalse((Path(temp) / "test/test.exe").exists())

    def test_transient_compiler_output_failure_retries(self):
        with tempfile.TemporaryDirectory() as temp:
            attempts = []

            def runner(command, **kwargs):
                if command[0] == "mock-cc":
                    attempts.append(command)
                    if len(attempts) == 1:
                        raise CommandFailure(subprocess.CompletedProcess(command, 1, "", f"LINK : fatal error LNK1104: cannot open file '{command[-1]}'"))
                    Path(command[-1]).write_bytes(pe_bytes())
                return "observed 0 1"

            result = self.build(Path(temp), runner)
            self.assertEqual(result["attempts"], 2)
            self.assertEqual(len(attempts), 2)

    def test_missing_library_is_not_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                raise CommandFailure(subprocess.CompletedProcess(command, 1, "", "fatal error LNK1104: cannot open file 'missing.lib'"))

            with self.assertRaises(BuildFailure) as raised:
                self.build(Path(temp), runner)
            self.assertEqual(len(calls), 1)
            self.assertIn("missing.lib", raised.exception.record["diagnostic"])

    def test_publish_failure_is_bounded_and_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            final = root / "test/test.exe"
            final.parent.mkdir()
            final.write_bytes(b"previous")

            def runner(command, **kwargs):
                if command[0] == "mock-cc":
                    Path(command[-1]).write_bytes(pe_bytes())
                return "observed 0 1"

            def locked(source, target):
                raise PermissionError("output is locked")

            with self.assertRaises(BuildFailure) as raised:
                self.build(root, runner, replace=locked)
            self.assertEqual(raised.exception.record["attempts"], 3)
            self.assertEqual(final.read_bytes(), b"previous")

    def test_cleanup_cannot_touch_source_or_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stage = root / ".staging/attempt-1"
            stage.mkdir(parents=True)
            (stage / "source.c").write_text("source")
            (stage / "old.obj").write_bytes(b"stale")
            clean_stage(stage, root)
            self.assertTrue((stage / "source.c").exists())
            self.assertFalse((stage / "old.obj").exists())
            with self.assertRaises(ValueError):
                clean_stage(root, root)


class PortableMetadataTests(unittest.TestCase):
    def test_windows_and_posix_flags_keep_semantic_information(self):
        for root in (r"C:\Users\alice\repo", "/home/alice/repo"):
            flags = ["/O2", "/Fe" + root + "/samples/builds/demo.exe", root + "/samples/source/demo.c"]
            normalized = portable_flags(flags, root)
            self.assertEqual(normalized, ["/O2", "/Fesamples/builds/demo.exe", "samples/source/demo.c"])
            self.assertIn(root, flags[1])  # Actual command is unchanged.
            assert_portable_metadata(normalized, root)

    def test_diagnostics_keep_error_and_remove_identity_paths(self):
        diagnostic = sanitize_text(r"LNK1104 C:\Users\alice\repo\samples\builds\x.exe; C:\Users\alice\cache\x.obj", r"C:\Users\alice\repo")
        self.assertIn("LNK1104", diagnostic)
        self.assertIn("samples/builds/x.exe", diagnostic)
        self.assertNotIn("alice", diagnostic)
        assert_portable_metadata(diagnostic)
        escaped = sanitize_text(repr(PermissionError(r"C:\Users\alice\repo\samples\x.exe")), r"C:\Users\alice\repo")
        self.assertIn("samples/x.exe", escaped)
        self.assertNotIn("USER_HOME", escaped)

    def test_machine_path_leaks_fail_closed(self):
        for path in (r"C:\Users\alice\repo\x.c", "/home/alice/repo/x.c"):
            with self.assertRaises(ValueError):
                assert_portable_metadata({"flags": [path]})

    def test_all_versioned_dataset_json_is_portable(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "datasets/osgf_pairs_v0_1").rglob("*.json"):
            with self.subTest(path=path.name):
                assert_portable_metadata(json.loads(path.read_text(encoding="utf-8")))
