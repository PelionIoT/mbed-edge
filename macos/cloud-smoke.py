#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enroll an isolated test identity and verify foreground reconnection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import tempfile
import time


class Failure(Exception):
    pass


def unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise Failure("Provisioning JSON has duplicate fields")
        result[name] = value
    return result


def read_input(path, limit=16 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise Failure("Provisioning input must be a bounded regular file")
        data = stream.read(limit + 1)
        if not 0 < len(data) <= limit:
            raise Failure("Provisioning input exceeds its size limit")
        return data


def write_private(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def prepare(source, kind, directory, converter):
    data = read_input(source, 1024 * 1024 if kind == "json" else 16 * 1024 * 1024)
    if kind == "developer":
        original = directory / "developer.c"
        write_private(original, data)
        bundle = directory / "provisioning.cbor"
        with (directory / "conversion.log").open("xb") as log:
            result = subprocess.run([str(converter), "convert-developer", "--input", str(original),
                                     "--output", str(bundle)], stdout=log, stderr=log, timeout=30)
        if result.returncode != 0:
            raise Failure("Developer credential conversion failed; inspect the private conversion log")
        return "--cbor-conf", bundle
    if kind == "json":
        root = json.loads(data, object_pairs_hook=unique_fields)
        if not isinstance(root, dict):
            raise Failure("Provisioning JSON must be an object")
        for group in ("Certificates", "Keys"):
            entries = root.get(group, [])
            if not isinstance(entries, list) or len(entries) > 256:
                raise Failure("Invalid provisioning credential group")
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict) or not isinstance(entry.get("Data"), str):
                    raise Failure("JSON credentials must reference local DER files")
                reference = entry["Data"]
                if not reference or ":" in reference or "\\" in reference or ".." in Path(reference).parts:
                    raise Failure("Invalid provisioning sidecar path")
                target = directory / (group + "-" + str(index) + ".der")
                write_private(target, read_input(source.parent / reference, 1024 * 1024))
                entry["Data"] = str(target)
        if "RoTFilePath" in root:
            reference = root["RoTFilePath"]
            if not isinstance(reference, str) or not reference or ":" in reference or ".." in Path(reference).parts:
                raise Failure("Invalid Root of Trust path")
            target = directory / "root-of-trust.bin"
            rot = read_input(source.parent / reference, 16)
            if len(rot) != 16:
                raise Failure("Root of Trust must contain 16 bytes")
            write_private(target, rot)
            root["RoTFilePath"] = str(target)
        data = json.dumps(root).encode()
    bundle = directory / ("provisioning." + kind)
    write_private(bundle, data)
    return "--" + kind + "-conf", bundle


def wait_connected(process, control, socket_path, deadline, log):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise Failure("Core exited before connecting; inspect its private log")
        result = subprocess.run([str(control), "diagnose", "--socket", str(socket_path),
                                 "--uid", str(os.getuid()), "--pid", str(process.pid), "--json"],
                                stdout=subprocess.PIPE, stderr=log, timeout=10)
        if result.returncode == 0:
            report = json.loads(result.stdout)
            if report["cloudState"] == "connected" and report["statusAvailable"] and report["processId"] == process.pid:
                # The private parent and checked process identity protect this second local read.
                raw = subprocess.run(["/usr/bin/curl", "--silent", "--show-error", "--fail", "--max-time", "3",
                                      "--noproxy", "*", "--unix-socket", str(socket_path), "http://localhost/status"],
                                     stdout=subprocess.PIPE, stderr=log, timeout=5)
                if raw.returncode == 0:
                    status = json.loads(raw.stdout)
                    identity = status.get("internal-id", "")
                    if (status.get("status") == "connected" and status["connectivity"]["processId"] == process.pid
                            and isinstance(identity, str) and len(identity) == 32
                            and all(c in "0123456789abcdefABCDEF" for c in identity)):
                        return identity.lower(), report["version"]
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise Failure("Core did not report Connected before the deadline; inspect its private log")


def run_core(core, control, directory, seconds, phase, provisioning=()):
    socket_path = directory / "status" / "status.sock"
    commands = [str(core), "--status-socket", str(socket_path), "--edge-pt-domain-socket",
                str(directory / "pt" / "pt.sock"), "--http-port", "0"] + list(map(str, provisioning))
    with (directory / (phase + ".log")).open("xb") as log:
        process = subprocess.Popen(commands, cwd=directory, stdout=log, stderr=log, start_new_session=True)
        connected = False
        try:
            result = wait_connected(process, control, socket_path, time.monotonic() + seconds, log)
            connected = True
            return result
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise Failure("Core required a forced shutdown; inspect its private log")
            if connected and process.returncode != 0:
                raise Failure("Core did not shut down cleanly; inspect its private log")


def main():
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, type=Path, help="non-production local provisioning file")
    parser.add_argument("--format", required=True, choices=("developer", "cbor", "json"))
    parser.add_argument("--core", type=Path, default=repository / "build/macos-release/bin/edge-core")
    parser.add_argument("--control", type=Path, default=repository.parent / "edge-core-monitor/build/macos/release/bin/izuma-edge-ctl")
    parser.add_argument("--timeout", type=int, default=180, help="connection deadline in seconds for each run")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() == 0:
        parser.error("Run as an ordinary user on Apple Silicon macOS")
    if int(platform.mac_ver()[0].split(".")[0]) < 14 or not 10 <= args.timeout <= 900:
        parser.error("Requires macOS 14+ and a timeout between 10 and 900 seconds")
    os.umask(0o077)
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    directory = Path(tempfile.mkdtemp(prefix="edge-cloud-", dir="/private/tmp"))
    report = {"schemaVersion": 1, "passed": False, "foreground": True, "releaseSigningRequired": False,
              "firstConnected": False, "retainedConnected": False, "sameIdentity": False,
              "ptCloudExchange": "pending", "stateDirectory": str(directory)}
    try:
        core, control = args.core.resolve(), args.control.resolve()
        for binary in (core, control):
            architectures = subprocess.run(["/usr/bin/lipo", "-archs", str(binary)], capture_output=True, timeout=10)
            if architectures.returncode != 0 or architectures.stdout.strip() != b"arm64":
                raise Failure("Core and the diagnostic console must be native arm64 executables")
        directory.joinpath("pt").mkdir(mode=0o700)
        directory.joinpath("status").mkdir(mode=0o700)
        report["coreSHA256"] = hashlib.sha256(core.read_bytes()).hexdigest()
        provisioning = prepare(args.credentials.absolute(), args.format, directory, core.parent / "edge-provision")
        identity, version = run_core(core, control, directory, args.timeout, "first", provisioning)
        report.update(firstConnected=True, version=version)
        retained, _ = run_core(core, control, directory, args.timeout, "retained")
        report.update(retainedConnected=True, sameIdentity=identity == retained)
        if not report["sameIdentity"]:
            raise Failure("Cloud identity changed after restart")
        report["passed"] = True
    except Failure as error:
        report["error"] = str(error)
    except KeyboardInterrupt:
        report["error"] = "Cloud check interrupted; retained private state was preserved"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        report["error"] = "Cloud check failed while reading input or running a local tool; inspect private logs"
    finally:
        write_private(directory / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
