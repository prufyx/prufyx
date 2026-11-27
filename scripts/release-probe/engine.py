# SPDX-License-Identifier: AGPL-3.0-only
"""One new, isolated container per case."""

import datetime
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid

import judge
import spec

_CONFIG_DIR = tempfile.mkdtemp(prefix="probe-docker-")


def docker_env():
    """The engine client gets no credentials and nothing a container could
    inherit by name."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "DOCKER_CONFIG": _CONFIG_DIR}


def docker(*args, check=True, timeout=600, binary=False):
    proc = subprocess.run(["docker"] + list(args), env=docker_env(), timeout=timeout,
                          capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError("docker %s failed: %s" % (
            args[0], proc.stderr.decode("utf-8", "replace")[:2000]))
    if binary:
        return proc
    proc.stdout = proc.stdout.decode("utf-8", "replace")
    proc.stderr = proc.stderr.decode("utf-8", "replace")
    return proc


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def create_args(name, image, entrypoint, argv, env, unset, tmpfs):
    args = ["create", "--name", name, "--hostname", "probe",
            "--network", "none", "--user", spec.UID,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
            "--pids-limit", "512", "--workdir", "/tmp"]
    for path in tmpfs:
        args += ["--tmpfs", path + ":rw,mode=1777,size=256m"]
    # A name without a value removes the variable the image would set.
    for key in unset:
        args += ["--env", key]
    for key, value in sorted(env.items()):
        args += ["--env", "%s=%s" % (key, value)]
    return args + ["--entrypoint", entrypoint, image] + argv


def options_from_inspect(info):
    host, config = info["HostConfig"], info["Config"]
    return {
        "network_mode": host.get("NetworkMode"),
        "mounts": info.get("Mounts"),
        "binds": host.get("Binds"),
        "volumes_from": host.get("VolumesFrom"),
        "devices": host.get("Devices"),
        "tmpfs": host.get("Tmpfs"),
        "user": config.get("User"),
        "cap_drop": host.get("CapDrop"),
        "cap_add": host.get("CapAdd"),
        "privileged": host.get("Privileged"),
        "security_opt": host.get("SecurityOpt"),
        "pid_mode": host.get("PidMode"),
        "ipc_mode": host.get("IpcMode"),
        "memory": host.get("Memory"),
        "nano_cpus": host.get("NanoCpus"),
        "pids_limit": host.get("PidsLimit"),
        "env": config.get("Env") or [],
        "image": info.get("Image"),
    }


class _Stream:
    def __init__(self, pipe, limit):
        self.data = bytearray()
        self.truncated = False
        self._limit = limit
        self._pipe = pipe
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            chunk = self._pipe.read1(65536)
            if not chunk:
                return
            room = self._limit - len(self.data)
            if len(chunk) > room:
                self.truncated = True
            self.data += chunk[:max(room, 0)]

    def text(self):
        return bytes(self.data).decode("utf-8", "replace")


def run_case(image, entrypoint, argv, env, ready_pattern, unset=(), tmpfs=("/tmp",),
             time_limit=spec.TIME_LIMIT_SECONDS, output_limit=spec.OUTPUT_LIMIT_BYTES):
    """Runs one case and returns the raw observation. A container whose
    reported options break an isolation rule is never started."""
    name = "probe-" + uuid.uuid4().hex
    obs = {"start": now(), "end": None, "exit_code": None, "timed_out": False,
           "truncated": False, "oom": False, "stopped_when_ready": False,
           "stdout": "", "stderr": "", "options": None, "error": None}
    try:
        docker(*create_args(name, image, entrypoint, argv, env, unset, tmpfs))
        info = json.loads(docker("inspect", name).stdout)[0]
        obs["options"] = options_from_inspect(info)
        problems = judge.option_problems(obs["options"], env)
        if problems:
            raise RuntimeError("isolation: " + "; ".join(problems))
        proc = subprocess.Popen(["docker", "start", "--attach", name], env=docker_env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = _Stream(proc.stdout, output_limit)
        err = _Stream(proc.stderr, output_limit)
        deadline = time.monotonic() + time_limit
        seen = 0
        while proc.poll() is None:
            if out.truncated or err.truncated:
                break
            size = len(out.data) + len(err.data)
            if ready_pattern and size != seen:
                seen = size
                if re.search(ready_pattern, out.text() + "\n" + err.text()):
                    time.sleep(0.3)
                    obs["stopped_when_ready"] = proc.poll() is None
                    break
            if time.monotonic() > deadline:
                obs["timed_out"] = True
                break
            time.sleep(0.02)
        if proc.poll() is None:
            docker("kill", name, check=False)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError("container did not stop")
        out.thread.join(10)
        err.thread.join(10)
        if out.thread.is_alive() or err.thread.is_alive():
            raise RuntimeError("output stream did not close")
        state = json.loads(docker("inspect", name).stdout)[0]["State"]
        if state.get("Running") or state.get("Error") or \
                str(state.get("StartedAt", "")).startswith("0001-"):
            raise RuntimeError("container state: %s" % state.get("Error", "never ran"))
        obs["exit_code"] = state["ExitCode"]
        obs["oom"] = bool(state.get("OOMKilled"))
        obs["truncated"] = out.truncated or err.truncated
        obs["stdout"], obs["stderr"] = out.text(), err.text()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
        obs["error"] = str(exc)[:2000]
    finally:
        docker("rm", "-f", "-v", name, check=False)
        obs["end"] = now()
    return obs
