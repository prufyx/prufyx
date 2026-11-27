# SPDX-License-Identifier: AGPL-3.0-only
"""Classification of raw container output, and the pass rule of a case.
Output is untrusted text: it is matched, never executed. Anything that is
not exactly the expected outcome fails."""

import re

import spec

_GOFLAG = re.compile(r"^flag provided but not defined: -(\S+)[ \t\r]*$", re.M)
_PFLAG_LONG = re.compile(r"unknown flag: --([^\s\"'\\]+)")
_PFLAG_SHORT = re.compile(r"unknown shorthand flag: '(.)' in -([^\s\"'\\]+)")
# The whole message, only after one of the two prefixes the program prints.
_KINGPIN = re.compile(
    r"(?:^thanos: error: |^error parsing commandline arguments: .*\]: )"
    r"unknown (long flag '--|short flag '-)([^'\n]*)'[ \t\r]*$", re.M)
_CRASH = re.compile(r"^(panic: |fatal error: )|SIGSEGV", re.M)


def unknown_tokens(parser, text):
    """Sorted list of [template, token] for every unknown-item message."""
    found = set()
    if parser == "goflag":
        for m in _GOFLAG.finditer(text):
            found.add(("goflag", m.group(1)))
    elif parser == "pflag":
        for m in _PFLAG_LONG.finditer(text):
            found.add(("long", m.group(1).split("=")[0]))
        for m in _PFLAG_SHORT.finditer(text):
            token = m.group(2).split("=")[0]
            if token[:1] != m.group(1):
                token = "?" + token
            found.add(("short", token))
    elif parser == "kingpin":
        for m in _KINGPIN.finditer(text):
            style = "long" if m.group(1).startswith("long") else "short"
            found.add((style, m.group(2)))
    else:
        raise ValueError("unknown parser %r" % parser)
    return sorted(list(t) for t in found)


def text_of(obs):
    return obs["stdout"] + "\n" + obs["stderr"]


def classify(parser, ready_pattern, obs):
    text = text_of(obs)
    tokens = unknown_tokens(parser, text)
    ready = re.search(ready_pattern, text)
    result = {"class": "OTHER", "tokens": tokens,
              "ready_text": ready.group(0).rstrip() if ready else None}
    if obs.get("error"):
        result["class"] = "HARNESS_ERROR"
    elif obs["truncated"]:
        result["class"] = "TRUNCATED"
    elif obs["oom"]:
        result["class"] = "OOM"
    elif _CRASH.search(text):
        result["class"] = "CRASH"
    elif ready and tokens:
        result["class"] = "READY_WITH_UNKNOWN"
    elif obs["timed_out"]:
        result["class"] = "TIMEOUT"
    elif ready:
        result["class"] = "READY"
    elif tokens and obs["exit_code"] != 0:
        result["class"] = "REJECTED"
    elif tokens:
        result["class"] = "UNKNOWN_BUT_EXIT_ZERO"
    return result


def version_problem(project, tag, commit, obs):
    """None when the version output names the tag and the tag commit."""
    if obs.get("error") or obs["truncated"] or obs["timed_out"] or obs["oom"]:
        return "version run did not complete"
    if obs["exit_code"] != 0:
        return "version run exited %s" % obs["exit_code"]
    text = text_of(obs)
    if project == "etcd":
        versions = re.findall(r"^etcd Version: (\S+)[ \t\r]*$", text, re.M)
        commits = re.findall(r"^Git SHA: (\S+)[ \t\r]*$", text, re.M)
    elif project == "vitess":
        found = re.findall(r"Version: (\d\S*) .*?\(?Git revision (\S+)", text)
        versions = [v for v, _ in found]
        commits = [c for _, c in found]
    elif project == "thanos":
        found = re.findall(r"^thanos, version (\S+) \(branch: [^,\n]*, "
                           r"revision: ([0-9a-f]+)\)[ \t\r]*$", text, re.M)
        versions = [v for v, _ in found]
        commits = [c for _, c in found]
    else:
        return "unknown project"
    if len(set(versions)) != 1 or versions[0] != tag[1:]:
        return "version output names %s, tag is %s" % (sorted(set(versions)), tag)
    if len(set(commits)) != 1 or not re.fullmatch(r"[0-9a-f]{7,40}", commits[0]) \
            or not commit.startswith(commits[0]):
        return "version output commit %s does not match tag commit %s" % (
            sorted(set(commits)), commit)
    return None


def case_problem(parser, case, result):
    """None when a non-version case has exactly the expected outcome."""
    if case["expect"] == "ready":
        if result["class"] != "READY":
            return "expected ready, got " + _describe(result)
        return None
    if case["expect"] == "rejected":
        if result["class"] != "REJECTED":
            return "expected rejection of %s, got %s" % (case["token"], _describe(result))
        template = "goflag" if parser == "goflag" else case["style"]
        if result["tokens"] != [[template, case["token"]]]:
            return "expected %s message naming %s, got %s" % (
                template, case["token"], result["tokens"])
        return None
    return "case expectation %r is not judged here" % case["expect"]


def _describe(result):
    if result["tokens"]:
        return "%s %s" % (result["class"], result["tokens"])
    return result["class"]


_ENV_PATH = "PATH="


def option_problems(options, env):
    """Violations of the isolation rules in the engine's own report."""
    problems = []

    def need(ok, what):
        if not ok:
            problems.append(what)

    need(options.get("network_mode") == "none", "network mode is not none")
    need(options.get("mounts") == [], "mount list is not empty")
    need(not options.get("binds"), "bind mounts present")
    need(not options.get("volumes_from"), "volumes-from present")
    need(not options.get("devices"), "devices present")
    need(options.get("user") == spec.UID, "user is not " + spec.UID)
    need(options.get("cap_drop") == ["ALL"], "capabilities not all dropped")
    need(not options.get("cap_add"), "capabilities added")
    need(options.get("privileged") is False, "privileged")
    need(options.get("security_opt") == ["no-new-privileges"],
         "security options are not exactly no-new-privileges")
    need(options.get("pid_mode") == "", "pid namespace shared")
    need(options.get("ipc_mode") in ("", "private"), "ipc namespace shared")
    for key in ("memory", "nano_cpus", "pids_limit"):
        need(isinstance(options.get(key), int) and options[key] > 0, key + " is not limited")
    listed = options.get("env")
    if not isinstance(listed, list):
        problems.append("environment not reported")
    else:
        want = ["%s=%s" % kv for kv in sorted(env.items())]
        got = sorted(e for e in listed if "=" in e and not e.startswith(_ENV_PATH))
        need(got == want, "environment is %s, want %s" % (got, want))
    return problems
