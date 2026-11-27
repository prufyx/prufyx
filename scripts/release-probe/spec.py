# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned probe definitions: pairs, items, base invocations and the full
case list. The runner and the checker both derive the expected cases from
here, so a case that was not run is a gap."""

import itertools

REPEATS = 2
ARCHES = ("amd64", "arm64")
UID = "65532:65532"
TIME_LIMIT_SECONDS = 60
OUTPUT_LIMIT_BYTES = 256 * 1024

# Bogus names. The pflag one starts with the same letter as the item it
# controls, so the single dash template names the same shorthand letter. The
# kingpin one starts with a letter the probed command does not register as a
# shorthand.
BOGUS = {"goflag": "probe-bogus-item", "pflag": "tzz-probe-bogus",
         "kingpin": "zz-probe-bogus"}

ETCD_CA = "/probe/tls/ca.pem"


def _item(name, value, retained, boolean=False):
    return {"name": name, "value": value, "retained": retained, "boolean": boolean}


_ETCD_CONTEXTS = {
    "base": ["--data-dir", "/tmp/probe-data"],
    "config-file": ["--config-file", "/probe/etcd.yml"],
}

PAIRS = {
    "etcd-3.3-3.4": {
        "project": "etcd",
        "binary": "etcd",
        "entrypoint": "/usr/local/bin/etcd",
        "parser": "goflag",
        "from": "3.3",
        "to": "3.4",
        "ready": r"ready to serve client requests",
        "contexts": _ETCD_CONTEXTS,
        "from_context": "base",
        "to_contexts": ["base", "config-file"],
        "items": [
            _item("ca-file", ETCD_CA, ["--trusted-ca-file=" + ETCD_CA]),
            _item("peer-ca-file", ETCD_CA, ["--peer-trusted-ca-file=" + ETCD_CA]),
        ],
        "excluded": {},
    },
    "etcd-3.4-3.5": {
        "project": "etcd",
        "binary": "etcd",
        "entrypoint": "/usr/local/bin/etcd",
        "parser": "goflag",
        "from": "3.4",
        "to": "3.5",
        "ready": r"ready to serve client requests",
        "contexts": _ETCD_CONTEXTS,
        "from_context": "base",
        "to_contexts": ["base", "config-file"],
        "items": [
            _item("debug", "true", ["--log-level=info"], boolean=True),
            _item("log-output", "stderr", ["--log-outputs=stderr"]),
            _item("log-package-levels", "etcdmain=INFO", ["--log-level=info"]),
            _item("experimental-backend-bbolt-freelist-type", "map",
                  ["--backend-bbolt-freelist-type=map"]),
        ],
        "excluded": {"logger=capnslog": "a flag value is not a set member"},
    },
    "vitess-20-21": {
        "project": "vitess",
        "binary": "vttablet",
        "entrypoint": "/vt/bin/vttablet",
        "parser": "pflag",
        "from": "20.0",
        "to": "21.0",
        # Printed by the run function, which starts only after flag parsing.
        "ready": r"failed to parse --tablet-path: [^\n\"]*",
        "contexts": {},
        "from_context": "base",
        "to_contexts": ["base", "config-file", "twopc"],
        "items": [
            _item("twopc_coordinator_address", "127.0.0.1:15999",
                  ["--twopc_abandon_age=1"]),
        ],
        "excluded": {},
    },
}

_VTTABLET_BASE = [
    "--topo_implementation=etcd2",
    "--topo_global_server_address=127.0.0.1:2379",
    "--topo_global_root=/vitess/global",
    "--tablet-path=probeinvalid",
]
PAIRS["vitess-20-21"]["contexts"] = {
    "base": _VTTABLET_BASE,
    "config-file": _VTTABLET_BASE + ["--config-file=/probe/vtconfig.yaml"],
    "twopc": _VTTABLET_BASE + ["--twopc_enable", "--twopc_abandon_age=1"],
}

_THANOS_QUERY_BASE = [
    "--http-address=127.0.0.1:10902",
    "--grpc-address=127.0.0.1:10901",
]
_THANOS_ENDPOINT = "127.0.0.1:15999"


def _thanos_item(name, retained):
    return _item(name, _THANOS_ENDPOINT, ["--%s=%s" % (retained, _THANOS_ENDPOINT)])


PAIRS["thanos-0.37-0.38"] = {
    "project": "thanos",
    "binary": "thanos query",
    "entrypoint": "/usr/local/bin/thanos",
    # The subcommand. Every case but the version one starts with it.
    "command": ["query"],
    "parser": "kingpin",
    "from": "0.37",
    "to": "0.38",
    # Logged by the gRPC server actor, which runs only after flag parsing.
    "ready": r'msg="changing probe status" status=ready',
    "contexts": {
        "base": _THANOS_QUERY_BASE,
        # Endpoint config file mode.
        "sd-config": _THANOS_QUERY_BASE
        + ["--endpoint.sd-config-file=/probe/endpoints.yml"],
        "distributed": _THANOS_QUERY_BASE + ["--query.mode=distributed"],
        # The parser expands @file into further arguments.
        "args-file": _THANOS_QUERY_BASE + ["@/probe/query.args"],
    },
    "from_context": "base",
    "to_contexts": ["base", "sd-config", "distributed", "args-file"],
    "items": [
        _thanos_item("store", "endpoint"),
        _thanos_item("store-strict", "endpoint-strict"),
        _thanos_item("rule", "endpoint"),
        _thanos_item("target", "endpoint"),
        _thanos_item("metadata", "endpoint"),
        _thanos_item("exemplar", "endpoint"),
    ],
    "excluded": {},
}

REPOSITORIES = {
    "etcd": "https://github.com/etcd-io/etcd",
    "thanos": "https://github.com/thanos-io/thanos",
    "vitess": "https://github.com/vitessio/vitess",
}


def case_env(pair, side, arch):
    """etcd before 3.5 refuses to start on arm64 without this variable, so it
    is part of the base invocation there and is recorded with every case."""
    conf = PAIRS[pair]
    line = conf[side]
    if conf["project"] == "etcd" and arch == "arm64" and line in ("3.3", "3.4"):
        return {"ETCD_UNSUPPORTED_ARCH": "arm64"}
    return {}


def spellings(name):
    """Every '-' / '_' spelling, the canonical one first."""
    parts = name.replace("_", "-").split("-")
    out = [name]
    for seps in itertools.product("-_", repeat=len(parts) - 1):
        word = parts[0] + "".join(s + p for s, p in zip(seps, parts[1:]))
        if word not in out:
            out.append(word)
    return out


def forms(item, name):
    """(form id, dash style, argv tokens) for one spelling."""
    out = []
    for dash, style in (("--", "long"), ("-", "short")):
        flag = dash + name
        if item["boolean"]:
            rows = [("bare", [flag]),
                    ("eq-true", [flag + "=true"]), ("eq-false", [flag + "=false"]),
                    ("sp-true", [flag, "true"]), ("sp-false", [flag, "false"]),
                    ("eq-empty", [flag + "="])]
        else:
            rows = [("eq", [flag + "=" + item["value"]]),
                    ("sp", [flag, item["value"]]),
                    ("bare", [flag]),
                    ("eq-empty", [flag + "="])]
        out.extend((style + "-" + fid, style, argv) for fid, argv in rows)
    return out


def _case(cid, kind, context, argv, expect, item=None, token=None, style=None):
    return {"id": cid, "kind": kind, "context": context, "argv": argv,
            "expect": expect, "item": item, "token": token, "style": style}


def cases(pair, side):
    """The full case list of one release on one side ('from' or 'to')."""
    conf = PAIRS[pair]
    bogus = BOGUS[conf["parser"]]
    command = conf.get("command", [])

    def named(name, style):
        """The token the parser's message names. kingpin reads a single dash
        word as shorthand letters and names only the first one."""
        if conf["parser"] == "kingpin" and style == "short":
            return name[0]
        return name

    out = [_case("version", "version", None, ["--version"], "version")]
    if side == "from":
        ctx = conf["from_context"]
        base = conf["contexts"][ctx]
        out.append(_case(ctx + "/F0", "F0", ctx, command + base, "ready"))
        for item in conf["items"]:
            with_item = command + base + ["--%s=%s" % (item["name"], item["value"])]
            out.append(_case("%s/F1/%s" % (ctx, item["name"]), "F1", ctx,
                             with_item, "ready", item=item["name"]))
            out.append(_case("%s/FB/%s" % (ctx, item["name"]), "FB", ctx,
                             with_item + ["--" + bogus], "rejected",
                             item=item["name"], token=bogus, style="long"))
        return out
    if side != "to":
        raise ValueError("unknown side %r" % side)
    for ctx in conf["to_contexts"]:
        base = conf["contexts"][ctx]
        out.append(_case(ctx + "/T0", "T0", ctx, command + base, "ready"))
        for style, dash in (("long", "--"), ("short", "-")):
            out.append(_case("%s/T2/%s" % (ctx, style), "T2", ctx,
                             command + base + [dash + bogus + "=x"], "rejected",
                             token=named(bogus, style), style=style))
        for item in conf["items"]:
            out.append(_case("%s/T3/%s" % (ctx, item["name"]), "T3", ctx,
                             command + base + item["retained"], "ready",
                             item=item["name"]))
            for name in spellings(item["name"]):
                for fid, style, argv in forms(item, name):
                    for pos in ("first", "last"):
                        full = command + (argv + base if pos == "first"
                                          else base + argv)
                        out.append(_case(
                            "%s/T1/%s/%s/%s/%s" % (ctx, item["name"], name, fid, pos),
                            "T1", ctx, full, "rejected",
                            item=item["name"], token=named(name, style), style=style))
    return out
