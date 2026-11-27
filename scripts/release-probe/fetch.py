# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch phase: release set, official artifacts, digest checks and the probe
images. Network, no credentials. Nothing upstream is executed here."""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import engine
import spec

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(HERE, "..", "..", "cli", "internal", "maintainer",
                        "coveragereport", "data", "coverage-lines.json")
USER_AGENT = "release-probe"
IMAGES = {"etcd": "gcr.io/etcd-development/etcd", "vitess": "docker.io/vitess/vttablet"}
_MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json"])


class Withhold(Exception):
    """No acceptable official artifact: the pair cannot pass."""


class NotPublished(Exception):
    """Upstream publishes nothing for this platform."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data, want):
    got = sha256(data)
    if got != want:
        raise Withhold("digest mismatch: got %s, upstream lists %s" % (got, want))
    return got


def http_get(url, headers=None):
    """(status, headers, body); status is 200 or 404, anything else raises."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=120) as reply:
                return 200, reply.headers, reply.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, exc.headers, b""
            if exc.code == 401:
                return 401, exc.headers, b""
            last = "HTTP %d" % exc.code
        except (urllib.error.URLError, OSError) as exc:
            last = str(exc)
        time.sleep(2 ** attempt)
    raise Withhold("cannot fetch %s: %s" % (url, last))


# Release set.

def final_tags(ls_remote, line):
    """{tag: commit} of the final tags of one line; peeled commits win."""
    pattern = re.compile(r"refs/tags/(v%s\.(?:0|[1-9]\d*))(\^\{\})?" % re.escape(line))
    plain, peeled = {}, {}
    for row in ls_remote.splitlines():
        parts = row.split("\t")
        if len(parts) != 2:
            continue
        m = pattern.fullmatch(parts[1])
        if m:
            (peeled if m.group(2) else plain)[m.group(1)] = parts[0]
    return {**plain, **peeled}


def release_set_problems(pinned, snapshot, live):
    """pinned: [{tag, commit}]; snapshot: [version]; live: {tag: commit}."""
    problems = []
    tags = [r["tag"] for r in pinned]
    if not tags:
        problems.append("pinned release set is empty")
    for tag in sorted({t for t in tags if tags.count(t) > 1}):
        problems.append("duplicate pinned tag " + tag)
    snap = ["v" + v for v in snapshot]
    for tag in sorted({t for t in snap if snap.count(t) > 1}):
        problems.append("duplicate snapshot tag " + tag)
    for tag in sorted(set(snap) - set(tags)):
        problems.append("snapshot tag not pinned: " + tag)
    for tag in sorted(set(tags) - set(snap)):
        problems.append("tag missing from the lines snapshot: " + tag)
    for tag in sorted(set(live) - set(tags)):
        problems.append("upstream tag not pinned (newer or extra): " + tag)
    for row in pinned:
        if row["tag"] not in live:
            problems.append("pinned tag missing upstream: " + row["tag"])
        elif live[row["tag"]] != row["commit"]:
            problems.append("tag moved: " + row["tag"])
    return problems


def load_releases():
    with open(os.path.join(HERE, "releases.json"), encoding="utf-8") as f:
        return json.load(f)


def load_snapshot():
    with open(SNAPSHOT, "rb") as f:
        raw = f.read()
    return json.loads(raw), sha256(raw)


def release_set(pair):
    conf = spec.PAIRS[pair]
    repo = spec.REPOSITORIES[conf["project"]]
    proc = subprocess.run(["git", "ls-remote", "--tags", repo], capture_output=True,
                          text=True, timeout=300, env={"PATH": os.environ["PATH"],
                                                       "GIT_TERMINAL_PROMPT": "0"})
    if proc.returncode != 0:
        raise RuntimeError("tag listing failed: " + proc.stderr[:500])
    snapshot, digest = load_snapshot()
    record = {"repository": repo, "snapshot_sha256": digest, "lines": {}}
    for side in ("from", "to"):
        line = conf[side]
        record["lines"][line] = {
            "snapshot": snapshot["projects"][conf["project"]]["releases"].get(line, []),
            "live": final_tags(proc.stdout, line),
        }
    return record


# Release assets.

def parse_sums(text, name):
    """The one sha256 the checksum file lists for name, or None."""
    found = set()
    for row in text.splitlines():
        parts = row.split()
        if len(parts) == 2 and parts[1].lstrip("*") in (name, "./" + name) \
                and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            found.add(parts[0].lower())
    if len(found) > 1:
        raise Withhold("checksum file lists conflicting digests for " + name)
    return found.pop() if found else None


def tar_member(data, path):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        found = [m for m in tar.getmembers() if m.name in (path, "./" + path)]
        if len(found) != 1 or not found[0].isfile():
            raise Withhold("archive does not hold exactly one regular file " + path)
        return tar.extractfile(found[0]).read()


def signature_state(urls):
    """Signatures upstream publishes next to the asset. No signer is pinned,
    so a published signature cannot be verified and the release is withheld."""
    published = []
    for url in urls:
        status, _, body = http_get(url)
        if status == 200:
            proc = subprocess.run(["gpg", "--batch", "--list-packets"], input=body,
                                  capture_output=True, timeout=60,
                                  env={"PATH": os.environ["PATH"],
                                       "GNUPGHOME": tempfile.mkdtemp()})
            keys = re.findall(r"keyid ([0-9A-F]{16})", proc.stdout.decode("utf-8", "replace"))
            published.append("%s (key id %s)" % (url, ",".join(sorted(set(keys))) or "unread"))
        elif status != 404:
            raise Withhold("cannot tell whether a signature is published: " + url)
    return published


def etcd_asset(tag, arch):
    """(binary bytes, record), or None when upstream lists no checksum."""
    base = "https://github.com/etcd-io/etcd/releases/download/%s/" % tag
    name = "etcd-%s-linux-%s.tar.gz" % (tag, arch)
    status, _, sums = http_get(base + "SHA256SUMS")
    if status == 401:
        raise Withhold("checksum file needs credentials")
    listed = parse_sums(sums.decode("utf-8", "replace"), name) if status == 200 else None
    if listed is None:
        return None
    status, _, data = http_get(base + name)
    if status != 200:
        raise Withhold("asset listed in the checksum file is missing: " + name)
    digest = verify_sha256(data, listed)
    published = signature_state([base + name + ".asc", base + "SHA256SUMS.asc"])
    if published:
        raise Withhold("upstream publishes a signature that is not verified: "
                       + "; ".join(published))
    binary = tar_member(data, name[:-len(".tar.gz")] + "/etcd")
    return binary, {"route": "asset", "artifact_url": base + name, "artifact_sha256": digest,
                    "checksum_source": base + "SHA256SUMS",
                    "checksum_file_sha256": sha256(sums), "checksum_listed": listed,
                    "checksum_result": "match", "signature": "none published",
                    "base_image": "scratch (empty)", "binary_sha256": sha256(binary)}


def vitess_checksum_note(tags):
    """Per tag: refuse unless upstream's release lists no checksum asset."""
    notes = {}
    for page in range(1, 5):
        status, _, body = http_get(
            "https://api.github.com/repos/vitessio/vitess/releases?per_page=100&page=%d" % page,
            {"Accept": "application/vnd.github+json"})
        if status != 200:
            raise Withhold("cannot list upstream releases")
        rows = json.loads(body)
        for row in rows:
            if row.get("tag_name") in tags:
                names = [a["name"] for a in row.get("assets", [])]
                notes[row["tag_name"]] = {
                    "assets": names,
                    "checksum_assets": [n for n in names if re.search(
                        r"(?i)sha(1|256|512)|checksum|sums|\.(asc|sig)$", n)]}
        if not rows or set(tags) <= set(notes):
            break
    return notes


# Official images by manifest digest.

def registry_get(repo, reference):
    host, path = repo.split("/", 1)
    if host == "docker.io":
        host = "registry-1.docker.io"
    url = "https://%s/v2/%s/manifests/%s" % (host, path, reference)
    headers = {"Accept": _MANIFEST_TYPES}
    status, reply, body = http_get(url, headers)
    if status == 401:
        # Anonymous pull token, as the registry asks for it.
        fields = dict(re.findall(r'(\w+)="([^"]*)"', reply.get("WWW-Authenticate", "")))
        query = urllib.parse.urlencode(
            {"service": fields.get("service", ""), "scope": "repository:%s:pull" % path})
        status, _, token = http_get(fields.get("realm", "") + "?" + query)
        if status != 200:
            raise Withhold("registry gave no anonymous token")
        headers["Authorization"] = "Bearer " + json.loads(token)["token"]
        status, reply, body = http_get(url, headers)
    if status == 404:
        return None
    if status != 200:
        raise Withhold("registry refused " + url)
    digest = "sha256:" + sha256(body)
    claimed = reply.get("Docker-Content-Digest")
    if claimed and claimed != digest:
        raise Withhold("manifest bytes do not match the registry digest")
    if reference.startswith("sha256:") and reference != digest:
        raise Withhold("manifest bytes do not match the requested digest")
    return digest, json.loads(body)


def resolve_image(repo, tag, arch):
    """Digest record for the exact version tag on one platform."""
    got = registry_get(repo, tag)
    if got is None:
        raise Withhold("no official image %s:%s" % (repo, tag))
    tag_digest, manifest = got
    platform_digest = tag_digest
    if "manifests" in manifest:
        match = [m["digest"] for m in manifest["manifests"]
                 if m.get("platform", {}).get("os") == "linux"
                 and m.get("platform", {}).get("architecture") == arch]
        if not match:
            raise NotPublished("image index has no linux/" + arch)
        if len(match) != 1:
            raise Withhold("image index lists linux/%s more than once" % arch)
        platform_digest = match[0]
        if registry_get(repo, platform_digest) is None:
            raise Withhold("platform manifest is missing")
    return {"repository": repo, "tag": tag, "tag_digest": tag_digest,
            "platform_digest": platform_digest}


def build_image(base, arch, files, label):
    """files: {absolute path: (bytes, mode)}; copied in before any start."""
    work = tempfile.mkdtemp(prefix="probe-build-")
    try:
        root = os.path.join(work, "root")
        for path, (data, mode) in files.items():
            target = os.path.join(root, path.lstrip("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
            os.chmod(target, mode)
        for current, dirs, _ in os.walk(root):
            os.chmod(current, 0o755)
            for d in dirs:
                os.chmod(os.path.join(current, d), 0o755)
        with open(os.path.join(work, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write("FROM %s\nCOPY root/ /\n" % base)
        iid = os.path.join(work, "iid")
        engine.docker("build", "--platform", "linux/" + arch, "--network", "none",
                      "--iidfile", iid, "-t", "release-probe/" + label, work, timeout=900)
        with open(iid, encoding="utf-8") as f:
            return f.read().strip()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def throwaway_ca():
    work = tempfile.mkdtemp(prefix="probe-ca-")
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "2", "-subj", "/CN=probe-throwaway-ca",
                        "-keyout", os.path.join(work, "key.pem"),
                        "-out", os.path.join(work, "ca.pem")],
                       check=True, capture_output=True, timeout=120)
        with open(os.path.join(work, "ca.pem"), "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def synthetic_files(project):
    if project == "etcd":
        return {
            "/probe/etcd.yml": b"name: default\ndata-dir: /tmp/probe-data\n"
                               b"initial-cluster: default=http://localhost:2380\n",
            "/probe/tls/ca.pem": throwaway_ca(),
        }
    return {"/probe/vtconfig.yaml": b"{}\n"}


def prepare(project, tag, arch, files, notes):
    """The fetch record of one release, including the probe image id."""
    staged = {path: (data, 0o644) for path, data in files.items()}
    record = {}
    asset = etcd_asset(tag, arch) if project == "etcd" else None
    if asset:
        binary, record = asset
        staged["/usr/local/bin/etcd"] = (binary, 0o755)
        image = build_image("scratch", arch, staged, "%s-%s-%s" % (project, tag, arch))
        info = json.loads(engine.docker("image", "inspect", image).stdout)[0]
    else:
        if project == "vitess":
            note = notes.get(tag)
            if note is None:
                raise Withhold("upstream release entry not found")
            if note["checksum_assets"]:
                raise Withhold("upstream publishes checksum or signature assets this harness "
                               "does not verify: %s" % note["checksum_assets"])
            checksum_note = {"assets": note["assets"]}
        else:
            checksum_note = {}
        resolved = resolve_image(IMAGES[project], tag, arch)
        pinned = "%s@%s" % (resolved["repository"], resolved["platform_digest"])
        engine.docker("pull", "--platform", "linux/" + arch, pinned, timeout=900)
        base = json.loads(engine.docker("image", "inspect", pinned).stdout)[0]
        if base["Architecture"] != arch or base["Os"] != "linux":
            raise NotPublished("official image is %s/%s" % (base["Os"], base["Architecture"]))
        image = build_image(pinned, arch, staged, "%s-%s-%s" % (project, tag, arch))
        info = json.loads(engine.docker("image", "inspect", image).stdout)[0]
        record = {"route": "image", "artifact_url": pinned, "image": resolved,
                  "checksum_source": "upstream publishes no checksum file for this artifact; "
                                     "official image pinned by manifest digest",
                  "checksum_result": "digest pin", "upstream": checksum_note,
                  "base_image": pinned,
                  "binary_sha256": image_file_sha256(
                      image, next(p["entrypoint"] for p in spec.PAIRS.values()
                                  if p["project"] == project))}
    config = info.get("Config", {})
    names = [e.split("=", 1)[0] for e in config.get("Env") or []]
    record.update({
        "status": "ok", "image_id": info["Id"],
        "unset_env": sorted(n for n in names if n != "PATH"),
        "image_entrypoint": config.get("Entrypoint"),
        "tmpfs": sorted({"/tmp"} | set(config.get("Volumes") or {})),
        "files": {path: {"sha256": sha256(data), "content": data.decode("utf-8")}
                  for path, data in files.items()},
    })
    return record


def image_file_sha256(image, path):
    name = "probe-copy-%d" % time.monotonic_ns()
    engine.docker("create", "--name", name, "--network", "none", "--entrypoint", path, image)
    try:
        proc = engine.docker("cp", "--follow-link", "%s:%s" % (name, path), "-", binary=True)
        with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            if len(members) != 1:
                raise Withhold("binary not found in the image: " + path)
            return sha256(tar.extractfile(members[0]).read())
    finally:
        engine.docker("rm", "-f", "-v", name, check=False)
