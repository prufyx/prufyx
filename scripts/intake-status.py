#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Post the intake status of onboarding request issues (workflow intake-status.yml).

Reads the published status feed over HTTPS from one fixed URL, validates it against a closed schema, checks every id of an entry
against the live issue, and writes ONE comment per issue (created once, then edited in place). Standard library only.

What it never does: read, print or forward the title or body of an issue (the API objects are parsed in this process and only
numbers, state names and label names are looked at), pass any value to a shell, change a label, close, lock or edit an issue, touch
an issue that is not listed in a valid feed, or follow a redirect. Every comment text comes from the fixed tables below; the only
values substituted are a validated project slug and a reason code from a closed set.

The closed sets (STATES, REASONS) repeat the ones the factory publishes; its tests pin them, and a change there must be copied here.
Exit codes: 0 = done (including "no feed yet" and a stale feed), 1 = the feed was refused or an API error happened.
"""
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

FEED_URL = "https://prufyx.com/intake-status/v1.json"
REPO = "prufyx/prufyx"
API = "https://api.github.com"
DOCS_URL = "https://github.com/prufyx/prufyx/blob/main/docs/maintainers.md"
LABEL = "maintainer-intake"
BOT_LOGIN = "github-actions[bot]"
BOT_ID = 41898282  # numeric id of github-actions[bot]; the name alone is never trusted

SCHEMA = "prufyx.io/intake-status"
VERSION = 1
MAX_FEED_BYTES = 256 * 1024
MAX_ITEMS = 500
MAX_API_BYTES = 1024 * 1024
MAX_WRITES = 20
MAX_COMMENT_PAGES = 5
MAX_AGE_SECONDS = 3600
MAX_BODY = 1500
MAX_ID = 2 ** 53

STATES = ("accepted", "held", "onboarded", "parked", "received", "refused")
REASONS = {
    "held": ("alias-unverified", "calver-component", "chart-tag-pattern", "crd-not-structural", "exclusion-needs-owner",
             "group-absent-at-later-release", "helm-target-shape", "incomplete-tree", "invalid-target", "landscape-subject",
             "licence", "no-crds", "no-final-tags", "no-path-set", "other", "reserved-group", "shared-group", "tag-prefix",
             "templated-crds", "tree-too-large", "unreadable-crd"),
    "refused": ("account-too-young", "body-invalid", "body-malformed", "cap-login", "known-project", "no-invite", "other",
                "proof-ambiguous", "record-malformed", "repo-archived", "repo-is-fork", "repo-moved", "repo-not-public",
                "slug-collision", "slug-invalid"),
    "parked": ("already-known", "author-changed", "changed", "issue-closed", "issue-gone", "issue-is-pr", "maintainer-changed",
               "malformed", "other", "proof-expired", "repo-archived", "repo-moved", "repo-not-public", "slug-invalid", "stale"),
}
ITEM_KEYS = frozenset(("issueNumber", "issueId", "authorId", "project", "state", "reason", "updatedAt"))
TOP_KEYS = frozenset(("schema", "version", "generatedAt", "items"))
SLUG_RE = re.compile(r"^[a-z0-9-]{1,63}$")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

# Fixed texts: (headline, next step). Nothing here comes from an issue.
TEXT = {
    "received": ("Your onboarding request was received and passed validation.",
                 "The project is added to the factory catalogue next. Nothing for you to do."),
    "accepted": ("Your onboarding request is accepted and queued.",
                 "It moves through classification and the onboarding pipeline. Nothing for you to do."),
    "held": ("Your request is on hold at a classification check.",
             "A Prufyx maintainer looks at it and replies here if input is needed."),
    "onboarded": ("The project is onboarded.", "Nothing for you to do."),
    "refused": ("Your onboarding request was refused.",
                "The reason code says why. Correct it and file a new request with the current form."),
    "parked": ("Processing of your request is on hold.",
               "A Prufyx maintainer looks at it. File a new request if the project should still be onboarded."),
}


class FeedError(Exception):
    """The feed is refused as a whole (nothing is written)."""


def log(level, code, **kv):
    # only numbers and closed codes are ever logged: no text of an issue, no response body
    parts = " ".join("%s=%s" % (k, kv[k]) for k in sorted(kv))
    print("::%s::intake-status %s %s" % (level, code, parts))


def _pairs(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise FeedError("duplicate key")
        seen[k] = v
    return seen


def _bad_constant(_):
    raise FeedError("non-finite number")


def _is_int(v):
    return type(v) is int  # bool is an int subclass: excluded on purpose


def _parse_time(s):
    if not isinstance(s, str) or not TIME_RE.fullmatch(s):
        raise FeedError("time form")
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise FeedError("time value")


def validate_feed(raw, now):
    """Return the list of items of a valid, fresh feed. FeedError: refuse the whole document. FeedStale: too old to act on."""
    if not isinstance(raw, (bytes, bytearray)) or not raw or len(raw) > MAX_FEED_BYTES:
        raise FeedError("size")
    try:
        text = bytes(raw).decode("utf-8")
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_bad_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise FeedError("not json")
    if not isinstance(doc, dict) or set(doc) != TOP_KEYS:
        raise FeedError("top keys")
    if doc["schema"] != SCHEMA or not _is_int(doc["version"]) or doc["version"] != VERSION:
        raise FeedError("schema or version")
    generated = _parse_time(doc["generatedAt"])
    items = doc["items"]
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise FeedError("items")
    prev, ids = 0, set()
    for it in items:
        if not isinstance(it, dict) or set(it) != ITEM_KEYS:
            raise FeedError("item keys")
        n, i, a = it["issueNumber"], it["issueId"], it["authorId"]
        if not (_is_int(n) and 1 <= n <= 2147483647 and _is_int(i) and 1 <= i <= MAX_ID and _is_int(a) and 1 <= a <= MAX_ID):
            raise FeedError("ids")
        if not isinstance(it["project"], str) or (it["project"] != "" and not SLUG_RE.fullmatch(it["project"])):
            raise FeedError("project")
        state, reason = it["state"], it["reason"]
        if not isinstance(state, str) or state not in STATES or not isinstance(reason, str):
            raise FeedError("state")
        if state in REASONS:
            if reason not in REASONS[state]:
                raise FeedError("reason")
        elif reason != "":
            raise FeedError("reason")
        _parse_time(it["updatedAt"])
        if n <= prev or i in ids:
            raise FeedError("order or duplicate")
        prev = n
        ids.add(i)
    check_freshness(generated, now)
    return items


class FeedStale(Exception):
    """The feed is older than an hour (or from the future): nothing is acted on."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def check_freshness(generated, now):
    age = (now - generated).total_seconds()
    if age > MAX_AGE_SECONDS or age < -300:
        raise FeedStale(age)


def comment_body(item):
    headline, nxt = TEXT[item["state"]]
    lines = ["<!-- prufyx-intake-status:v1 #%d -->" % item["issueNumber"], "Intake status: " + headline, nxt]
    if item["project"]:
        lines.append("Catalogue name: " + item["project"])
    if item["reason"]:
        lines.append("Reason code: " + item["reason"])
    lines.append("This is the status of the intake request only; it is not a compatibility claim.")
    lines.append("How intake works: " + DOCS_URL)
    body = "\n".join(lines)
    if len(body) > MAX_BODY or "@" in body or any(ord(c) > 126 or (ord(c) < 32 and c != "\n") for c in body):
        raise FeedError("comment text")
    # the only '<' is the marker
    if body.count("<") != 1 or body.count(">") != 1:
        raise FeedError("comment text")
    return body


def marker(n):
    return "<!-- prufyx-intake-status:v1 #%d -->" % n


# --- GitHub API: a closed set of requests -------------------------------------------------------------------------------------

_ALLOWED = (
    ("GET", re.compile(r"^/repos/prufyx/prufyx/issues/[0-9]+$")),
    ("GET", re.compile(r"^/repos/prufyx/prufyx/issues/[0-9]+/comments\?per_page=100&page=[1-5]$")),
    ("POST", re.compile(r"^/repos/prufyx/prufyx/issues/[0-9]+/comments$")),
    ("PATCH", re.compile(r"^/repos/prufyx/prufyx/issues/comments/[0-9]+$")),
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    return urllib.request.build_opener(NoRedirect())


def _read_bounded(resp, limit):
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise OSError("response too large")
    return data


def fetch_feed():
    """Return the feed bytes, or None when there is no feed yet (404). Fixed https URL, no redirect, bounded."""
    assert FEED_URL.startswith("https://")
    req = urllib.request.Request(FEED_URL, headers={"Accept": "application/json", "User-Agent": "prufyx-intake-status"})
    try:
        with _opener().open(req, timeout=20) as resp:
            if resp.status != 200:
                raise OSError("feed status")
            return _read_bounded(resp, MAX_FEED_BYTES)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise OSError("feed http %d" % e.code)


class Api:
    def __init__(self, token):
        if not token:
            raise OSError("no token")
        self.token = token

    def request(self, method, path, body=None):
        if not any(m == method and rx.fullmatch(path) for m, rx in _ALLOWED):
            raise PermissionError("request outside the allow-list")
        data = None
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "prufyx-intake-status"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
        try:
            with _opener().open(req, timeout=30) as resp:
                raw = _read_bounded(resp, MAX_API_BYTES)
                return resp.status, json.loads(raw.decode("utf-8")) if raw else None
        except urllib.error.HTTPError as e:
            return e.code, None


# --- per issue ----------------------------------------------------------------------------------------------------------------

def check_issue(api, item):
    """Return None when the live issue is the one the entry names, else a closed reason code. Only ids and flags are read."""
    st, obj = api.request("GET", "/repos/%s/issues/%d" % (REPO, item["issueNumber"]))
    if st != 200 or not isinstance(obj, dict):
        return "issue-unreadable"
    user = obj.get("user")
    if "pull_request" in obj:
        return "is-pull-request"
    if obj.get("number") != item["issueNumber"] or not _is_int(obj.get("id")) or obj.get("id") != item["issueId"]:
        return "issue-id-mismatch"
    if not isinstance(user, dict) or not _is_int(user.get("id")) or user.get("id") != item["authorId"] or user.get("type") != "User":
        return "author-id-mismatch"
    if obj.get("state") != "open" or obj.get("locked") is not False:
        return "not-open"
    labels = obj.get("labels")
    if not isinstance(labels, list) or not any(isinstance(l, dict) and l.get("name") == LABEL for l in labels):
        return "no-intake-label"
    return None


def own_comments(api, number):
    """Comments of the thread that carry the marker AND were written by the Actions bot (by name and numeric id)."""
    mine, mk = [], marker(number)
    for page in range(1, MAX_COMMENT_PAGES + 1):
        st, obj = api.request("GET", "/repos/%s/issues/%d/comments?per_page=100&page=%d" % (REPO, number, page))
        if st != 200 or not isinstance(obj, list):
            raise OSError("comments unreadable")
        for c in obj:
            u = c.get("user") if isinstance(c, dict) else None
            if (isinstance(u, dict) and u.get("login") == BOT_LOGIN and u.get("id") == BOT_ID and u.get("type") == "Bot"
                    and isinstance(c.get("body"), str) and c["body"].startswith(mk) and _is_int(c.get("id"))):
                mine.append((c["id"], c["body"]))
        if len(obj) < 100:
            return sorted(mine)
    raise OSError("too many comments")


def process(items, api, generated, clock, max_writes=MAX_WRITES):
    res = {"created": 0, "edited": 0, "same": 0, "skipped": 0, "errors": 0}
    writes = 0
    for index, it in enumerate(items):
        n = it["issueNumber"]
        try:
            why = check_issue(api, it)
            if why:
                log("warning", "skip", issue=n, why=why)
                res["skipped"] += 1
                continue
            body = comment_body(it)
            mine = own_comments(api, n)
            if mine and mine[0][1] == body:
                res["same"] += 1
                continue
            if writes >= max_writes:
                log("notice", "write-cap", issue=n)
                res["skipped"] += 1
                continue
            check_freshness(generated, clock())
            writes += 1
            if mine:
                st, _ = api.request("PATCH", "/repos/%s/issues/comments/%d" % (REPO, mine[0][0]), {"body": body})
                ok, key = st == 200, "edited"
            else:
                st, _ = api.request("POST", "/repos/%s/issues/%d/comments" % (REPO, n), {"body": body})
                ok, key = st == 201, "created"
            if ok:
                res[key] += 1
            else:
                log("error", "write-failed", issue=n, http=st)
                res["errors"] += 1
        except FeedStale as e:
            log("warning", "feed-stale", age=int(e.args[0]))
            res["skipped"] += len(items) - index
            break
        except (OSError, PermissionError, FeedError) as e:
            log("error", "api-error", issue=n, kind=type(e).__name__)
            res["errors"] += 1
    return res


def main(env=None, fetch=fetch_feed, api_factory=Api, clock=None):
    env = os.environ if env is None else env
    if env.get("GITHUB_REPOSITORY") != REPO:
        log("error", "wrong-repository")
        return 1
    clock = utc_now if clock is None else clock
    try:
        raw = fetch()
    except OSError as e:
        log("error", "feed-unreachable", kind=type(e).__name__)
        return 1
    if raw is None:
        log("notice", "no-feed-yet")
        return 0
    try:
        items = validate_feed(raw, clock())
    except FeedStale as e:
        log("warning", "feed-stale", age=int(e.args[0]))
        return 0
    except FeedError as e:
        log("error", "feed-refused", why=str(e).replace(" ", "-"))
        return 1
    try:
        api = api_factory(env.get("GH_TOKEN", ""))
    except OSError:
        log("error", "no-token")
        return 1
    generated = _parse_time(json.loads(raw)["generatedAt"])
    res = process(items, api, generated, clock)
    log("notice", "done", **res)
    return 1 if res["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
