# SPDX-License-Identifier: AGPL-3.0-only
"""Script test of scripts/intake-status.py: a fixture feed and a mocked API. No network, no token.

Run: python3 -I scripts/intake_status_test.py   (the Go test cli/internal/maintainer/intakestatusworkflow runs it in CI)
"""
import copy
import datetime
import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("intake_status", os.path.join(HERE, "intake-status.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

NO_NETWORK = mock.patch.object(S, "_opener", side_effect=AssertionError("network disabled in tests"))


def setUpModule():
    NO_NETWORK.start()


def tearDownModule():
    NO_NETWORK.stop()


NOW = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
GEN = "2026-11-20T11:50:00Z"
HOSTILE = "PWNED @everyone <script>alert(1)</script> $(touch /tmp/x) https://evil.example/x"


def item(n, iid, aid, state="received", reason="", project=""):
    return {"issueNumber": n, "issueId": iid, "authorId": aid, "project": project, "state": state, "reason": reason,
            "updatedAt": "2026-11-20T11:00:00Z"}


def feed(items, **over):
    d = {"schema": "prufyx.io/intake-status", "version": 1, "generatedAt": GEN, "items": items}
    d.update(over)
    return d


def raw(d):
    return json.dumps(d).encode()


class FakeApi:
    """Mocked GitHub API. Issue and comment objects carry hostile title/body text on purpose: it must never be written back."""

    def __init__(self):
        self.issues = {}
        self.comments = {}
        self.calls = []
        self.next_id = 9000

    def add_issue(self, n, iid, aid, labels=("maintainer-intake",), state="open", pr=False, utype="User", locked=False):
        o = {"number": n, "id": iid, "state": state, "locked": locked, "title": HOSTILE, "body": HOSTILE,
             "user": {"id": aid, "login": "someone", "type": utype}, "labels": [{"name": l} for l in labels]}
        if pr:
            o["pull_request"] = {"url": "x"}
        self.issues[n] = o
        self.comments.setdefault(n, [])

    def add_comment(self, n, body, login=S.BOT_LOGIN, uid=S.BOT_ID, utype="Bot"):
        self.next_id += 1
        self.comments[n].append({"id": self.next_id, "body": body, "user": {"login": login, "id": uid, "type": utype}})
        return self.next_id

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if not any(m == method and rx.fullmatch(path) for m, rx in S._ALLOWED):
            raise PermissionError("outside allow-list")
        parts = path.split("?")[0].split("/")
        if method == "GET" and parts[-2] == "issues":
            n = int(parts[-1])
            return (200, copy.deepcopy(self.issues[n])) if n in self.issues else (404, None)
        if method == "GET" and parts[-1] == "comments":
            n = int(parts[-2])
            page = int(path.rsplit("page=", 1)[1])
            return 200, copy.deepcopy(self.comments.get(n, [])[(page - 1) * 100:page * 100])
        if method == "POST":
            n = int(parts[-2])
            self.add_comment(n, body["body"])
            return 201, {"id": self.next_id}
        if method == "PATCH":
            cid = int(parts[-1])
            for lst in self.comments.values():
                for c in lst:
                    if c["id"] == cid:
                        c["body"] = body["body"]
                        return 200, {"id": cid}
            return 404, None
        raise AssertionError(method + path)

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


def run_main(fetch_bytes, api, token="t"):
    return S.main(env={"GITHUB_REPOSITORY": "prufyx/prufyx", "GH_TOKEN": token}, fetch=lambda: fetch_bytes,
                  api_factory=lambda tok: api, clock=lambda: NOW)


class ValidateFeed(unittest.TestCase):
    def ok(self, d):
        return S.validate_feed(raw(d), NOW)

    def bad(self, d_or_bytes, exc=S.FeedError):
        data = d_or_bytes if isinstance(d_or_bytes, (bytes, bytearray)) else raw(d_or_bytes)
        with self.assertRaises(exc):
            S.validate_feed(data, NOW)

    def test_valid(self):
        got = self.ok(feed([item(3, 30, 300), item(5, 50, 500, "refused", "repo-is-fork"), item(7, 70, 700, "accepted", "", "sample")]))
        self.assertEqual([i["issueNumber"] for i in got], [3, 5, 7])
        self.assertEqual(self.ok(feed([])), [])

    def test_admission_reasons(self):
        for state, reason in (("refused", "no-invite"), ("refused", "proof-ambiguous"),
                              ("parked", "maintainer-changed"), ("parked", "proof-expired")):
            got = self.ok(feed([item(3, 30, 300, state, reason)]))
            self.assertEqual(got[0]["reason"], reason)
            self.assertIn("Reason code: " + reason, S.comment_body(got[0]))
        self.bad(feed([item(3, 30, 300, "held", "no-invite")]))        # a reason of another state
        self.bad(feed([item(3, 30, 300, "refused", "proof-expired")]))
        self.bad(feed([item(3, 30, 300, "parked", "no-invite")]))
        self.bad(feed([item(3, 30, 300, "refused", "proof-unknown")]))  # unknown stays refused

    def test_bad_schema(self):
        base = [item(3, 30, 300)]
        self.bad(feed(base, schema="prufyx.io/other"))
        self.bad(feed(base, version=2))
        self.bad(feed(base, version=True))
        self.bad(feed(base, version=1.0 + 0.5))
        self.bad(feed(base, extra="x"))
        d = feed(base)
        del d["generatedAt"]
        self.bad(d)
        self.bad(feed(base, generatedAt="yesterday"))
        self.bad(feed(base, generatedAt="2026-11-20T11:50:00+00:00"))
        self.bad(feed(None))
        self.bad(feed({"a": 1}))
        self.bad(b"")
        self.bad(b"not json")
        self.bad(b"[]")
        self.bad(b'{"schema":"prufyx.io/intake-status","version":1,"version":1,"generatedAt":"%s","items":[]}' % GEN.encode())
        self.bad(b'{"schema":"prufyx.io/intake-status","version":NaN,"generatedAt":"%s","items":[]}' % GEN.encode())
        self.bad(raw(feed([])) + b"{}")
        self.bad(b"\xff\xfe")
        self.bad(b"x" * (S.MAX_FEED_BYTES + 1))

    def test_bad_items(self):
        def mut(**kw):
            i = item(3, 30, 300)
            i.update(kw)
            return feed([i])
        self.bad(mut(state="approved"))
        self.bad(mut(state="Received"))
        self.bad(mut(reason="other"))                      # a reason on a state without reasons
        self.bad(mut(state="refused", reason=""))          # a state with reasons needs one
        self.bad(mut(state="refused", reason="tag-prefix"))  # a reason of another state
        self.bad(mut(state="held", reason="because"))
        self.bad(mut(issueNumber=0))
        self.bad(mut(issueNumber="3"))
        self.bad(mut(issueNumber=True))
        self.bad(mut(issueId=0))
        self.bad(mut(issueId=2 ** 53 + 1))
        self.bad(mut(authorId=-1))
        self.bad(mut(authorId=300.0))
        self.bad(mut(project="Sample"))
        self.bad(mut(project="a b"))
        self.bad(mut(project="@everyone"))
        self.bad(mut(project=None))
        self.bad(mut(updatedAt="2026-11-20"))
        self.bad(mut(updatedAt="2026-13-40T00:00:00Z"))
        i = item(3, 30, 300)
        i["title"] = "text"
        self.bad(feed([i]))
        i = item(3, 30, 300)
        del i["authorId"]
        self.bad(feed([i]))
        self.bad(feed([item(5, 50, 500), item(3, 30, 300)]))   # not ordered
        self.bad(feed([item(3, 30, 300), item(3, 31, 301)]))   # duplicate number
        self.bad(feed([item(3, 30, 300), item(4, 30, 301)]))   # duplicate issue id
        self.bad(feed([item(n, 100 + n, 5) for n in range(1, S.MAX_ITEMS + 2)]))

    def test_stale_and_future(self):
        self.bad(feed([], generatedAt="2026-11-20T10:00:00Z"), S.FeedStale)
        self.bad(feed([], generatedAt="2026-11-20T13:00:00Z"), S.FeedStale)
        self.assertEqual(self.ok(feed([], generatedAt="2026-11-20T11:00:00Z")), [])
        self.assertEqual(self.ok(feed([], generatedAt="2026-11-20T12:05:00Z")), [])
        self.bad(feed([], generatedAt="2026-11-20T10:59:59Z"), S.FeedStale)
        self.bad(feed([], generatedAt="2026-11-20T12:05:01Z"), S.FeedStale)

    def test_terminal_newlines_are_refused(self):
        for project in ("sample\n", "sample\r\n"):
            with self.subTest(project=repr(project)):
                self.bad(feed([item(3, 30, 300, project=project)]))
        self.bad(feed([], generatedAt=GEN + "\n"))
        it = item(3, 30, 300)
        it["updatedAt"] += "\n"
        self.bad(feed([it]))

    def test_comment_text_is_closed(self):
        for state in S.STATES:
            reason = S.REASONS[state][0] if state in S.REASONS else ""
            body = S.comment_body(item(4, 40, 400, state, reason, "sample"))
            self.assertTrue(body.startswith("<!-- prufyx-intake-status:v1 #4 -->"))
            self.assertNotIn("@", body)
            self.assertLessEqual(len(body), S.MAX_BODY)
            self.assertEqual(body.count("<"), 1)
            self.assertNotIn("endorse", body.lower())
            self.assertIn("not a compatibility claim", body)


class Process(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.api.add_issue(3, 30, 300)
        self.items = [item(3, 30, 300, "accepted", "", "sample")]

    def test_project_terminal_newline_writes_nothing(self):
        self.items[0]["project"] = "sample\n"
        self.assertEqual(run_main(raw(feed(self.items)), self.api), 1)
        self.assertEqual(self.api.calls, [])

    def run_expiring(self, expire_at, editing=False):
        current = [NOW]
        expired = NOW + datetime.timedelta(hours=1)
        data = raw(feed(self.items))
        request = self.api.request
        if editing:
            self.api.add_comment(3, S.marker(3) + "\nprevious status")

        def fetch():
            if expire_at == "fetch":
                current[0] = expired
            return data

        def advancing_request(method, path, body=None):
            result = request(method, path, body)
            if ((expire_at == "comments" and method == "GET" and "/comments?" in path)
                    or (expire_at == "write" and method in ("POST", "PATCH"))):
                current[0] = expired
            return result

        with mock.patch.object(S.datetime, "datetime", wraps=datetime.datetime) as dt, \
                mock.patch.object(self.api, "request", side_effect=advancing_request), \
                mock.patch("builtins.print") as printed:
            dt.now.side_effect = lambda tz: current[0]
            code = S.main(env={"GITHUB_REPOSITORY": S.REPO, "GH_TOKEN": "t"}, fetch=fetch,
                          api_factory=lambda token: self.api)
        self.assertEqual(code, 0)
        logs = "\n".join(c.args[0] for c in printed.call_args_list)
        self.assertIn("feed-stale", logs)
        return logs

    def test_expiry_during_fetch_writes_nothing(self):
        self.run_expiring("fetch")
        self.assertEqual(self.api.calls, [])

    def test_expiry_during_comment_read_stops_create_and_edit(self):
        for editing in (False, True):
            with self.subTest(editing=editing):
                self.api = FakeApi()
                self.api.add_issue(3, 30, 300)
                logs = self.run_expiring("comments", editing=editing)
                self.assertEqual(self.api.writes(), [])
                self.assertIn("created=0 edited=0 errors=0 same=0 skipped=1", logs)

    def test_expiry_between_writes_preserves_partial_counts(self):
        for editing in (False, True):
            with self.subTest(editing=editing):
                self.api = FakeApi()
                self.api.add_issue(3, 30, 300)
                self.api.add_issue(4, 40, 400)
                self.api.add_issue(5, 50, 500)
                self.items = [item(3, 30, 300), item(4, 40, 400), item(5, 50, 500)]
                logs = self.run_expiring("write", editing=editing)
                self.assertEqual([c[0] for c in self.api.writes()], ["PATCH" if editing else "POST"])
                expected = "created=0 edited=1" if editing else "created=1 edited=0"
                self.assertIn(expected + " errors=0 same=0 skipped=2", logs)


    def test_creates_one_comment(self):
        self.assertEqual(run_main(raw(feed(self.items)), self.api), 0)
        w = self.api.writes()
        self.assertEqual([c[0] for c in w], ["POST"])
        self.assertEqual(w[0][1], "/repos/prufyx/prufyx/issues/3/comments")
        self.assertTrue(w[0][2]["body"].startswith(S.marker(3)))
        self.assertIn("Catalogue name: sample", w[0][2]["body"])

    def test_duplicate_run_writes_nothing(self):
        self.assertEqual(run_main(raw(feed(self.items)), self.api), 0)
        self.api.calls.clear()
        self.assertEqual(run_main(raw(feed(self.items)), self.api), 0)
        self.assertEqual(self.api.writes(), [])
        self.assertEqual(len(self.api.comments[3]), 1)

    def test_state_change_edits_the_same_comment(self):
        run_main(raw(feed(self.items)), self.api)
        cid = self.api.comments[3][0]["id"]
        self.api.calls.clear()
        run_main(raw(feed([item(3, 30, 300, "onboarded", "", "sample")])), self.api)
        w = self.api.writes()
        self.assertEqual([(c[0], c[1]) for c in w], [("PATCH", "/repos/prufyx/prufyx/issues/comments/%d" % cid)])
        self.assertEqual(len(self.api.comments[3]), 1)
        self.assertIn("onboarded", self.api.comments[3][0]["body"])

    def test_bad_schema_writes_nothing(self):
        for data in (raw(feed(self.items, version=2)), raw(feed(self.items, extra=1)), b"garbage"):
            self.assertEqual(run_main(data, self.api), 1)
        self.assertEqual(self.api.calls, [])

    def test_unknown_state_refuses_the_whole_document(self):
        bad = [item(3, 30, 300, "approved"), item(4, 40, 400)]
        self.api.add_issue(4, 40, 400)
        self.assertEqual(run_main(raw(feed(bad)), self.api), 1)
        self.assertEqual(self.api.calls, [])

    def test_id_mismatch_writes_nothing(self):
        for it in (item(3, 31, 300), item(3, 30, 301)):
            self.api.calls.clear()
            self.assertEqual(run_main(raw(feed([it])), self.api), 0)
            self.assertEqual(self.api.writes(), [])
        # the number names another issue than the one the ids belong to
        self.api.add_issue(8, 88, 800)
        self.api.calls.clear()
        run_main(raw(feed([item(8, 30, 300)])), self.api)
        self.assertEqual(self.api.writes(), [])

    def test_wrong_kind_of_target_is_skipped(self):
        cases = {"pull request": dict(pr=True), "closed": dict(state="closed"), "no label": dict(labels=("bug",)),
                 "bot author": dict(utype="Bot"), "locked": dict(locked=True)}
        for name, kw in cases.items():
            api = FakeApi()
            api.add_issue(3, 30, 300, **kw)
            self.assertEqual(run_main(raw(feed(self.items)), api), 0, name)
            self.assertEqual(api.writes(), [], name)
        api = FakeApi()  # the issue does not exist
        self.assertEqual(run_main(raw(feed(self.items)), api), 0)
        self.assertEqual(api.writes(), [])

    def test_issue_absent_from_the_feed_is_never_touched(self):
        self.api.add_issue(4, 40, 400)
        self.api.add_issue(5, 50, 500)
        run_main(raw(feed(self.items)), self.api)
        touched = {c[1].split("/")[5] for c in self.api.calls if "/issues/" in c[1] and "comments/" not in c[1]}
        self.assertEqual(touched, {"3"})
        self.assertEqual(self.api.comments[4], [])
        self.assertEqual(self.api.comments[5], [])

    def test_hostile_issue_text_never_reaches_a_write(self):
        self.api.add_comment(3, "hostile comment " + HOSTILE, login="attacker", uid=1, utype="User")
        run_main(raw(feed(self.items)), self.api)
        for c in self.api.writes():
            body = c[2]["body"]
            for frag in ("PWNED", "everyone", "script", "$(", "evil", "attacker", "hostile"):
                self.assertNotIn(frag, body)

    def test_marker_comment_of_another_author_is_not_adopted_or_edited(self):
        theirs = self.api.add_comment(3, S.marker(3) + "\nfake status", login="attacker", uid=1, utype="User")
        wrong_id = self.api.add_comment(3, S.marker(3) + "\nfake status", login=S.BOT_LOGIN, uid=12345, utype="Bot")
        run_main(raw(feed(self.items)), self.api)
        w = self.api.writes()
        self.assertEqual([c[0] for c in w], ["POST"])
        by_id = {c["id"]: c["body"] for c in self.api.comments[3]}
        self.assertEqual(by_id[theirs], S.marker(3) + "\nfake status")
        self.assertEqual(by_id[wrong_id], S.marker(3) + "\nfake status")

    def test_never_changes_labels_closes_or_edits_the_issue(self):
        self.api.add_issue(4, 40, 400)
        run_main(raw(feed(self.items + [item(4, 40, 400)])), self.api)
        for method, path, _ in self.api.calls:
            self.assertNotIn("/labels", path)
            if method != "GET":
                self.assertTrue(path.endswith("/comments") or "/issues/comments/" in path, path)
        with self.assertRaises(PermissionError):
            S.Api("t").request("POST", "/repos/prufyx/prufyx/issues/3/labels", {"labels": ["x"]})
        with self.assertRaises(PermissionError):
            S.Api("t").request("PATCH", "/repos/prufyx/prufyx/issues/3", {"state": "closed"})
        with self.assertRaises(PermissionError):
            S.Api("t").request("GET", "/repos/other/repo/issues/3")
        with self.assertRaises(PermissionError):
            S.Api("t").request("DELETE", "/repos/prufyx/prufyx/issues/comments/1")

    def test_write_cap(self):
        items = []
        for n in range(1, 31):
            self.api.add_issue(n, 100 + n, 200 + n)
            items.append(item(n, 100 + n, 200 + n))
        run_main(raw(feed(items)), self.api)
        self.assertEqual(len(self.api.writes()), S.MAX_WRITES)

    def test_stale_or_missing_feed(self):
        self.assertEqual(run_main(raw(feed(self.items, generatedAt="2026-11-20T09:00:00Z")), self.api), 0)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(run_main(None, self.api), 0)  # no feed yet
        self.assertEqual(self.api.calls, [])

    def test_unreachable_feed_and_missing_token_fail(self):
        def boom():
            raise OSError("down")
        self.assertEqual(S.main(env={"GITHUB_REPOSITORY": "prufyx/prufyx", "GH_TOKEN": "t"}, fetch=boom, api_factory=lambda t: self.api, clock=lambda: NOW), 1)
        self.assertEqual(S.main(env={"GITHUB_REPOSITORY": "prufyx/prufyx"}, fetch=lambda: raw(feed(self.items)), clock=lambda: NOW), 1)

    def test_runs_only_in_the_main_repository(self):
        self.assertEqual(S.main(env={"GITHUB_REPOSITORY": "someone/fork", "GH_TOKEN": "t"}, fetch=lambda: raw(feed(self.items)),
                                api_factory=lambda t: self.api, clock=lambda: NOW), 1)
        self.assertEqual(self.api.calls, [])

    def test_failed_write_is_an_error(self):
        class Failing(FakeApi):
            def request(self, method, path, body=None):
                if method == "POST":
                    return 500, None
                return super().request(method, path, body)
        api = Failing()
        api.add_issue(3, 30, 300)
        self.assertEqual(run_main(raw(feed(self.items)), api), 1)

    def test_issue_read_status_errors_and_absence(self):
        for status in (401, 403, 429, 500, 503, 404):
            with self.subTest(status=status), \
                    mock.patch.object(self.api, "request", return_value=(status, None)) as request, \
                    mock.patch("builtins.print") as printed:
                self.assertEqual(run_main(raw(feed(self.items)), self.api), 0 if status == 404 else 1)
                request.assert_called_once_with("GET", "/repos/prufyx/prufyx/issues/3")
                logs = "\n".join(c.args[0] for c in printed.call_args_list)
                counts = "errors=0 same=0 skipped=1" if status == 404 else "errors=1 same=0 skipped=0"
                self.assertIn("created=0 edited=0 " + counts, logs)

    def test_issue_read_operational_failure_is_an_error(self):
        with mock.patch.object(self.api, "request", side_effect=OSError(HOSTILE)) as request, \
                mock.patch("builtins.print") as printed:
            self.assertEqual(run_main(raw(feed(self.items)), self.api), 1)
            request.assert_called_once_with("GET", "/repos/prufyx/prufyx/issues/3")
            logs = "\n".join(c.args[0] for c in printed.call_args_list)
            self.assertIn("created=0 edited=0 errors=1 same=0 skipped=0", logs)
            self.assertNotIn(HOSTILE, logs)

    def test_malformed_issue_response_is_an_error(self):
        responses = [[], {}, {"number": 3}, {"id": 30}]
        for key in ("number", "id"):
            for value in (None, True, "3", 3.0):
                obj = copy.deepcopy(self.api.issues[3])
                obj[key] = value
                responses.append(obj)
        for index, obj in enumerate(responses):
            with self.subTest(index=index), mock.patch.object(self.api, "request", return_value=(200, obj)) as request, \
                    mock.patch("builtins.print") as printed:
                self.assertEqual(run_main(raw(feed(self.items)), self.api), 1)
                request.assert_called_once_with("GET", "/repos/prufyx/prufyx/issues/3")
                logs = "\n".join(c.args[0] for c in printed.call_args_list)
                self.assertIn("created=0 edited=0 errors=1 same=0 skipped=0", logs)

    def test_different_issue_identity_is_skipped(self):
        for key, value in (("number", 4), ("id", 31)):
            obj = copy.deepcopy(self.api.issues[3])
            obj[key] = value
            with self.subTest(key=key), mock.patch.object(self.api, "request", return_value=(200, obj)) as request, \
                    mock.patch("builtins.print") as printed:
                self.assertEqual(run_main(raw(feed(self.items)), self.api), 0)
                request.assert_called_once_with("GET", "/repos/prufyx/prufyx/issues/3")
                logs = "\n".join(c.args[0] for c in printed.call_args_list)
                self.assertIn("created=0 edited=0 errors=0 same=0 skipped=1", logs)


class Transport(unittest.TestCase):
    def test_api_paths_with_terminal_newlines_are_refused(self):
        for method, path in (("GET", "/repos/prufyx/prufyx/issues/3"),
                             ("GET", "/repos/prufyx/prufyx/issues/3/comments?per_page=100&page=1"),
                             ("POST", "/repos/prufyx/prufyx/issues/3/comments"),
                             ("PATCH", "/repos/prufyx/prufyx/issues/comments/9001")):
            with self.subTest(method=method, path=path), \
                    mock.patch.object(S, "_opener", side_effect=AssertionError("network disabled in tests")) as opener:
                with self.assertRaises(PermissionError):
                    S.Api("t").request(method, path + "\n")
                opener.assert_not_called()

    def test_feed_url_is_fixed_https(self):
        self.assertTrue(S.FEED_URL.startswith("https://"))
        self.assertNotIn("FEED_URL", os.environ.get("X", ""))

    def test_redirects_are_not_followed(self):
        self.assertIsNone(S.NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/"))

    def test_the_script_imports_only_the_standard_library(self):
        with open(os.path.join(HERE, "intake-status.py"), encoding="utf-8") as fh:
            src = fh.read()
        mods = {l.split()[1].split(".")[0] for l in src.splitlines() if l.startswith(("import ", "from "))}
        self.assertEqual(mods, {"datetime", "json", "os", "re", "sys", "urllib"})
        for banned in ("subprocess", "os.system", "eval(", "exec(", "__import__", "shell=True", "/labels", "event.issue", "GITHUB_EVENT"):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main(verbosity=1)
