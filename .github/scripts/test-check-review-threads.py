#!/usr/bin/env python3
"""Self-check for the unresolved-review-thread gate."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "check-review-threads.py"
_spec = importlib.util.spec_from_file_location("check_review_threads", _SCRIPT)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


HEAD = "a" * 40


def thread(resolved, path="crates/kms/src/lib.rs", url="https://example.test/thread"):
    return {
        "isResolved": resolved,
        "isOutdated": False,
        "path": path,
        "comments": {"nodes": [{"url": url}]},
    }


def graphql_body(*nodes, has_next=False, cursor=None):
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                        "nodes": list(nodes),
                    }
                }
            }
        }
    }


def run_gate(env, opener):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = gate.execute(env, opener, stdout, stderr)
    return code, stdout.getvalue(), stderr.getvalue()


class RecordingOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        if timeout != 30:
            raise AssertionError(f"timeout {timeout}")
        payload = self.responses.pop(0)
        if isinstance(payload, Exception):
            raise payload
        return io.BytesIO(json.dumps(payload).encode())


class ReviewThreadGateTest(unittest.TestCase):
    def test_no_threads_passes(self):
        self.assertEqual(gate.unresolved_threads([]), [])
        self.assertEqual(gate.report([], io.StringIO()), 0)

    def test_resolved_threads_pass(self):
        threads = [thread(True), thread(True, path="README.md")]
        self.assertEqual(gate.unresolved_threads(threads), [])
        self.assertEqual(gate.report(threads, io.StringIO()), 0)

    def test_unresolved_thread_fails(self):
        pending = thread(False)
        self.assertEqual(gate.unresolved_threads([pending, thread(True)]), [pending])
        self.assertEqual(gate.report([pending], io.StringIO()), 1)

    def test_outdated_unresolved_thread_still_fails(self):
        pending = thread(False)
        pending["isOutdated"] = True
        self.assertEqual(gate.unresolved_threads([pending]), [pending])

    def test_missing_resolved_flag_fails_closed(self):
        pending = {"path": "Cargo.toml", "comments": {"nodes": []}}
        self.assertEqual(gate.unresolved_threads([pending]), [pending])
        self.assertEqual(gate.thread_location(pending), "Cargo.toml")

    def test_location_prefers_comment_url(self):
        pending = thread(False, url="https://example.test/c1")
        self.assertEqual(
            gate.thread_location(pending),
            "https://example.test/c1 (crates/kms/src/lib.rs)",
        )

    def test_fetch_follows_pages_and_stops(self):
        pages = [
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "pageInfo": {"hasNextPage": True, "endCursor": "cursor-2"},
                                "nodes": [thread(True, path="a.rs")],
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                                "nodes": [thread(False, path="b.rs")],
                            }
                        }
                    }
                }
            },
        ]

        def opener(_request, timeout):
            self.assertEqual(timeout, 30)
            payload = pages.pop(0)
            return io.BytesIO(json.dumps(payload).encode())

        threads = gate.fetch_threads("starknet-innovation/krusty-kms", 7, "token", opener)
        self.assertEqual([item["path"] for item in threads], ["a.rs", "b.rs"])
        self.assertEqual(gate.report(threads, io.StringIO()), 1)

    def test_fetch_rejects_a_stuck_page(self):
        def opener(_request, timeout):
            del timeout
            payload = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "pageInfo": {"hasNextPage": True, "endCursor": None},
                                "nodes": [],
                            }
                        }
                    }
                }
            }
            return io.BytesIO(json.dumps(payload).encode())

        with self.assertRaises(RuntimeError):
            gate.fetch_threads("starknet-innovation/krusty-kms", 7, "token", opener)

    def test_cli_fixture_exits_nonzero_when_unresolved(self):
        script = Path(__file__).resolve().parent / "check-review-threads.py"
        completed = subprocess.run(
            [sys.executable, str(script)],
            check=False,
            capture_output=True,
            text=True,
            env={
                "REVIEW_THREADS_JSON": json.dumps([thread(False)]),
                "PATH": "/usr/bin",
            },
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("unresolved review thread", completed.stdout)

    def test_status_description_stays_within_github_limit(self):
        state, description = gate.status_for_threads([thread(False)])
        self.assertEqual(state, "failure")
        self.assertLessEqual(len(description), 140)
        state, description = gate.status_for_threads([thread(True)])
        self.assertEqual(state, "success")
        self.assertLessEqual(len(description), 140)

    def test_publish_posts_failure_on_the_head_sha(self):
        opener = RecordingOpener([graphql_body(thread(False)), {}])
        code, _stdout, _stderr = run_gate(
            {
                "GITHUB_REPOSITORY": "starknet-innovation/krusty-kms",
                "PR_NUMBER": "150",
                "GH_TOKEN": "token",
                "HEAD_SHA": HEAD,
                "PUBLISH_STATUS": "1",
                "STATUS_TARGET_URL": "https://example.test/run/1",
            },
            opener,
        )
        self.assertEqual(code, 0)
        status = opener.requests[-1]
        self.assertEqual(status.method, "POST")
        self.assertTrue(status.full_url.endswith(f"/statuses/{HEAD}"))
        body = json.loads(status.data.decode())
        self.assertEqual(body["state"], "failure")
        self.assertEqual(body["context"], "Review conversations")
        self.assertEqual(body["target_url"], "https://example.test/run/1")
        self.assertLessEqual(len(body["description"]), 140)
        self.assertIn("Bearer token", status.headers["Authorization"])

    def test_publish_posts_success_when_every_thread_is_resolved(self):
        opener = RecordingOpener([graphql_body(thread(True)), {}])
        code, _stdout, _stderr = run_gate(
            {
                "GITHUB_REPOSITORY": "starknet-innovation/krusty-kms",
                "PR_NUMBER": "150",
                "GH_TOKEN": "token",
                "HEAD_SHA": HEAD.upper(),
                "PUBLISH_STATUS": "1",
            },
            opener,
        )
        self.assertEqual(code, 0)
        body = json.loads(opener.requests[-1].data.decode())
        self.assertEqual(body["state"], "success")
        self.assertNotIn("target_url", body)

    def test_dispatch_looks_up_the_head_sha(self):
        opener = RecordingOpener(
            [graphql_body(), {"head": {"sha": HEAD}}, {}]
        )
        code, _stdout, _stderr = run_gate(
            {
                "GITHUB_REPOSITORY": "starknet-innovation/krusty-kms",
                "PR_NUMBER": "9",
                "GH_TOKEN": "token",
                "PUBLISH_STATUS": "1",
            },
            opener,
        )
        self.assertEqual(code, 0)
        self.assertTrue(opener.requests[1].full_url.endswith("/pulls/9"))
        self.assertEqual(opener.requests[1].method, "GET")
        self.assertTrue(opener.requests[2].full_url.endswith(f"/statuses/{HEAD}"))

    def test_invalid_head_sha_is_not_published(self):
        opener = RecordingOpener([graphql_body(thread(False))])
        code, _stdout, stderr = run_gate(
            {
                "GITHUB_REPOSITORY": "starknet-innovation/krusty-kms",
                "PR_NUMBER": "150",
                "GH_TOKEN": "token",
                "HEAD_SHA": "not-a-sha",
                "PUBLISH_STATUS": "1",
            },
            opener,
        )
        self.assertEqual(code, 1)
        self.assertIn("invalid HEAD_SHA", stderr)
        self.assertEqual(len(opener.requests), 1)

    def test_query_failure_posts_an_error_status(self):
        opener = RecordingOpener(
            [{"errors": [{"message": "boom"}]}, {}]
        )
        code, _stdout, stderr = run_gate(
            {
                "GITHUB_REPOSITORY": "starknet-innovation/krusty-kms",
                "PR_NUMBER": "150",
                "GH_TOKEN": "token",
                "HEAD_SHA": HEAD,
                "PUBLISH_STATUS": "1",
            },
            opener,
        )
        self.assertIn("boom", stderr)
        self.assertEqual(code, 0)
        body = json.loads(opener.requests[-1].data.decode())
        self.assertEqual(body["state"], "error")
        self.assertLessEqual(len(body["description"]), 140)


if __name__ == "__main__":
    unittest.main()
