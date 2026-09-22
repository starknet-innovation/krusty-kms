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


def thread(resolved, path="crates/kms/src/lib.rs", url="https://example.test/thread"):
    return {
        "isResolved": resolved,
        "isOutdated": False,
        "path": path,
        "comments": {"nodes": [{"url": url}]},
    }


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


if __name__ == "__main__":
    unittest.main()
