#!/usr/bin/env python3
"""Fail while a pull request still has an unresolved review thread.

GitHub's "Require conversation resolution before merging" setting is the
merge-button gate. This check is the in-repository equivalent: every review
thread, including outdated ones, must be resolved. Ordinary PR comments have
no resolve action and are not threads.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

GRAPHQL_URL = "https://api.github.com/graphql"
PAGE_SIZE = 100
MAX_PAGES = 50

THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: %d, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          isResolved
          isOutdated
          path
          comments(first: 1) {
            nodes { url }
          }
        }
      }
    }
  }
}
""" % PAGE_SIZE


def unresolved_threads(threads):
    """Return threads that still block merge.

    A missing ``isResolved`` flag fails closed. Outdated threads still block,
    matching GitHub's conversation-resolution rule.
    """
    return [thread for thread in threads if not thread.get("isResolved")]


def thread_location(thread):
    comments = (thread.get("comments") or {}).get("nodes") or []
    url = comments[0].get("url") if comments else None
    path = thread.get("path") or "unknown file"
    if url:
        return f"{url} ({path})"
    return path


def fetch_threads(repository, number, token, opener=urllib.request.urlopen):
    owner, _, name = repository.partition("/")
    if not owner or not name or "/" in name:
        raise RuntimeError(f"invalid GITHUB_REPOSITORY {repository!r}")

    threads = []
    cursor = None
    for _page in range(MAX_PAGES):
        payload = json.dumps(
            {
                "query": THREADS_QUERY,
                "variables": {
                    "owner": owner,
                    "name": name,
                    "number": number,
                    "cursor": cursor,
                },
            }
        ).encode()
        request = urllib.request.Request(
            GRAPHQL_URL,
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "krusty-review-threads",
            },
            method="POST",
        )
        try:
            with opener(request, timeout=30) as response:
                body = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise RuntimeError(
                f"GitHub review-thread query failed with HTTP {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"GitHub review-thread query failed: {error.reason}") from error

        if body.get("errors"):
            messages = "; ".join(
                error.get("message", "unknown error") for error in body["errors"]
            )
            raise RuntimeError(f"GitHub review-thread query failed: {messages}")

        pull_request = ((body.get("data") or {}).get("repository") or {}).get(
            "pullRequest"
        )
        if pull_request is None:
            raise RuntimeError(f"pull request {number} was not found in {repository}")

        connection = pull_request["reviewThreads"]
        threads.extend(connection["nodes"])
        page = connection["pageInfo"]
        if not page["hasNextPage"]:
            return threads
        cursor = page.get("endCursor")
        if not cursor:
            raise RuntimeError("GitHub returned another thread page without a cursor")

    raise RuntimeError(
        f"stopped after {MAX_PAGES} pages of review threads; refusing to treat the rest as resolved"
    )


def report(threads, stream=None):
    stream = sys.stdout if stream is None else stream
    pending = unresolved_threads(threads)
    if not pending:
        print(
            f"All review threads are resolved ({len(threads)} thread(s)).",
            file=stream,
        )
        return 0

    print(
        f"::error::Pull request has {len(pending)} unresolved review thread(s). "
        "Resolve every conversation before merging.",
        file=stream,
    )
    for thread in pending:
        print(f"::error::{thread_location(thread)}", file=stream)
    return 1


def main(argv=None):
    del argv
    raw = os.environ.get("REVIEW_THREADS_JSON")
    if raw is not None:
        try:
            threads = json.loads(raw)
        except json.JSONDecodeError as error:
            print(f"::error::REVIEW_THREADS_JSON is not valid JSON: {error}", file=sys.stderr)
            return 1
        if not isinstance(threads, list):
            print("::error::REVIEW_THREADS_JSON must be a list of review threads", file=sys.stderr)
            return 1
        return report(threads)

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    number = os.environ.get("PR_NUMBER", "")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not repository or not number or not token:
        print(
            "::error::review-thread check failed closed: "
            "GITHUB_REPOSITORY, PR_NUMBER, and GH_TOKEN are required",
            file=sys.stderr,
        )
        return 1
    try:
        pr_number = int(number)
    except ValueError:
        print(f"::error::invalid PR_NUMBER {number!r}", file=sys.stderr)
        return 1
    try:
        threads = fetch_threads(repository, pr_number, token)
    except RuntimeError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return report(threads)


if __name__ == "__main__":
    sys.exit(main())
