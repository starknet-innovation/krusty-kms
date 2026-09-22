#!/usr/bin/env python3
"""Fail while a pull request still has an unresolved review thread.

GitHub's conversation-resolution ruleset is the merge-button gate. This
script is the in-repository signal: every review thread, including outdated
ones, must be resolved. Ordinary PR comments have no resolve action and are
not threads.

When ``PUBLISH_STATUS=1``, the result is a commit status on the pull request
head. A ``pull_request_target`` job is attached to the base commit, so the
status has to be posted on the head SHA or a required check stays pending.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

GRAPHQL_URL = "https://api.github.com/graphql"
API_ROOT = "https://api.github.com"
PAGE_SIZE = 100
MAX_PAGES = 50
STATUS_CONTEXT = "Review conversations"
STATUS_DESCRIPTION_LIMIT = 140
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

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


def status_for_threads(threads):
    """Return the commit-status state and a description of at most 140 characters."""
    pending = unresolved_threads(threads)
    if not pending:
        description = f"All {len(threads)} review thread(s) are resolved."
    else:
        description = (
            f"{len(pending)} unresolved review thread(s). "
            "Resolve them, then re-run Review conversations."
        )
    return ("failure" if pending else "success"), description[:STATUS_DESCRIPTION_LIMIT]


def summary_text(threads):
    pending = unresolved_threads(threads)
    if not pending:
        return f"All {len(threads)} review thread(s) are resolved.\n"
    lines = [f"{len(pending)} unresolved review thread(s).", ""]
    lines.extend(f"- {thread_location(thread)}" for thread in pending)
    lines.append("")
    lines.append(
        "Resolving a thread does not start this workflow. "
        "Push a commit, leave a review comment, or run Review conversations "
        "with the pull request number."
    )
    return "\n".join(lines) + "\n"


def _split_repository(repository):
    owner, _, name = repository.partition("/")
    if not owner or not name or "/" in name:
        raise RuntimeError(f"invalid GITHUB_REPOSITORY {repository!r}")
    return owner, name


def github_json(url, token, opener, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "krusty-review-threads",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST" if data is not None else "GET",
    )
    try:
        with opener(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise RuntimeError(f"GitHub request failed with HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"GitHub request failed: {error.reason}") from error
    if not raw:
        return {}
    return json.loads(raw.decode())


def fetch_threads(repository, number, token, opener=urllib.request.urlopen):
    owner, name = _split_repository(repository)
    threads = []
    cursor = None
    for _page in range(MAX_PAGES):
        body = github_json(
            GRAPHQL_URL,
            token,
            opener,
            {
                "query": THREADS_QUERY,
                "variables": {
                    "owner": owner,
                    "name": name,
                    "number": number,
                    "cursor": cursor,
                },
            },
        )
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


def fetch_head_sha(repository, number, token, opener):
    body = github_json(
        f"{API_ROOT}/repos/{repository}/pulls/{number}",
        token,
        opener,
    )
    sha = ((body.get("head") or {}).get("sha") or "").lower()
    if not SHA_RE.fullmatch(sha):
        raise RuntimeError(f"pull request {number} did not include a head SHA")
    return sha


def publish_status(repository, sha, token, state, description, target_url, opener):
    if not SHA_RE.fullmatch(sha):
        raise RuntimeError(f"refusing to publish a status for invalid SHA {sha!r}")
    _split_repository(repository)
    payload = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description[:STATUS_DESCRIPTION_LIMIT],
    }
    if target_url:
        payload["target_url"] = target_url
    github_json(
        f"{API_ROOT}/repos/{repository}/statuses/{sha.lower()}",
        token,
        opener,
        payload,
    )


def report(threads, stream=None):
    stream = sys.stdout if stream is None else stream
    state, description = status_for_threads(threads)
    if state == "success":
        print(description, file=stream)
        return 0

    print(
        f"::error::Pull request has {description}",
        file=stream,
    )
    for thread in unresolved_threads(threads):
        print(f"::error::{thread_location(thread)}", file=stream)
    return 1


def _write_summary(env, text):
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


def _credentials(env):
    repository = env.get("GITHUB_REPOSITORY", "")
    number = env.get("PR_NUMBER", "")
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    if not repository or not number or not token:
        raise RuntimeError(
            "review-thread check failed closed: "
            "GITHUB_REPOSITORY, PR_NUMBER, and GH_TOKEN are required"
        )
    try:
        pr_number = int(number)
    except ValueError as error:
        raise RuntimeError(f"invalid PR_NUMBER {number!r}") from error
    if pr_number <= 0:
        raise RuntimeError(f"invalid PR_NUMBER {number!r}")
    return repository, pr_number, token


def _head_sha(env, repository, number, token, opener):
    supplied = env.get("HEAD_SHA", "").strip()
    if supplied:
        if not SHA_RE.fullmatch(supplied):
            raise RuntimeError(f"invalid HEAD_SHA {supplied!r}")
        return supplied.lower()
    return fetch_head_sha(repository, number, token, opener)


def _publish(env, opener, repository, number, token, state, description):
    sha = _head_sha(env, repository, number, token, opener)
    publish_status(
        repository,
        sha,
        token,
        state,
        description,
        env.get("STATUS_TARGET_URL", ""),
        opener,
    )


def execute(env, opener=urllib.request.urlopen, stream=None, error_stream=None):
    stream = sys.stdout if stream is None else stream
    error_stream = sys.stderr if error_stream is None else error_stream
    raw = env.get("REVIEW_THREADS_JSON")
    if raw is not None:
        try:
            threads = json.loads(raw)
        except json.JSONDecodeError as error:
            print(f"::error::REVIEW_THREADS_JSON is not valid JSON: {error}", file=error_stream)
            return 1
        if not isinstance(threads, list):
            print(
                "::error::REVIEW_THREADS_JSON must be a list of review threads",
                file=error_stream,
            )
            return 1
        return report(threads, stream)

    publish = env.get("PUBLISH_STATUS") == "1"
    try:
        repository, number, token = _credentials(env)
        threads = fetch_threads(repository, number, token, opener)
    except RuntimeError as error:
        print(f"::error::{error}", file=error_stream)
        if not publish:
            return 1
        try:
            repository, number, token = _credentials(env)
            _publish(
                env,
                opener,
                repository,
                number,
                token,
                "error",
                "Review-thread query failed. See the workflow log.",
            )
        except RuntimeError as publish_error:
            print(f"::error::{publish_error}", file=error_stream)
            return 1
        return 0

    code = report(threads, stream)
    _write_summary(env, summary_text(threads))
    if not publish:
        return code
    state, description = status_for_threads(threads)
    try:
        _publish(env, opener, repository, number, token, state, description)
    except RuntimeError as error:
        print(f"::error::{error}", file=error_stream)
        return 1
    # The commit status on the head SHA is the required check. Exiting
    # non-zero here would fail the job on the base commit instead.
    return 0


def main(argv=None):
    del argv
    return execute(os.environ)


if __name__ == "__main__":
    sys.exit(main())
