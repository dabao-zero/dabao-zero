from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx
import pytest

from dabao.agent import LLMAgentRunner, ToolError
from dabao.llm import ChatClient, LLMConfig
from dabao.models import Advisory, Component
from dabao.toolbox import EgressPolicy, SandboxToolBox

COMMIT = "https://github.com/tukaani-project/xz/commit/abc123"


class Net:
    """A fake network: records every request, answers from a table, refuses anything else."""

    def __init__(self, routes: dict[str, httpx.Response] | None = None) -> None:
        self.routes = routes or {}
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        return self.routes.get(url, httpx.Response(404, text="not found"))


def box(
    tmp_path: Path,
    net: Net,
    runner: object = None,
    max_bytes: int = 200_000,
) -> SandboxToolBox:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return SandboxToolBox(
        source_dir=src,
        policy=EgressPolicy(),
        transport=httpx.MockTransport(net),
        runner=runner or (lambda a, d: subprocess.CompletedProcess(a, 0, b"", b"")),  # type: ignore[arg-type]
        max_bytes=max_bytes,
    )


# --- egress: nothing but the allow-listed sources is reachable ---------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/fix.patch",  # not on the list
        "http://github.com/o/r/commit/abc",  # not https
        "https://github.com.evil.example/o/r/commit/abc",  # suffix trick
        "https://github.com@evil.example/o/r/commit/abc",  # userinfo trick
        "https://github.com:8443/o/r/commit/abc",  # other port
        "https://127.0.0.1/x",  # loopback
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://localhost/x",
        "file:///etc/passwd",
        "ftp://github.com/x",
    ],
)
def test_a_url_off_the_allow_list_is_refused_and_no_request_is_made(
    tmp_path: Path, url: str
) -> None:
    net = Net()
    with pytest.raises(ToolError):
        box(tmp_path, net).fetch_upstream_fix(url)
    assert net.requests == []


def test_a_redirect_to_a_host_off_the_list_is_refused(tmp_path: Path) -> None:
    net = Net(
        {COMMIT + ".patch": httpx.Response(302, headers={"location": "https://evil.example/x"})}
    )
    with pytest.raises(ToolError, match="not on the allow-list"):
        box(tmp_path, net).fetch_upstream_fix(COMMIT)
    assert net.requests == [COMMIT + ".patch"]  # the second hop was never made


def test_a_redirect_between_allowed_hosts_is_followed(tmp_path: Path) -> None:
    final = "https://gitlab.com/o/r/-/commit/abc.patch"
    net = Net(
        {
            COMMIT + ".patch": httpx.Response(301, headers={"location": final}),
            final: httpx.Response(200, text="diff --git a/x b/x"),
        }
    )
    assert "diff --git" in box(tmp_path, net).fetch_upstream_fix(COMMIT)


def test_a_redirect_loop_is_cut_off(tmp_path: Path) -> None:
    url = COMMIT + ".patch"
    net = Net({url: httpx.Response(302, headers={"location": url})})
    with pytest.raises(ToolError, match="too many redirects"):
        box(tmp_path, net).fetch_upstream_fix(COMMIT)


def test_github_commit_urls_are_fetched_as_patches(tmp_path: Path) -> None:
    net = Net({COMMIT + ".patch": httpx.Response(200, text="PATCH")})
    assert box(tmp_path, net).fetch_upstream_fix(COMMIT) == "PATCH"


def test_big_responses_are_truncated_with_a_marker(tmp_path: Path) -> None:
    net = Net({COMMIT + ".patch": httpx.Response(200, text="x" * 500)})
    out = box(tmp_path, net, max_bytes=100).fetch_upstream_fix(COMMIT)
    assert out.startswith("x" * 100) and "truncated" in out and len(out) < 200


def test_a_failed_fetch_is_a_tool_error_not_an_empty_success(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="404"):
        box(tmp_path, Net()).fetch_upstream_fix(COMMIT)


# --- advisories ---------------------------------------------------------------------------------


def test_advisory_ids_are_validated_before_they_become_part_of_a_url(tmp_path: Path) -> None:
    net = Net()
    for bad in ["../../etc/passwd", "CVE-2024-1234/../x", "CVE-2024-1234?x=1", ""]:
        with pytest.raises(ToolError, match="advisory id"):
            box(tmp_path, net).fetch_advisory(bad)
    assert net.requests == []


def test_advisory_text_comes_from_osv(tmp_path: Path) -> None:
    url = "https://api.osv.dev/v1/vulns/CVE-2022-48303"
    net = Net({url: httpx.Response(200, json={"id": "CVE-2022-48303", "summary": "tar OOB"})})
    assert "tar OOB" in box(tmp_path, net).fetch_advisory("CVE-2022-48303")


# --- source files -------------------------------------------------------------------------------


def test_source_files_are_read_from_the_source_tree(tmp_path: Path) -> None:
    b = box(tmp_path, Net())
    (tmp_path / "src" / "src").mkdir()
    (tmp_path / "src" / "src" / "list.c").write_text("int x;\n")
    assert b.fetch_source_file("src/list.c") == "int x;\n"


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "a/../../secret", "src/../../x"])
def test_paths_outside_the_source_tree_are_refused(tmp_path: Path, path: str) -> None:
    (tmp_path / "secret").write_text("s3cret")
    with pytest.raises(ToolError, match="outside the source tree"):
        box(tmp_path, Net()).fetch_source_file(path)


def test_a_symlink_out_of_the_tree_is_refused(tmp_path: Path) -> None:
    b = box(tmp_path, Net())
    (tmp_path / "secret").write_text("s3cret")
    (tmp_path / "src" / "link").symlink_to(tmp_path / "secret")
    with pytest.raises(ToolError, match="outside the source tree"):
        b.fetch_source_file("link")


def test_a_missing_source_file_is_a_tool_error(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="no such file"):
        box(tmp_path, Net()).fetch_source_file("nope.c")


# --- try_apply ----------------------------------------------------------------------------------


def test_try_apply_is_a_dry_run_in_the_source_tree(tmp_path: Path) -> None:
    seen: list[tuple[list[str], bytes]] = []

    def runner(args: list[str], diff: bytes) -> subprocess.CompletedProcess[bytes]:
        seen.append((args, diff))
        return subprocess.CompletedProcess(args, 0, b"checking file src/list.c\n", b"")

    out = box(tmp_path, Net(), runner).try_apply("--- a/x\n+++ b/x\n")
    assert "applies cleanly" in out
    args, diff = seen[0]
    assert "--dry-run" in args and "-p1" in args and str(tmp_path / "src") in args
    assert diff == b"--- a/x\n+++ b/x\n"


def test_try_apply_reports_why_a_patch_does_not_apply(tmp_path: Path) -> None:
    def runner(args: list[str], diff: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 1, b"Hunk #1 FAILED at 881.\n", b"")

    assert "Hunk #1 FAILED" in box(tmp_path, Net(), runner).try_apply("diff")


# --- wired into the agent -----------------------------------------------------------------------


def test_the_agent_cannot_fetch_or_submit_from_a_host_off_the_list(tmp_path: Path) -> None:
    evil = "https://evil.example/fix.patch"
    replies = iter(
        [
            {
                "id": "1",
                "function": {"name": "fetch_upstream_fix", "arguments": json.dumps({"ref": evil})},
            },
            {
                "id": "2",
                "function": {
                    "name": "submit_patch",
                    "arguments": json.dumps({"upstream_ref": evil, "diff": "--- a/x\n+++ b/x\n"}),
                },
            },
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        call = next(replies, None)
        msg = {"role": "assistant", "content": None, "tool_calls": [call] if call else []}
        return httpx.Response(200, json={"choices": [{"message": msg}], "usage": {}})

    client = ChatClient(
        LLMConfig(api_key="k", model="m", base_url="https://llm.example/v1"),
        transport=httpx.MockTransport(handler),
    )
    net = Net()
    result = LLMAgentRunner(client, box(tmp_path, net)).propose_patch(
        Advisory(id="CVE-2022-48303"), Component(stream="debian", package="tar", version="1")
    )
    assert result.patch is None
    assert net.requests == []
