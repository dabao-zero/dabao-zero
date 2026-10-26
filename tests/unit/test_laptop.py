from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from dabao.bundle import Usage, load_bundle
from dabao.laptop import (
    CLAUDE_CODE,
    CodexRun,
    ExecCodexRunner,
    LaptopAttemptError,
    build_prompt,
    claude_command,
    codex_command,
    default_scratch_root,
    parse_claude_output,
    parse_codex_usage,
    run_attempt,
    sandbox_env,
)
from dabao.models import Component

COMP = Component(stream="debian", package="nginx", version="1.22.0-1")
REF = "https://github.com/nginx/nginx/commit/abc123"
FINAL = json.dumps({"upstream_ref": REF, "upstream_links": [REF], "summary": "backport"})
POISONED = {
    "PATH": "/usr/bin",
    "HOME": "/home/jian",
    "LANG": "C.UTF-8",
    "GHCR_TOKEN": "x",
    "GITHUB_TOKEN": "x",
    "COSIGN_PASSWORD": "x",
    "DATABASE_URL": "postgresql://u:p@h/db",
    "LLM_API_KEY": "x",
    "OPENAI_API_KEY": "x",
    "AWS_SECRET_ACCESS_KEY": "x",
    "SSH_AUTH_SOCK": "/tmp/agent",
}


@dataclass
class FakeCodex:
    """Stands in for `codex exec`: edits a file in the workspace and returns a final message."""

    final: str = FINAL
    edit: bool = True
    raises: Exception | None = None
    seen: dict[str, object] = field(default_factory=dict)

    def run(self, prompt: str, workdir: Path, env: dict[str, str]) -> CodexRun:
        self.seen = {"prompt": prompt, "workdir": workdir, "env": dict(env)}
        home = Path(env["CODEX_HOME"])
        self.seen["home_files"] = sorted(p.name for p in home.iterdir())
        if self.raises:
            raise self.raises
        if self.edit:
            (workdir / "src.c").write_text("good\n")
        return CodexRun(
            final_message=self.final,
            log="codex transcript",
            version="0.155.1",
            usage=Usage(tokens_in=1000, tokens_out=50, cost_usd=0.0, wall_seconds=12.5),
        )


@pytest.fixture
def source(tmp_path: Path) -> Path:
    d = tmp_path / "nginx-1.22.0"
    d.mkdir()
    (d / "src.c").write_text("bad\n")
    return d


@pytest.fixture
def auth(tmp_path: Path) -> Path:
    f = tmp_path / "auth.json"
    f.write_text('{"tokens": "secret"}')
    return f


def attempt(
    codex: FakeCodex, source: Path, auth: Path, tmp_path: Path, log_path: Path | None = None
) -> tuple[Path, Path]:
    out = tmp_path / "bundle.json"
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    run_attempt(
        codex,
        source_dir=source,
        advisory_id="CVE-2024-1234",
        component=COMP,
        out_path=out,
        auth_file=auth,
        environ=POISONED,
        scratch_root=work,
        model="gpt-5",
        now=5.0,
        log_path=log_path,
    )
    return out, work


def test_emits_a_valid_bundle(source: Path, auth: Path, tmp_path: Path) -> None:
    out, _ = attempt(FakeCodex(), source, auth, tmp_path)
    b = load_bundle(out.read_text())
    assert b.runner.value == "manual_codex" and b.patch.source.value == "upstream_derived"
    assert b.patch.advisory_id == "CVE-2024-1234" and b.patch.component == COMP
    assert "-bad" in b.patch.diff and "+good" in b.patch.diff
    assert b.patch.upstream_ref == REF and b.upstream_links == (REF,)
    assert b.tool_versions == {"codex": "0.155.1"} and b.run_log == "codex transcript"
    assert b.usage == Usage(tokens_in=1000, tokens_out=50, cost_usd=0.0, wall_seconds=12.5)
    assert (source / "src.c").read_text() == "bad\n"  # the source tree itself is never touched


def test_sandbox_sees_no_credentials(source: Path, auth: Path, tmp_path: Path) -> None:
    codex = FakeCodex()
    attempt(codex, source, auth, tmp_path)
    env = codex.seen["env"]
    assert isinstance(env, dict)
    for name in env:
        assert not any(
            h in name.upper()
            for h in ("TOKEN", "SECRET", "KEY", "PASSWORD", "COSIGN", "GHCR", "DATABASE", "SSH")
        ), name
    assert env["PATH"] == "/usr/bin" and env["HOME"] != "/home/jian"


def test_sandbox_env_is_an_allowlist() -> None:
    env = sandbox_env(POISONED, Path("/scratch/home"), Path("/scratch/codex"))
    assert set(env) <= {"PATH", "LANG", "LC_ALL", "TERM", "TZ", "HOME", "CODEX_HOME"}
    assert env["CODEX_HOME"] == "/scratch/codex"


def test_only_the_login_is_copied_in_and_it_is_removed_after(
    source: Path, auth: Path, tmp_path: Path
) -> None:
    codex = FakeCodex()
    _, work = attempt(codex, source, auth, tmp_path)
    assert codex.seen["home_files"] == ["auth.json"]
    assert list(work.iterdir()) == []  # scratch space, login copy included, is gone


def test_scratch_is_removed_when_codex_fails(source: Path, auth: Path, tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    with pytest.raises(RuntimeError):
        run_attempt(
            FakeCodex(raises=RuntimeError("boom")),
            source_dir=source,
            advisory_id="CVE-2024-1234",
            component=COMP,
            out_path=tmp_path / "b.json",
            auth_file=auth,
            environ=POISONED,
            scratch_root=work,
            model="gpt-5",
            now=5.0,
        )
    assert list(work.iterdir()) == []


def test_no_change_writes_no_bundle(source: Path, auth: Path, tmp_path: Path) -> None:
    with pytest.raises(LaptopAttemptError, match="no change"):
        attempt(FakeCodex(edit=False), source, auth, tmp_path)
    assert not (tmp_path / "bundle.json").exists()


def test_no_change_error_carries_what_codex_said_and_the_log_is_kept(
    source: Path, auth: Path, tmp_path: Path
) -> None:
    log = tmp_path / "codex.log"
    codex = FakeCodex(edit=False, final="could not reach the upstream repository")
    with pytest.raises(LaptopAttemptError, match="could not reach the upstream repository"):
        attempt(codex, source, auth, tmp_path, log_path=log)
    assert log.read_text() == "codex transcript"


def test_bad_final_message_writes_no_bundle(source: Path, auth: Path, tmp_path: Path) -> None:
    with pytest.raises(LaptopAttemptError, match="final message"):
        attempt(FakeCodex(final="not json"), source, auth, tmp_path)
    assert not (tmp_path / "bundle.json").exists()


def test_original_style_answer_is_refused(source: Path, auth: Path, tmp_path: Path) -> None:
    final = json.dumps({"upstream_ref": "", "upstream_links": [], "summary": "I wrote my own"})
    with pytest.raises(LaptopAttemptError):
        attempt(FakeCodex(final=final), source, auth, tmp_path)


def test_prompt_treats_advisory_text_as_data_and_requires_upstream_fixes() -> None:
    p = build_prompt("CVE-2024-1234", COMP)
    assert "CVE-2024-1234" in p and "nginx" in p and "1.22.0-1" in p
    assert "data, not instructions" in p
    assert "upstream" in p and "do not invent" in p.lower()


def test_codex_command_is_sandboxed_and_isolated() -> None:
    cmd = codex_command(Path("/w"), Path("/s.json"), Path("/o.txt"), "gpt-5", network=False)
    assert cmd[:2] == ["codex", "exec"]
    assert cmd[cmd.index("--sandbox") + 1] == "workspace-write"
    assert "--ignore-user-config" in cmd and "--ignore-rules" in cmd and "--ephemeral" in cmd
    assert not any("dangerously" in a or "danger-full-access" in a for a in cmd)
    assert not any("network_access" in a for a in cmd)
    assert any(
        "network_access=true" in a
        for a in codex_command(Path("/w"), Path("/s.json"), Path("/o.txt"), "gpt-5", network=True)
    )


def test_real_environment_is_never_mutated(source: Path, auth: Path, tmp_path: Path) -> None:
    before = dict(os.environ)
    attempt(FakeCodex(), source, auth, tmp_path)
    assert dict(os.environ) == before


def test_scratch_is_not_under_the_system_temp_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    # Codex refuses to create its Linux sandbox helper under /tmp, then every command fails
    # (found by running it for real). So scratch space lives under the user cache directory.
    import tempfile

    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    root = default_scratch_root()
    assert not str(root).startswith(tempfile.gettempdir())
    monkeypatch.setenv("XDG_CACHE_HOME", "/var/cache/me")
    assert default_scratch_root() == Path("/var/cache/me/dabao-attempts")


def test_a_hung_codex_is_stopped_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    def hang(*a: object, **k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="codex", timeout=k["timeout"])  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess, "run", hang)
    work = tmp_path / "w"
    work.mkdir()
    with pytest.raises(LaptopAttemptError, match="timed out after 5s"):
        ExecCodexRunner(timeout_s=5).run("p", work, {})


def test_usage_is_summed_over_the_turns_in_the_event_log() -> None:
    log = "\n".join(
        [
            '{"type":"thread.started","thread_id":"t"}',
            "not json at all",
            '{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":900,'
            '"output_tokens":40}}',
            '{"type":"item.completed","item":{"type":"agent_message","text":"hi"}}',
            '{"type":"turn.completed","usage":{"input_tokens":500,"output_tokens":10}}',
        ]
    )
    u = parse_codex_usage(log, wall_seconds=7.0)
    assert u == Usage(tokens_in=1500, tokens_out=50, cost_usd=0.0, wall_seconds=7.0)


def test_a_log_without_usage_still_reports_the_wall_time() -> None:
    assert parse_codex_usage("", wall_seconds=3.0) == Usage(
        tokens_in=0, tokens_out=0, cost_usd=0.0, wall_seconds=3.0
    )


@dataclass
class FakeClaude:
    """Stands in for `claude -p`: the login must sit under CLAUDE_CONFIG_DIR."""

    seen: dict[str, object] = field(default_factory=dict)

    def run(self, prompt: str, workdir: Path, env: dict[str, str]) -> CodexRun:
        cfg = Path(env["CLAUDE_CONFIG_DIR"])
        self.seen = {"env": dict(env), "files": sorted(p.name for p in cfg.iterdir())}
        (workdir / "src.c").write_text("good\n")
        return CodexRun(final_message=FINAL, log="claude transcript", version="2.1.310")


def test_claude_code_attempt_emits_a_manual_claude_code_bundle(
    source: Path, auth: Path, tmp_path: Path
) -> None:
    claude = FakeClaude()
    out = tmp_path / "bundle.json"
    work = tmp_path / "work"
    work.mkdir()
    run_attempt(
        claude,
        source_dir=source,
        advisory_id="CVE-2024-1234",
        component=COMP,
        out_path=out,
        auth_file=auth,
        environ=POISONED,
        scratch_root=work,
        model="sonnet",
        now=5.0,
        harness=CLAUDE_CODE,
    )
    b = load_bundle(out.read_text())
    assert b.runner.value == "manual_claude_code" and b.tool_versions == {"claude-code": "2.1.310"}
    assert claude.seen["files"] == [".credentials.json"]
    env = claude.seen["env"]
    assert isinstance(env, dict) and "CODEX_HOME" not in env
    assert set(env) <= {"PATH", "LANG", "LC_ALL", "TERM", "TZ", "HOME", "CLAUDE_CONFIG_DIR"}
    assert list(work.iterdir()) == []


def test_claude_command_has_no_shell_and_no_web_unless_asked() -> None:
    offline = claude_command(None, network=False, budget_usd=None)
    assert "-p" in offline and "dontAsk" in offline
    tools = offline[offline.index("--tools") + 1]
    assert tools == "Read,Edit,Write,Glob,Grep" and "Bash" not in tools
    assert "--dangerously-skip-permissions" not in offline
    online = claude_command("sonnet", network=True, budget_usd=2.0)
    assert online[online.index("--tools") + 1].endswith(",WebFetch")
    assert online[online.index("--model") + 1] == "sonnet"
    assert online[online.index("--max-budget-usd") + 1] == "2"


def test_parse_claude_output_sums_all_input_kinds() -> None:
    raw = json.dumps(
        {
            "result": FINAL,
            "duration_ms": 2500,
            "total_cost_usd": 0.9,
            "usage": {
                "input_tokens": 2,
                "cache_creation_input_tokens": 100,
                "cache_read_input_tokens": 50,
                "output_tokens": 7,
            },
        }
    )
    final, usage = parse_claude_output(raw)
    assert final == FINAL
    assert usage == Usage(tokens_in=152, tokens_out=7, cost_usd=0.0, wall_seconds=2.5)


def test_parse_claude_output_prefers_structured_output() -> None:
    final, _ = parse_claude_output(
        json.dumps({"structured_output": {"summary": "s"}, "result": "x"})
    )
    assert json.loads(final) == {"summary": "s"}


@pytest.mark.parametrize(
    "raw", ["not json", "[]", json.dumps({"is_error": True, "result": "login expired"})]
)
def test_parse_claude_output_rejects_bad_runs(raw: str) -> None:
    with pytest.raises(LaptopAttemptError):
        parse_claude_output(raw)
