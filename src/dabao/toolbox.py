"""The agent's real ToolBox (ADR-0005): look up advisories and fixes, read the source, dry-run.

Egress is enforced here, at the one place the agent can reach the network: only https, only the
listed hosts, only port 443, every redirect hop checked again. This is the application-level half
of "network limited to the source mirror and package proxy"; a network namespace around the whole
sandbox is the other half (E8). Everything returned is untrusted data: the agent runner wraps it.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from dabao.agent import ToolError

# Where an advisory can be read and where upstream fixes live. Hosts only; paths are not restricted.
DEFAULT_HOSTS = frozenset(
    {
        "api.osv.dev",
        "security-tracker.debian.org",
        "github.com",
        "gitlab.com",
        "git.savannah.gnu.org",
        "cgit.git.savannah.gnu.org",
        "git.kernel.org",
        "sources.debian.org",
        "salsa.debian.org",
    }
)

ADVISORY_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|DSA-\d+-\d+|DLA-\d+-\d+)$")
GITHUB_COMMIT = re.compile(r"^https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]+$")
MAX_REDIRECTS = 3

Apply = Callable[[list[str], bytes], "subprocess.CompletedProcess[bytes]"]


@dataclass(frozen=True)
class EgressPolicy:
    hosts: frozenset[str] = DEFAULT_HOSTS

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ToolError(f"only https is allowed: {url}")
        if parts.username is not None or parts.password is not None:
            raise ToolError(f"credentials in a URL are not allowed: {url}")
        host = (parts.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ToolError(f"IP addresses are not allowed: {host}")
        if parts.port not in (None, 443):
            raise ToolError(f"only port 443 is allowed: {url}")
        if host not in self.hosts:
            raise ToolError(f"host not on the allow-list: {host or url}")


def _apply(args: list[str], diff: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, input=diff, capture_output=True, timeout=60, check=False)


class SandboxToolBox:
    def __init__(
        self,
        source_dir: Path,
        policy: EgressPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        runner: Apply = _apply,
        max_bytes: int = 200_000,
        timeout_s: float = 30.0,
    ) -> None:
        self._src = source_dir.resolve()
        self._policy = policy or EgressPolicy()
        # No automatic redirects: each hop is checked against the policy by hand.
        self._http = httpx.Client(transport=transport, timeout=timeout_s, follow_redirects=False)
        self._runner, self._max = runner, max_bytes

    def _get(self, url: str) -> str:
        for _ in range(MAX_REDIRECTS + 1):
            self._policy.check(url)
            try:
                resp = self._http.get(url)
            except httpx.HTTPError as exc:
                raise ToolError(f"request failed: {type(exc).__name__}") from exc
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                url = urljoin(url, resp.headers["location"])
                continue
            if resp.status_code != 200:
                raise ToolError(f"{url} answered {resp.status_code}")
            return self._clip(resp.text)
        raise ToolError("too many redirects")

    def _clip(self, text: str) -> str:
        if len(text) <= self._max:
            return text
        return text[: self._max] + f"\n[truncated: {len(text) - self._max} more characters]"

    def fetch_advisory(self, advisory_id: str) -> str:
        if not ADVISORY_ID.match(advisory_id):
            raise ToolError(f"not a valid advisory id: {advisory_id!r}")
        return self._get(f"https://api.osv.dev/v1/vulns/{advisory_id}")

    def fetch_upstream_fix(self, ref: str) -> str:
        url = ref + ".patch" if GITHUB_COMMIT.match(ref) else ref
        self._policy.check(url)
        return self._get(url)

    def fetch_source_file(self, path: str) -> str:
        target = (self._src / path).resolve()
        if Path(path).is_absolute() or not target.is_relative_to(self._src):
            raise ToolError(f"path is outside the source tree: {path}")
        if not target.is_file():
            raise ToolError(f"no such file: {path}")
        return self._clip(target.read_text(errors="replace"))

    def try_apply(self, diff: str) -> str:
        cmd = ["patch", "-p1", "--dry-run", "--no-backup-if-mismatch", "-d", str(self._src)]
        res = self._runner(cmd, diff.encode())
        out = (res.stdout + res.stderr).decode(errors="replace").strip()
        if res.returncode == 0:
            return "the patch applies cleanly\n" + self._clip(out)
        return "the patch does NOT apply:\n" + self._clip(out)
