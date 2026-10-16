from dabao import fakes
from dabao.models import Advisory, Component, Finding, Patch, PatchSource
from dabao.seams import (
    AdvisorySource,
    AgentRunner,
    Clock,
    DistroAdapter,
    Registry,
    Scanner,
    Signer,
)

ADV = Advisory(id="CVE-2024-0001")
COMP = Component(stream="debian", package="nginx", version="1.22.0-1")
PATCH = Patch(
    advisory_id=ADV.id,
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref="abc123",
    diff="--- a\n+++ b\n",
)


def test_fakes_satisfy_seams() -> None:
    # Static assignment: mypy fails if a fake drifts from its Protocol.
    _a: AgentRunner = fakes.FakeAgentRunner()
    _d: DistroAdapter = fakes.FakeDistroAdapter()
    _s: Scanner = fakes.FakeScanner()
    _r: Registry = fakes.FakeRegistry()
    _g: Signer = fakes.FakeSigner()
    _v: AdvisorySource = fakes.FakeAdvisorySource()
    _c: Clock = fakes.FakeClock()


def test_agent_replay_returns_recorded_patch_or_none() -> None:
    runner = fakes.FakeAgentRunner({(ADV.id, "nginx"): PATCH})
    assert runner.propose_patch(ADV, COMP) == PATCH
    assert runner.propose_patch(Advisory(id="CVE-2024-9999"), COMP) is None


def test_build_is_reproducible_and_patch_changes_digest() -> None:
    adapter = fakes.FakeDistroAdapter()
    assert adapter.build_image(COMP, PATCH) == adapter.build_image(COMP, PATCH)
    assert adapter.build_image(COMP, PATCH) != adapter.build_image(COMP, None)


def test_scan_before_and_after() -> None:
    adapter = fakes.FakeDistroAdapter()
    before, after = adapter.build_image(COMP, None), adapter.build_image(COMP, PATCH)
    scanner = fakes.FakeScanner({before: [Finding(advisory_id=ADV.id, package="nginx")]})
    assert scanner.scan(before) != []
    assert scanner.scan(after) == []


def test_fake_clock_is_driven_explicitly() -> None:
    clock = fakes.FakeClock()
    clock.advance(5)
    assert clock.now() == 5
