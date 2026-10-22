from __future__ import annotations

import json
from typing import Any

import pytest

from dabao.bundle import BUNDLE_VERSION, BundleError, CandidateBundle, load_bundle


def good() -> dict[str, Any]:
    return {
        "schema_version": BUNDLE_VERSION,
        "runner": "manual_codex",
        "patch": {
            "advisory_id": "CVE-2024-1234",
            "component": {"stream": "debian", "package": "nginx", "version": "1.22.0-1"},
            "source": "upstream_derived",
            "upstream_ref": "https://github.com/nginx/nginx/commit/abc123",
            "diff": "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-bad\n+good\n",
        },
        "upstream_links": ["https://github.com/nginx/nginx/commit/abc123"],
        "run_log": "codex run transcript",
        "tool_versions": {"codex": "0.1.0"},
        "model": "gpt-5",
        "created_at": 1.0,
    }


def test_valid_bundle_loads_and_round_trips() -> None:
    b = load_bundle(json.dumps(good()))
    assert b.patch.advisory_id == "CVE-2024-1234"
    assert load_bundle(b.model_dump_json()) == b


@pytest.mark.parametrize("field", ["run_log", "patch", "upstream_links", "model", "tool_versions"])
def test_missing_field_is_rejected(field: str) -> None:
    doc = good()
    del doc[field]
    with pytest.raises(BundleError, match=field):
        load_bundle(json.dumps(doc))


def test_original_source_is_rejected() -> None:
    doc = good()
    doc["patch"]["source"] = "original"
    with pytest.raises(BundleError, match="upstream_derived"):
        load_bundle(json.dumps(doc))


def test_empty_diff_is_rejected() -> None:
    doc = good()
    doc["patch"]["diff"] = "  \n"
    with pytest.raises(BundleError, match="diff"):
        load_bundle(json.dumps(doc))


def test_upstream_ref_must_be_among_links() -> None:
    doc = good()
    doc["upstream_links"] = ["https://example.com/other"]
    with pytest.raises(BundleError, match="upstream_ref"):
        load_bundle(json.dumps(doc))


def test_empty_links_are_rejected() -> None:
    doc = good()
    doc["upstream_links"] = []
    with pytest.raises(BundleError):
        load_bundle(json.dumps(doc))


def test_unknown_runner_is_rejected() -> None:
    doc = good()
    doc["runner"] = "someone_else"
    with pytest.raises(BundleError, match="runner"):
        load_bundle(json.dumps(doc))


def test_other_schema_version_is_rejected() -> None:
    doc = good()
    doc["schema_version"] = BUNDLE_VERSION + 1
    with pytest.raises(BundleError, match="schema_version"):
        load_bundle(json.dumps(doc))


def test_unknown_field_is_rejected() -> None:
    doc = good()
    doc["approved_by"] = "me"
    with pytest.raises(BundleError, match="approved_by"):
        load_bundle(json.dumps(doc))


def test_not_json_is_rejected() -> None:
    with pytest.raises(BundleError, match="JSON"):
        load_bundle("{nope")


def test_bundle_is_frozen() -> None:
    b = load_bundle(json.dumps(good()))
    assert isinstance(b, CandidateBundle)
    with pytest.raises(ValueError):
        b.model = "other"
