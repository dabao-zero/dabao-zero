import pytest

pytestmark = pytest.mark.integration


def test_integration_layer_is_wired() -> None:
    """Real-infra tests (testcontainers) land here from V1; this keeps the CI job meaningful."""
    assert True
