"""Precision-focused unit tests for the false-positive classifiers.

These lock in the P1 detector precision work: secret references, code
expressions, placeholders, and known-test credentials must be classified as
non-secrets, while real provider-prefixed secrets must NOT be.
"""
import pytest

from credscan.enhanced.result_deduplicator import ResultDeduplicator


@pytest.fixture
def dedup():
    return ResultDeduplicator({})


class TestSecretReferenceClassifier:
    # Things that ARE references / non-literals (should be suppressed).
    @pytest.mark.parametrize("value", [
        "password: ${DB_PASS}",
        "api_key = os.environ['API_KEY']",
        "token = os.getenv('TOKEN')",
        "SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}",
        "aws_access_key_id=AWS_ACCESS_KEY_ID",
        "secret_access_key=AWS_SECRET_ACCESS_KEY",
        "value = match.group('key')",
        "match.group('token')",
        "key = config.get('token')",
    ])
    def test_references_are_classified_as_non_secret(self, dedup, value):
        assert dedup._is_secret_reference(value) is True

    # Things that are REAL secrets (must NOT be suppressed as references).
    @pytest.mark.parametrize("value", [
        'AWS_ACCESS_KEY_ID = "AKIAZ7Q2MNP4RVTW6XYL"',
        "HF_TOKEN=hf_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy",
        "OPENAI_API_KEY=sk-proj-R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy",
        "JWT_SIGNING_SECRET=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMifQ.8tat9Act5Rd",
        'github_token: "ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1"',
    ])
    def test_real_secrets_are_not_classified_as_reference(self, dedup, value):
        assert dedup._is_secret_reference(value) is False


class TestKnownTestCredentials:
    def test_loaded_from_data_file(self, dedup):
        # The AWS documentation example must be recognized as a test credential.
        assert "AKIAIOSFODNN7EXAMPLE" in dedup.known_test_credentials

    def test_nonempty(self, dedup):
        assert len(dedup.known_test_credentials) >= 8


class TestPlaceholderDetection:
    @pytest.mark.parametrize("value", [
        'SECRET_KEY = "REPLACE_WITH_YOUR_SECRET_KEY"',
        'password = "changeme"',
        'api_key = "your_api_key_here"',
        'token = "<your-token>"',
    ])
    def test_placeholders_flagged_as_test(self, dedup, value):
        info = dedup._analyze_test_credential(
            {"value": value, "variable": "", "path": "app/config.py", "description": ""}
        )
        assert info["is_test"] is True
