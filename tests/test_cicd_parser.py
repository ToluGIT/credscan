"""Tests for CI/CD parser — GitHub Actions, GitLab CI, Jenkins credential detection."""
import os
import pytest
from credscan.parsers.cicd_parser import CICDParser

TESTDATA = os.path.join(os.path.dirname(__file__), 'testdata', 'cicd')


@pytest.fixture
def parser():
    return CICDParser({})


class TestCICDParserCanParse:
    def test_accepts_github_actions_workflow(self, parser):
        assert parser.can_parse('.github/workflows/deploy.yml')

    def test_accepts_gitlab_ci(self, parser):
        assert parser.can_parse('.gitlab-ci.yml')

    def test_accepts_circleci_config(self, parser):
        assert parser.can_parse('.circleci/config.yml')

    def test_accepts_jenkinsfile(self, parser):
        assert parser.can_parse('Jenkinsfile')

    def test_rejects_regular_yaml(self, parser):
        assert not parser.can_parse('config.yaml')

    def test_rejects_python_file(self, parser):
        assert not parser.can_parse('app.py')


class TestHardcodedEnvDetection:
    def test_finds_hardcoded_api_token(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky_workflow.yml'))
        assert result['entries'], "Expected findings in leaky workflow"
        assert any('API_TOKEN' in e['key'] or 'hardcoded' in e['rule_name'].lower()
                   for e in result['entries'])

    def test_finds_hardcoded_database_password(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky_workflow.yml'))
        assert any('PASSWORD' in e['key'] or 'password' in e['rule_name'].lower()
                   for e in result['entries'])

    def test_safe_workflow_has_no_hardcoded_secrets(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'safe_workflow.yml'))
        # All values use ${{ secrets.X }} — no hardcoded values
        hardcoded = [
            e for e in result.get('entries', [])
            if e['severity'] in ('critical', 'high')
            and 'echo' not in e['rule_name'].lower()
        ]
        assert len(hardcoded) == 0, \
            f"Expected no hardcoded secrets in safe workflow, got: {hardcoded}"


class TestEchoLeakDetection:
    def test_finds_echo_secret(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky_workflow.yml'))
        echo_findings = [e for e in result.get('entries', [])
                         if 'echo' in e['rule_name'].lower() or 'Log' in e['rule_name']]
        assert len(echo_findings) > 0, "Expected echo leak finding"


class TestPlatformDetection:
    def test_detects_github_actions_platform(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky_workflow.yml'))
        assert result['file_type'] == 'cicd_github_actions'
