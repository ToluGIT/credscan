"""Tests for IaC parser — Terraform and CloudFormation credential detection."""
import os
import pytest
from credscan.parsers.iac_parser import IaCParser

TESTDATA = os.path.join(os.path.dirname(__file__), 'testdata', 'iac')


@pytest.fixture
def parser():
    return IaCParser({})


class TestIaCParserCanParse:
    def test_accepts_tf(self, parser):
        assert parser.can_parse('main.tf')

    def test_accepts_tfvars(self, parser):
        assert parser.can_parse('terraform.tfvars')

    def test_accepts_cloudformation_yaml(self, parser):
        assert parser.can_parse('cloudformation-stack.yaml')

    def test_accepts_template_json(self, parser):
        assert parser.can_parse('stack.template')

    def test_rejects_plain_python(self, parser):
        assert not parser.can_parse('app.py')

    def test_rejects_plain_yaml(self, parser):
        # generic YAML with no CF hint in filename is not parsed
        assert not parser.can_parse('config.yaml')


class TestTerraformDetection:
    def test_finds_hardcoded_access_key(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky.tf'))
        assert result, "Parser returned empty result"
        keys = [e['key'] for e in result['entries']]
        assert any('Access Key' in k or 'access_key' in k.lower() for k in keys), \
            f"Expected access key finding, got: {keys}"

    def test_finds_hardcoded_secret_key(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky.tf'))
        assert any('Secret' in e['key'] or 'secret_key' in e['key'].lower()
                   for e in result['entries'])

    def test_finds_hardcoded_password(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky.tf'))
        assert any('password' in e['value'].lower() or 'Token' in e['rule_name']
                   for e in result['entries']), \
            f"Expected password finding, got: {result['entries']}"

    def test_clean_file_produces_no_credential_findings(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'clean.tf'))
        # clean.tf uses var references — should produce no credential findings
        cred_findings = [
            e for e in result.get('entries', [])
            if e['severity'] in ('critical', 'high')
        ]
        assert len(cred_findings) == 0, \
            f"Expected no high/critical findings in clean file, got: {cred_findings}"

    def test_file_type_is_terraform(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'leaky.tf'))
        assert result['file_type'] == 'terraform'


class TestCloudFormationDetection:
    def test_finds_hardcoded_password(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'template.yaml'))
        assert result, "Parser returned empty result for CloudFormation template"
        assert len(result['entries']) > 0, "Expected at least one finding"
        assert any('password' in e['rule_name'].lower() or 'CloudFormation' in e['rule_name']
                   for e in result['entries'])

    def test_file_type_is_cloudformation(self, parser):
        result = parser.parse(os.path.join(TESTDATA, 'template.yaml'))
        assert result['file_type'] == 'cloudformation'
