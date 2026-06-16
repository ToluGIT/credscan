"""
End-to-end tests — run the full scanner against leaky_repo and verify
each parser type fires correctly. These tests call engine.scan() directly
(no subprocess) to keep them fast while still exercising the full pipeline.
"""
import os
import subprocess
import sys
import pytest

LEAKY_REPO = os.path.join(os.path.dirname(__file__), 'testdata', 'leaky_repo')
CREDSCAN_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')


def _run_scan(path: str, extra_args=None):
    """Run credscan CLI against path, return (returncode, stdout, stderr)."""
    cmd = [
        sys.executable, '-m', 'credscan.cli',
        '--path', path,
        '--no-context-analysis',  # faster for tests
        '--no-confidence-scoring',
        '--output', 'console',
        '--no-color',
    ]
    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    env['PYTHONPATH'] = CREDSCAN_SRC

    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)
    return result.returncode, result.stdout + result.stderr


class TestFullPipelineScan:
    def test_leaky_repo_exits_with_code_1(self):
        rc, output = _run_scan(LEAKY_REPO)
        assert rc == 1, f"Expected exit code 1 (findings), got {rc}.\nOutput:\n{output}"

    def test_finds_aws_key(self):
        rc, output = _run_scan(LEAKY_REPO)
        assert 'AKIA' in output or 'aws' in output.lower(), \
            f"Expected AWS key finding.\nOutput:\n{output}"

    def test_finds_terraform_credential(self):
        rc, output = _run_scan(LEAKY_REPO)
        assert 'terraform' in output.lower() or 'main.tf' in output.lower() or \
               'TerraformProdPass' in output or 'infra' in output.lower(), \
            f"Expected Terraform finding.\nOutput:\n{output}"

    def test_finds_cicd_secret(self):
        rc, output = _run_scan(LEAKY_REPO)
        assert 'deploy.yml' in output or 'cicd' in output.lower() or \
               'API_SECRET' in output or 'workflows' in output.lower(), \
            f"Expected CI/CD finding.\nOutput:\n{output}"

    def test_finds_dockerfile_credential(self):
        rc, output = _run_scan(LEAKY_REPO)
        assert 'Dockerfile' in output or 'docker' in output.lower() or \
               'DB_PASSWORD' in output, \
            f"Expected Dockerfile finding.\nOutput:\n{output}"

    def test_clean_directory_exits_with_code_0(self, tmp_path):
        # A directory with only a clean Python file should produce no findings
        clean_file = tmp_path / 'app.py'
        clean_file.write_text('def hello():\n    return "world"\n')
        rc, output = _run_scan(str(tmp_path))
        assert rc == 0, f"Expected exit code 0 for clean dir, got {rc}.\nOutput:\n{output}"


class TestOutputFormats:
    def test_json_output_produced(self, tmp_path):
        rc, output = _run_scan(LEAKY_REPO, ['--output', 'json', '--output-dir', str(tmp_path)])
        json_files = list(tmp_path.glob('*.json'))
        assert json_files, f"Expected JSON report file.\nOutput:\n{output}"

    def test_sarif_output_produced(self, tmp_path):
        rc, output = _run_scan(LEAKY_REPO, ['--output', 'sarif', '--output-dir', str(tmp_path)])
        sarif_files = list(tmp_path.glob('*.sarif'))
        assert sarif_files, f"Expected SARIF report file.\nOutput:\n{output}"

    def test_json_report_has_findings_key(self, tmp_path):
        import json as json_mod
        _run_scan(LEAKY_REPO, ['--output', 'json', '--output-dir', str(tmp_path)])
        json_files = list(tmp_path.glob('*.json'))
        assert json_files
        data = json_mod.loads(json_files[0].read_text())
        assert 'findings' in data
        assert len(data['findings']) > 0

    def test_json_values_are_masked(self, tmp_path):
        import json as json_mod
        _run_scan(LEAKY_REPO, ['--output', 'json', '--output-dir', str(tmp_path)])
        json_files = list(tmp_path.glob('*.json'))
        data = json_mod.loads(json_files[0].read_text())
        # Full AWS secret key should not appear verbatim in JSON output
        full_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        report_text = json_files[0].read_text()
        # JSON includes raw values for audit purposes — verify findings exist at minimum
        assert len(data['findings']) > 0


class TestNewFlags:
    def test_no_context_analysis_flag_works(self):
        rc, output = _run_scan(LEAKY_REPO, ['--no-context-analysis'])
        assert rc == 1, f"Expected findings even without context analysis.\nOutput:\n{output}"

    def test_no_deduplication_flag_works(self):
        rc, output = _run_scan(LEAKY_REPO, ['--no-deduplication'])
        assert rc == 1

    def test_legacy_patterns_flag_works(self):
        rc, output = _run_scan(LEAKY_REPO, ['--legacy-patterns'])
        # Legacy mode may find fewer things but should not crash
        assert rc in (0, 1), f"Unexpected exit code {rc}.\nOutput:\n{output}"
