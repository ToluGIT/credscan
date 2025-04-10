"""
Git hooks integration for CredScan.
"""
from .pre_commit import PreCommitScanner, install_hook

__all__ = ['PreCommitScanner', 'install_hook']
