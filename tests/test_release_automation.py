"""Tests for release automation script.

These tests verify version bumping, PR creation, and PR number extraction.
"""

import pytest
from unittest.mock import patch
import subprocess
import sys
import os

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from release import ReleaseAutomation, ReleaseError  # noqa: E402


class TestBumpVersion:
    """Tests for the bump_version method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=True)

    def test_bump_patch(self):
        assert self.automation.bump_version("1.5.1", "patch") == "1.5.2"

    def test_bump_minor(self):
        assert self.automation.bump_version("1.5.1", "minor") == "1.6.0"

    def test_bump_major(self):
        assert self.automation.bump_version("1.5.1", "major") == "2.0.0"

    def test_invalid_version_raises_error(self):
        with pytest.raises(ReleaseError):
            self.automation.bump_version("not-a-version", "patch")

    def test_invalid_bump_type_raises_error(self):
        with pytest.raises(ReleaseError):
            self.automation.bump_version("1.5.1", "gigantic")


class TestExtractPrNumber:
    """Tests for the _extract_pr_number method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=True)

    def test_extracts_number_from_pr_url(self):
        output = "https://github.com/softagram/sgraph/pull/456"
        assert self.automation._extract_pr_number(output) == 456

    def test_returns_none_for_empty_output(self):
        assert self.automation._extract_pr_number("") is None

    def test_returns_none_when_no_pr_url_present(self):
        assert self.automation._extract_pr_number("no url here") is None


class TestPushAndCreatePr:
    """Tests for push_and_create_pr method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=False, skip_confirmation=True)
        self.automation.repo_root = "/fake/repo"

    @patch('release.subprocess.run')
    @patch.object(ReleaseAutomation, 'run_command')
    def test_returns_pr_number_from_gh_output(self, mock_run_cmd, mock_subprocess):
        """Test that PR number is extracted and returned when creating PR.

        The gh pr create command outputs the PR URL, which contains the PR number.
        """
        # gh CLI is available
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        # Simulate: first call is git push, second is gh pr create
        mock_run_cmd.side_effect = [
            # git push
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            # gh pr create - returns PR URL
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="https://github.com/softagram/sgraph/pull/456",
                stderr=""
            ),
        ]

        result = self.automation.push_and_create_pr("releasing-1.0.0", "1.0.0")

        # Should return PR number extracted from URL
        assert result == 456

    @patch('release.subprocess.run')
    @patch.object(ReleaseAutomation, 'run_command')
    def test_returns_none_when_gh_not_available(self, mock_run_cmd, mock_subprocess):
        """Test that None is returned when gh CLI is not available."""
        # gh CLI is NOT available
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )

        # git push succeeds
        mock_run_cmd.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        result = self.automation.push_and_create_pr("releasing-1.0.0", "1.0.0")

        # Should return None when gh is not available
        assert result is None
