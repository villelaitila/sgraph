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

    @patch('release.shutil.which', return_value='/usr/bin/gh')
    @patch.object(ReleaseAutomation, 'run_command')
    def test_returns_pr_number_from_gh_output(self, mock_run_cmd, mock_which):
        """Test that PR number is extracted and returned when creating PR.

        The gh pr create command outputs the PR URL, which contains the PR number.
        """

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

    @patch('release.shutil.which', return_value=None)
    @patch.object(ReleaseAutomation, 'run_command')
    def test_returns_none_when_gh_not_available(self, mock_run_cmd, mock_which):
        """Test that None is returned when gh CLI is not available."""
        # git push succeeds; gh pr create must never be reached
        mock_run_cmd.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        result = self.automation.push_and_create_pr("releasing-1.0.0", "1.0.0")

        # Should return None when gh is not available
        assert result is None

        # Only the git push ran - gh pr create was never attempted
        assert mock_run_cmd.call_count == 1
        assert mock_run_cmd.call_args[0][0][0] == "git"


class TestModuleAvailable:
    """Tests for the _module_available helper.

    The helper must probe the interpreter that will actually run the module
    (sys.executable), not whatever happens to be first on PATH.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=True)

    def test_returns_true_for_importable_module(self):
        assert self.automation._module_available("sys") is True

    def test_returns_false_for_missing_module(self):
        assert self.automation._module_available("no_such_module_xyz") is False

    @patch('release.subprocess.run')
    def test_probes_sys_executable_not_path(self, mock_subprocess):
        """The probe must run through sys.executable, never a bare PATH lookup."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        self.automation._module_available("twine")

        cmd = mock_subprocess.call_args[0][0]
        assert cmd[0] == sys.executable
        assert cmd[1] == "-c"
        assert "import twine" in cmd[2]
        assert "which" not in cmd


class TestValidateReleaseTooling:
    """Tests for validate_release_tooling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=False, skip_confirmation=True)

    @patch('release.shutil.which', return_value="/usr/bin/gh")
    @patch.object(ReleaseAutomation, '_module_available', return_value=True)
    def test_passes_when_all_modules_present(self, mock_available, mock_which):
        self.automation.validate_release_tooling()

        probed = {call[0][0] for call in mock_available.call_args_list}
        assert probed == {"setuptools", "wheel", "twine"}

    @patch('release.shutil.which', return_value="/usr/bin/gh")
    @patch.object(ReleaseAutomation, '_module_available')
    def test_raises_when_a_module_is_missing(self, mock_available, mock_which):
        """A missing build/upload module must abort, not merely warn."""
        mock_available.side_effect = lambda m: m != "setuptools"

        with pytest.raises(ReleaseError) as excinfo:
            self.automation.validate_release_tooling()

        assert "setuptools" in str(excinfo.value)

    @patch('release.shutil.which', return_value="/usr/bin/gh")
    @patch.object(ReleaseAutomation, '_module_available')
    def test_error_names_every_missing_module(self, mock_available, mock_which):
        mock_available.side_effect = lambda m: m == "wheel"

        with pytest.raises(ReleaseError) as excinfo:
            self.automation.validate_release_tooling()

        message = str(excinfo.value)
        assert "setuptools" in message
        assert "twine" in message

    @patch('release.shutil.which', return_value=None)
    @patch.object(ReleaseAutomation, '_module_available', return_value=True)
    def test_missing_gh_only_warns(self, mock_available, mock_which):
        """gh is recoverable by hand, so it must not abort the release."""
        self.automation.validate_release_tooling()


class TestCompleteReleaseOrdering:
    """Tests for the ordering guarantee inside complete_release.

    Pushing a tag is public and irreversible, so tooling must be validated
    before it happens - otherwise a missing build tool strands a published
    tag with no artifacts behind it.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.automation = ReleaseAutomation(dry_run=False, skip_confirmation=True)

    def test_tooling_is_validated_before_the_tag_is_pushed(self):
        calls = []

        with patch.object(ReleaseAutomation, 'validate_release_tooling',
                          side_effect=lambda: calls.append("validate")), \
             patch.object(ReleaseAutomation, 'sync_with_upstream',
                          side_effect=lambda: calls.append("sync")), \
             patch.object(ReleaseAutomation, 'create_git_tag',
                          side_effect=lambda v: calls.append("tag")), \
             patch.object(ReleaseAutomation, 'build_distribution',
                          side_effect=lambda: calls.append("build")), \
             patch.object(ReleaseAutomation, 'check_dist_contents',
                          side_effect=lambda: calls.append("dist") or True), \
             patch.object(ReleaseAutomation, 'upload_to_pypi',
                          side_effect=lambda: calls.append("upload")), \
             patch.object(ReleaseAutomation, 'create_github_release',
                          side_effect=lambda v: calls.append("release")):
            self.automation.complete_release("1.0.0")

        assert calls.index("validate") < calls.index("tag")
        assert calls == ["validate", "sync", "tag", "build", "dist", "upload", "release"]

    def test_failing_tooling_check_prevents_tagging(self):
        """When the preflight fails, nothing irreversible may run."""
        with patch.object(ReleaseAutomation, 'validate_release_tooling',
                          side_effect=ReleaseError("missing setuptools")), \
             patch.object(ReleaseAutomation, 'sync_with_upstream') as mock_sync, \
             patch.object(ReleaseAutomation, 'create_git_tag') as mock_tag, \
             patch.object(ReleaseAutomation, 'build_distribution') as mock_build:
            with pytest.raises(SystemExit):
                self.automation.complete_release("1.0.0")

        mock_sync.assert_not_called()
        mock_tag.assert_not_called()
        mock_build.assert_not_called()
