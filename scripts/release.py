#!/usr/bin/env python3
"""
Release automation script for sgraph.

This script automates the release process described in releasing.md:
1. Validates preconditions (clean working directory, on main branch)
2. Bumps version in setup.cfg
3. Creates release branch and commits changes
4. Pushes branch and creates PR (requires gh CLI)
5. After PR merge, creates git tag
6. Builds distribution packages
7. Uploads to PyPI (requires twine)
8. Creates GitHub release (requires gh CLI)
9. Syncs main branch with upstream

Usage:
    python scripts/release.py --version 1.2.0
    python scripts/release.py --bump patch  # auto-increment patch version
    python scripts/release.py --bump minor  # auto-increment minor version
    python scripts/release.py --bump major  # auto-increment major version
"""

import argparse
import configparser
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


class ReleaseError(Exception):
    """Custom exception for release errors."""
    pass


class ReleaseAutomation:
    def __init__(self, dry_run: bool = False, allow_uncommitted_changes: bool = False, skip_confirmation: bool = False):
        self.dry_run = dry_run
        self.allow_uncommitted_changes = allow_uncommitted_changes
        self.skip_confirmation = skip_confirmation
        self.repo_root = Path(__file__).parent.parent.absolute()
        self.setup_cfg = self.repo_root / "setup.cfg"

    def run_command(self, cmd: list[str], check: bool = True, capture: bool = True, read_only: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command with optional dry-run mode.

        Args:
            cmd: Command to run
            check: Raise exception on non-zero exit code
            capture: Capture stdout/stderr
            read_only: If True, run even in dry-run mode (for reading state, not modifying)
        """
        cmd_str = " ".join(cmd)
        if self.dry_run and not read_only:
            print(f"[DRY RUN] Would run: {cmd_str}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if self.dry_run and read_only:
            print(f"[DRY RUN] Reading: {cmd_str}")
        else:
            print(f"Running: {cmd_str}")

        result = subprocess.run(
            cmd,
            cwd=self.repo_root,
            check=check,
            capture_output=capture,
            text=True
        )
        if capture and result.stdout:
            print(result.stdout.strip())
        return result

    def get_current_version(self) -> str:
        """Read current version from setup.cfg."""
        config = configparser.ConfigParser()
        config.read(self.setup_cfg)
        return config.get("metadata", "version")

    def bump_version(self, current: str, bump_type: str) -> str:
        """Bump version number based on semver."""
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", current)
        if not match:
            raise ReleaseError(f"Invalid version format: {current}")

        major, minor, patch = map(int, match.groups())

        if bump_type == "major":
            return f"{major + 1}.0.0"
        elif bump_type == "minor":
            return f"{major}.{minor + 1}.0"
        elif bump_type == "patch":
            return f"{major}.{minor}.{patch + 1}"
        else:
            raise ReleaseError(f"Invalid bump type: {bump_type}")

    def update_version_in_setup_cfg(self, new_version: str) -> None:
        """Update version in setup.cfg."""
        config = configparser.ConfigParser()
        config.read(self.setup_cfg)
        config.set("metadata", "version", new_version)

        if not self.dry_run:
            with open(self.setup_cfg, "w") as f:
                config.write(f)
            print(f"Updated version in setup.cfg to {new_version}")
        else:
            print(f"[DRY RUN] Would update version in setup.cfg to {new_version}")

    def validate_preconditions(self) -> None:
        """Validate that we're ready to release."""
        print("\n=== Validating preconditions ===")

        # Check for uncommitted changes
        result = self.run_command(["git", "status", "--porcelain"], check=False, read_only=True)
        if result.stdout.strip():
            if self.allow_uncommitted_changes:
                print("WARNING: Working directory has uncommitted changes (allowed by --allow-uncommitted-changes)")
            else:
                raise ReleaseError(
                    "Working directory has uncommitted changes. "
                    "Please commit or stash them before releasing."
                )

        # Check current branch
        result = self.run_command(["git", "branch", "--show-current"], check=False, read_only=True)
        current_branch = result.stdout.strip()
        if current_branch != "main":
            raise ReleaseError(
                f"Must be on 'main' branch (currently on '{current_branch}'). "
                "Please checkout main before releasing."
            )

        # Check if gh CLI is available
        result = subprocess.run(["which", "gh"], capture_output=True, check=False)
        if result.returncode != 0:
            print("WARNING: 'gh' CLI not found. PR and release creation will need to be done manually.")

        # Check if twine is available
        result = subprocess.run(["which", "twine"], capture_output=True, check=False)
        if result.returncode != 0:
            print("WARNING: 'twine' not found. PyPI upload will need to be done manually.")

        print("Preconditions validated successfully")

    def create_release_branch(self, version: str) -> str:
        """Create and checkout release branch."""
        branch_name = f"releasing-{version}"
        print(f"\n=== Creating release branch: {branch_name} ===")
        self.run_command(["git", "checkout", "-b", branch_name])
        return branch_name

    def commit_version_change(self, version: str) -> None:
        """Commit the version change."""
        print(f"\n=== Committing version change ===")
        self.run_command(["git", "add", "setup.cfg"])
        self.run_command(["git", "commit", "-m", f"releasing {version}"])

    def push_and_create_pr(self, branch_name: str, version: str) -> None:
        """Push branch and create PR."""
        print(f"\n=== Pushing branch and creating PR ===")

        # Push branch
        self.run_command(["git", "push", "-u", "origin", branch_name])

        # Create PR using gh CLI
        result = subprocess.run(["which", "gh"], capture_output=True, check=False)
        if result.returncode == 0 and not self.dry_run:
            pr_title = f"Release {version}"
            pr_body = f"Automated release PR for version {version}"
            self.run_command([
                "gh", "pr", "create",
                "--title", pr_title,
                "--body", pr_body,
                "--base", "main"
            ])
            print("\nPR created successfully. Please review and merge it before continuing.")
        else:
            print(f"\nPlease create a PR manually for branch '{branch_name}'")

    def wait_for_pr_merge(self) -> None:
        """Wait for user to confirm PR is merged."""
        if self.dry_run:
            print("[DRY RUN] Would wait for PR merge confirmation")
            return

        if self.skip_confirmation:
            print("\n=== Skipping PR merge wait (--yes flag) ===")
            print("WARNING: Continuing without confirming PR merge. Make sure PR is merged before running!")
            return

        print("\n=== Waiting for PR merge ===")
        input("Press Enter after the PR has been merged to continue...")

    def sync_with_upstream(self) -> None:
        """Checkout main and pull from upstream."""
        print("\n=== Syncing with upstream ===")
        self.run_command(["git", "checkout", "main"])
        self.run_command(["git", "pull", "upstream", "main"])

    def create_git_tag(self, version: str) -> None:
        """Create and push git tag."""
        print(f"\n=== Creating git tag ===")
        tag_name = f"v{version}"
        self.run_command(["git", "tag", tag_name])
        self.run_command(["git", "push", "--tags", "upstream"])

    def build_distribution(self) -> None:
        """Build distribution packages."""
        print("\n=== Building distribution packages ===")
        self.run_command([sys.executable, "setup.py", "sdist", "bdist_wheel"])

    def check_dist_contents(self) -> bool:
        """Ask user to verify dist directory contents."""
        if self.dry_run:
            print("[DRY RUN] Would prompt to check dist directory")
            return True

        print("\n=== Checking dist directory ===")
        dist_dir = self.repo_root / "dist"
        if dist_dir.exists():
            files = list(dist_dir.glob("*"))
            print(f"Files in dist directory:")
            for f in sorted(files):
                print(f"  - {f.name}")

        if self.skip_confirmation:
            print("\nSkipping dist directory confirmation (--yes flag)")
            return True

        response = input("\nDoes the dist directory look correct? (yes/no): ").strip().lower()
        return response in ("yes", "y")

    def upload_to_pypi(self) -> None:
        """Upload to PyPI using twine."""
        print("\n=== Uploading to PyPI ===")

        result = subprocess.run(["which", "twine"], capture_output=True, check=False)
        if result.returncode != 0:
            print("ERROR: twine not found. Please install it with: pip install twine")
            print("Then run manually: python3 -m twine upload --repository sgraph dist/* --skip-existing")
            return

        if self.dry_run:
            print("[DRY RUN] Would upload to PyPI")
            return

        if not self.skip_confirmation:
            response = input("Ready to upload to PyPI? This cannot be undone. (yes/no): ").strip().lower()
            if response not in ("yes", "y"):
                print("Skipping PyPI upload. You can run it manually later:")
                print("  python3 -m twine upload --repository sgraph dist/* --skip-existing")
                return
        else:
            print("Uploading to PyPI (confirmation skipped with --yes flag)")

        self.run_command([
            sys.executable, "-m", "twine", "upload",
            "--repository", "sgraph",
            "dist/*",
            "--skip-existing"
        ], capture=False)

    def create_github_release(self, version: str) -> None:
        """Create GitHub release with auto-generated notes."""
        print("\n=== Creating GitHub release ===")

        result = subprocess.run(["which", "gh"], capture_output=True, check=False)
        if result.returncode != 0:
            print("gh CLI not found. Please create the release manually at:")
            print(f"  https://github.com/softagram/sgraph/releases/new")
            print(f"  Tag: v{version}")
            return

        if self.dry_run:
            print(f"[DRY RUN] Would create GitHub release for v{version} with auto-generated notes")
            return

        tag_name = f"v{version}"
        print(f"Creating release with auto-generated notes from merged PRs...")
        self.run_command([
            "gh", "release", "create",
            tag_name,
            "--title", f"Release {version}",
            "--generate-notes",
            "--latest"
        ])

    def release(self, version: Optional[str] = None, bump: Optional[str] = None) -> None:
        """Execute the full release process."""
        try:
            # Validate preconditions
            self.validate_preconditions()

            # Determine version
            current_version = self.get_current_version()
            print(f"\nCurrent version: {current_version}")

            if bump:
                new_version = self.bump_version(current_version, bump)
                print(f"Bumping {bump} version to: {new_version}")
            elif version:
                new_version = version
                print(f"Using specified version: {new_version}")
            else:
                raise ReleaseError("Must specify either --version or --bump")

            # Confirm with user
            if not self.dry_run and not self.skip_confirmation:
                response = input(f"\nProceed with release {new_version}? (yes/no): ").strip().lower()
                if response not in ("yes", "y"):
                    print("Release cancelled.")
                    return
            elif not self.dry_run and self.skip_confirmation:
                print(f"\nProceeding with release {new_version} (confirmation skipped)")

            # Update version
            self.update_version_in_setup_cfg(new_version)

            # Create release branch
            branch_name = self.create_release_branch(new_version)

            # Commit changes
            self.commit_version_change(new_version)

            # Push and create PR
            self.push_and_create_pr(branch_name, new_version)

            # Wait for PR merge
            self.wait_for_pr_merge()

            # Sync with upstream
            self.sync_with_upstream()

            # Create git tag
            self.create_git_tag(new_version)

            # Build distribution
            self.build_distribution()

            # Check dist contents
            if not self.check_dist_contents():
                print("Please review the dist directory and run the upload manually.")
                return

            # Upload to PyPI
            self.upload_to_pypi()

            # Create GitHub release
            self.create_github_release(new_version)

            print(f"\n{'='*60}")
            print(f"Release {new_version} completed successfully!")
            print(f"{'='*60}")

        except ReleaseError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"\nCommand failed: {e.cmd}", file=sys.stderr)
            if e.stderr:
                print(e.stderr, file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nRelease cancelled by user.")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Automate the sgraph release process",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Release specific version
  python scripts/release.py --version 1.2.0

  # Auto-bump patch version (1.1.1 -> 1.1.2)
  python scripts/release.py --bump patch

  # Auto-bump minor version (1.1.1 -> 1.2.0)
  python scripts/release.py --bump minor

  # Auto-bump major version (1.1.1 -> 2.0.0)
  python scripts/release.py --bump major

  # Dry run to see what would happen
  python scripts/release.py --bump patch --dry-run

  # Test with uncommitted changes (useful during development)
  python scripts/release.py --bump patch --dry-run --allow-uncommitted-changes
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--version",
        help="Specific version to release (e.g., 1.2.0)"
    )
    group.add_argument(
        "--bump",
        choices=["major", "minor", "patch"],
        help="Automatically bump version (major, minor, or patch)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually doing it"
    )

    parser.add_argument(
        "--allow-uncommitted-changes",
        action="store_true",
        help="Allow running with uncommitted changes (useful for testing the script itself)"
    )

    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip all confirmation prompts (useful for CI/CD)"
    )

    args = parser.parse_args()

    automation = ReleaseAutomation(
        dry_run=args.dry_run,
        allow_uncommitted_changes=args.allow_uncommitted_changes,
        skip_confirmation=args.yes
    )
    automation.release(version=args.version, bump=args.bump)


if __name__ == "__main__":
    main()
