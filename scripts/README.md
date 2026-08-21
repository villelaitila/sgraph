# Scripts

This directory contains automation and development scripts for the sgraph project.

## release.py

Automates the release process for creating new versions of sgraph.

### Prerequisites

- **gh CLI**: For creating PRs and GitHub releases
  ```bash
  # Install on macOS
  brew install gh

  # Authenticate
  gh auth login
  ```

- **Build and upload modules**: The build and upload steps run as
  `sys.executable -m <module>`, so `setuptools`, `wheel` and `twine` must be
  importable **by the same interpreter that runs the script** — having a
  `twine` elsewhere on `PATH` is not enough.

  ```bash
  uv pip install setuptools wheel twine
  ```

  A virtual environment created with `uv venv` ships none of these (not even
  `pip`), so a fresh checkout needs this step. `--complete` verifies all three
  up front and refuses to start rather than failing after the tag is pushed.

- **PyPI configuration**: Configure `~/.pypirc` with your PyPI token
  ```ini
  [distutils]
  index-servers =
      sgraph

  [sgraph]
  repository = https://upload.pypi.org/legacy/
  username = __token__
  password = pypi-your-token-here
  ```

### Usage

```bash
# Release a specific version
python scripts/release.py --version 1.2.0

# Auto-bump patch version (1.1.1 -> 1.1.2)
python scripts/release.py --bump patch

# Auto-bump minor version (1.1.1 -> 1.2.0)
python scripts/release.py --bump minor

# Auto-bump major version (1.1.1 -> 2.0.0)
python scripts/release.py --bump major

# Dry run to preview what would happen
python scripts/release.py --bump patch --dry-run

# Test with uncommitted changes (useful during script development)
python scripts/release.py --bump patch --dry-run --allow-uncommitted-changes
```

### What it does

1. Validates preconditions (clean working directory, on main branch)
2. Updates version in `setup.cfg`
3. Creates a release branch (`releasing-x.x.x`)
4. Commits the version change
5. Pushes the branch and creates a PR
6. Waits for PR to be merged (requires manual approval)
7. Validates release tooling (`setuptools`, `wheel`, `twine`) before anything irreversible happens
8. Syncs main branch with upstream
9. Creates a git tag (`vx.x.x`)
10. Builds distribution packages
11. Uploads to PyPI (with confirmation)
12. Creates a GitHub release with auto-generated release notes from merged PRs

### Options

- `--version X.Y.Z`: Release a specific version number
- `--bump {major,minor,patch}`: Automatically increment version number
- `--dry-run`: Preview all actions without executing them (no changes made)
- `--allow-uncommitted-changes`: Skip the uncommitted changes check (useful when testing or developing the script itself)
- `--yes`, `-y`: Skip all confirmation prompts (useful for CI/CD automation)

### Manual fallbacks

If `gh` is not available, the script will provide instructions for completing those steps manually.

A missing `setuptools`, `wheel` or `twine` is treated as an error rather than a warning: `--complete`
pushes the git tag before it builds, so continuing without them would leave a published tag with no
artifacts behind it.
