import json
import os
import shutil
import subprocess
import sys

import pytest

CONVERSION_FIXTURE = 'modelfile_for_sbom_tests.xml'


def _fixture_path():
    return os.path.join(os.path.dirname(__file__), CONVERSION_FIXTURE)


def test_module_is_importable():
    """Regression test: the module used to import a nonexistent top-level
    sgraph_json module and run the conversion at import time."""
    import sgraph.converters.xml_to_hierarchical_json  # noqa: F401


def test_main_converts_model_to_json(tmp_path, monkeypatch):
    from sgraph.converters import xml_to_hierarchical_json

    model_path = _fixture_path()
    output_path = str(tmp_path / 'output.json')
    monkeypatch.setattr(sys, 'argv', ['xml_to_hierarchical_json', model_path, output_path])

    xml_to_hierarchical_json.main()

    with open(output_path) as f:
        doc = json.load(f)
    assert doc


def test_the_conversion_fixture_is_tracked_in_git():
    """The fixture read by test_main_converts_model_to_json must be in the commit HEAD points at.

    An untracked fixture makes the suite pass on the machine that produced it and fail on a fresh
    clone. Two checks, because they prove different things and only the pair proves the claim:
    'ls-files --error-unmatch' proves the path is in the INDEX, and 'cat-file -e HEAD:<path>'
    proves it is in the COMMIT a clone would check out. A file that is staged and never committed
    satisfies the first and fails the second, which is the same broken clone reached by an amend,
    a reset, or an edit interrupted between 'git add' and 'git commit'.

    Skipped where the question cannot be asked: git absent, an unpacked sdist, or a bare
    repository — which answers --is-inside-work-tree with 'false' and exit code 0 rather than
    failing, so the answer is read from stdout and not from the exit code alone.
    """
    if shutil.which('git') is None:
        pytest.skip('git is not available')
    fixture = _fixture_path()
    directory = os.path.dirname(fixture)
    inside_worktree = subprocess.run(['git', '-C', directory, 'rev-parse', '--is-inside-work-tree'],
                                     capture_output=True, text=True)
    if inside_worktree.returncode != 0 or inside_worktree.stdout.strip() != 'true':
        pytest.skip('not a git checkout')

    # --full-name answers with the path relative to the repository root, spelled with forward
    # slashes on every platform, which is the spelling cat-file needs: the layout is asked for
    # rather than derived.
    indexed = subprocess.run(
        ['git', '-C', directory, 'ls-files', '--full-name', '--error-unmatch', fixture],
        capture_output=True, text=True)
    assert indexed.returncode == 0, f'{fixture} is not tracked in git: {indexed.stderr}'

    committed = subprocess.run(
        ['git', '-C', directory, 'cat-file', '-e', f'HEAD:{indexed.stdout.strip()}'],
        capture_output=True, text=True)
    assert committed.returncode == 0, f'{fixture} is staged but not committed: {committed.stderr}'
