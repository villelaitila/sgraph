import json
import os
import sys


def test_module_is_importable():
    """Regression test: the module used to import a nonexistent top-level
    sgraph_json module and run the conversion at import time."""
    import sgraph.converters.xml_to_hierarchical_json  # noqa: F401


def test_main_converts_model_to_json(tmp_path, monkeypatch):
    from sgraph.converters import xml_to_hierarchical_json

    model_path = os.path.join(os.path.dirname(__file__), 'model.xml')
    output_path = str(tmp_path / 'output.json')
    monkeypatch.setattr(sys, 'argv', ['xml_to_hierarchical_json', model_path, output_path])

    xml_to_hierarchical_json.main()

    with open(output_path) as f:
        doc = json.load(f)
    assert doc
