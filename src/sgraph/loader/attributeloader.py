from __future__ import annotations

import math
import os

from sgraph import SGraph
from sgraph.attributes import attributequeries


class AttributeLoader:
    def __init__(self):
        pass

    # noinspection PyMethodMayBeStatic
    def load_attrfile(self, filepath: str, model: SGraph, elem_attribute_filters: list[str]):
        ignored_attributes = []
        whitelisted_attributes = []

        for a in elem_attribute_filters:
            if a.startswith('IGNORE '):
                ignored = a[7:]
                if ignored == '*':
                    return model
                ignored_attributes.append(ignored)
            else:
                if a != '*':
                    whitelisted_attributes.append(a)

        columns, entries = attributequeries.read_attrs_generic(filepath)
        for elem_path, attrs in entries:
            if isinstance(elem_path, int):
                raise Exception(f'Invalid attribute file {filepath} as id {elem_path} is numeric..')
            elem = model.createOrGetElementFromPath(elem_path)
            for c in columns:
                if ignored_attributes:
                    if c in ignored_attributes:
                        continue
                elif whitelisted_attributes:
                    if c not in whitelisted_attributes:
                        continue
                val = attrs[c]
                if not isinstance(val, str):
                    val = '' if math.isnan(val) else val

                elem.addAttribute(c, val)

        return model

    def load_all_files(
        self,
        model: SGraph,
        filepath_of_model_root: str,
        elem_attribute_filters: list[str],
    ):
        attrfiles = [
            'attr_temporary.csv', 'git/attr_git_propagated.csv', 'git/attr_analysis_state.csv',
            'content/loc/attr_loc_propagated.csv', 'content/loc/attr_testcode_loc_propagated.csv',
            'content/loc/attr_languages.csv', 'content/attr_licenses.csv',
            'attr_issue_propagated.csv', 'content/attr_risk_level.csv', 'content/attr_pmd.csv'
        ]
        attribute_files_missing: list[str] = []
        for attrfile in attrfiles:
            fullpath = filepath_of_model_root + '/' + attrfile + '.zip'
            if os.path.exists(fullpath) and os.path.isfile(fullpath):
                # Usual case, when this is done after zipper postprocessor
                self.load_attrfile(fullpath, model, elem_attribute_filters)
            else:
                # Without .zip extension
                # Attributes can be loaded in data mining phase, when zipper has not been executed.
                fullpath = filepath_of_model_root + '/' + attrfile
                if os.path.exists(fullpath) and os.path.isfile(fullpath):
                    self.load_attrfile(fullpath, model, elem_attribute_filters)
                else:
                    attribute_files_missing.append(attrfile)
        return model, attribute_files_missing
