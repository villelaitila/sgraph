import math
import os

from sgraph.attributes import attributequeries
from sgraph import SGraph


class AttributeLoader:

    def __init__(self):
        pass

    # noinspection PyMethodMayBeStatic
    def load_attrfile(self, filepath, model: SGraph):
        columns, entries = attributequeries.read_attrs_generic(filepath)
        for elem_path, attrs in entries:
            if isinstance(elem_path, int):
                raise Exception(f'Invalid attribute file {filepath} as id {elem_path} is numeric..')
            for c in columns:
                val = attrs[c]
                if not isinstance(val, str):
                    val = '' if math.isnan(val) else val
                model.createOrGetElementFromPath(elem_path).addAttribute(c, val)

        return model

    def load_all_files(self, model, filepath_of_model_root):

        attrfiles = ['attr_temporary.csv', 'git/attr_git_propagated.csv',
                     'git/attr_analysis_state.csv', 'content/loc/attr_loc_propagated.csv',
                     'content/loc/attr_testcode_loc_propagated.csv',
                     'content/loc/attr_languages.csv', 'content/attr_licenses.csv',
                     'attr_issue_propagated.csv', 'content/attr_risk_level.csv',
                     'content/attr_pmd.csv']
        attribute_files_missing = []
        for attrfile in attrfiles:
            fullpath = filepath_of_model_root + '/' + attrfile + '.zip'
            if os.path.exists(fullpath) and os.path.isfile(fullpath):
                # Usual case, when this is done after zipper postprocessor
                self.load_attrfile(fullpath, model)
            else:
                # Without .zip extension
                # Attributes can be loaded in data mining phase, when zipper has not been executed.
                fullpath = filepath_of_model_root + '/' + attrfile
                if os.path.exists(fullpath) and os.path.isfile(fullpath):
                    self.load_attrfile(fullpath, model)
                else:
                    attribute_files_missing.append(attrfile)
        return model, attribute_files_missing
