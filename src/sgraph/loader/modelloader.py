import os
import sys

from sgraph.loader.attributeloader import AttributeLoader
from sgraph import SGraph


class ModelLoader:
    def __init__(self):
        pass

    # noinspection PyMethodMayBeStatic
    def load_model(self, filepath: str, dep_types: list = None,
                   ignored_attributes: list = None) -> SGraph:
        """
        Loads model and its attribute files.
        When returning model and [None], it means that the model path did not match to the usual
        model directory (*dependency/modelfile.xml) and thus it was not expected nor tried to
        find any attribute files.

        Produce stderr output if the usual attribute files are missing.

        :param filepath: model filepath
        :param dep_types: dependency types list or None
        :param ignored_attributes: list of attribute names to ignore while parsing XML model or None
        :return: the model SGraph object
        """
        ignored_attributes = ignored_attributes or []

        extracted_paths = []

        if dep_types is None:
            dep_types = ['IGNORE dynamic_function_ref', 'IGNORE dynamic_typeref_member']

        # TODO What else would good to hide by default, maybe everything dynamic_*?

        if not filepath.endswith('/dependency/modelfile.xml') and not filepath.endswith(
                '/dependency/modelfile.xml.zip'):
            # Attribute loading not supported in this case.
            model = SGraph.parse_xml_or_zipped_xml(filepath, type_rules=dep_types,
                                                   ignored_attributes=ignored_attributes)
        else:
            # Using attributes from sibling dirs
            model = SGraph.parse_xml_or_zipped_xml(os.path.abspath(filepath), type_rules=dep_types,
                                                   ignored_attributes=ignored_attributes)
            filepath_of_model_root = filepath.replace('/dependency/modelfile.xml.zip', '').\
                replace('/dependency/modelfile.xml', '')
            a = AttributeLoader()
            model, missing_attr_files = a.load_all_files(model, filepath_of_model_root)

            for missing in missing_attr_files:
                if missing != 'attr_temporary.csv':
                    sys.stderr.write('warning: cannot load default attribute file when loading the '
                                     'model for data mining. missing: ' + missing + '\n')

        for extracted_path in extracted_paths:
            if os.path.exists(extracted_path):
                os.remove(extracted_path)
            else:
                print(
                    'model_loader.py: XML file already deleted by other process: ' + extracted_path)
        return model
