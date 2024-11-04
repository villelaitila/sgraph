# coding: utf-8
import sys

from sgraph import SGraph
from sgraph_json import sgraph_to_json_file

sgraph_to_json_file(SGraph.parse_xml_or_zipped_xml(sys.argv[1]), sys.argv[2])
