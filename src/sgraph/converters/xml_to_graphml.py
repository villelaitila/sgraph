import sys

from sgraph import SGraph
from sgraph.converters.graphml import sgraph_to_graphml_file

sgraph_to_graphml_file(SGraph.parse_xml_or_zipped_xml(sys.argv[1]), sys.argv[2])
