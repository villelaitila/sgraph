# coding: utf-8
import sys

from sgraph import SGraph
from sgraph.converters.sgraph_json import sgraph_to_json_file


def main():
    sgraph_to_json_file(SGraph.parse_xml_or_zipped_xml(sys.argv[1]), sys.argv[2])


if __name__ == '__main__':
    main()
