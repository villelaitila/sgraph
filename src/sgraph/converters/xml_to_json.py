# coding: utf-8
import json
import random
import string

from lxml import etree


def get_node_path(elem_node):
    parent = elem_node.getparent()
    if parent is not None and parent.tag == 'e':
        return get_node_path(parent) + '/' + parent.get('n')
    else:
        return ''


class XmlToNodesAndEdges:
    """XmlToNodesAndEdges transforms dependency xml to nodes and edges"""
    def __init__(self, path_to_xml):
        self.path_to_xml = path_to_xml
        self.nodes = []
        self.edges = []
        self.__id_idx = set()

    def __build_node_initial(self, elem_node):
        """Builds node for internal purposes. __elem refers to actual parsed element.
        id=i if i exists. Otherwise id some other random string. N"""
        element_path = elem_node.get('i')
        if not element_path:
            element_path = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        if element_path in self.__id_idx:
            # TODO Generate new id if this
            raise ValueError('Duplicate id entry %s' % element_path)
        else:
            self.__id_idx.add(element_path)

        # This stores id to the actual xml element too (so that its usable all over the tree)
        if '_id' in elem_node.attrib:
            raise KeyError('_id key already in use')

        elem_node.attrib['_id'] = element_path

        node = {
            'id': element_path,
            'i': elem_node.get('i'),
            'name': elem_node.get('n'),
            'path': get_node_path(elem_node),
            '__elem': elem_node
        }

        if elem_node.get('loc'):
            node['loc'] = elem_node.get('loc')

        return node

    # TODO build as dict for better performance (easy: set id as key)
    def __parse(self, ):
        tree = etree.parse(self.path_to_xml)

        # Get all element nodes (not the meta)
        nodes = [self.__build_node_initial(e) for e in tree.findall('*//e')]

        edges = []
        edge_id = 1
        nodes_with_rels = [node for node in nodes if node['__elem'].find('./r') is not None]
        # Lets build the edges
        for node in nodes_with_rels:
            # Elements relations
            elem_rels = node['__elem'].findall('./r')
            for elem_r in elem_rels:
                # Relations in r tag
                for ri in elem_r.get('r').split(','):
                    edge_id += 1
                    edges.append({
                        'id': str(edge_id),
                        'source': node['id'],
                        'target': ri,
                        'type': elem_r.get('t')
                    })

        # Ids set -> get children
        for node in nodes:
            node['children_ids'] = [
                c.attrib['_id'] for c in node['__elem'].getchildren() if c.tag == 'e'
            ]

        # Delete actual XML Elem
        for node in nodes:
            del node['__elem']

        return (
            nodes,
            edges,
        )

    def get_doc(self):
        """Returns dict with nodes and edges"""
        if not self.nodes and not self.edges:
            self.nodes, self.edges = self.__parse()
        return {'nodes': self.nodes, 'edges': self.edges}

    def save_as_json(self, output_path):
        """Saves nodes and edges as json"""
        with open(output_path, 'w') as f:
            f.write(json.dumps(self.get_doc()))
