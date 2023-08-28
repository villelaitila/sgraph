import sys
import xml.etree.ElementTree as ET
from typing import Dict

from lxml import etree
from lxml.builder import ElementMaker

from lxml.etree import Element

from sgraph import SGraph, SElement, SElementAssociation

Y_NS = 'http://www.yworks.com/xml/graphml'
Y_NS_IN_BRACES = '{http://www.yworks.com/xml/graphml}'
GD_NS_IN_BRACES = '{http://graphml.graphdrawing.org/xmlns}'
XML_NS_IN_BRACES = '{{http://www.w3.org/XML/1998/namespace}'
NODE_TAGS = [f'{Y_NS_IN_BRACES}ShapeNode', f'{Y_NS_IN_BRACES}GenericNode']
SLASH_ENCODED = '__slash__'


def handle_realizers(realizers):
    nodelabel = ''
    realizer = realizers[int(realizers.attrib['active'])]
    if realizer.tag != f'{Y_NS_IN_BRACES}GroupNode':
        sys.stderr.write('Skipping something not expected...')
        return ''
    for group_node_child in realizer:
        if group_node_child.tag == f'{Y_NS_IN_BRACES}NodeLabel':
            nodelabel += group_node_child.text
    return nodelabel


def handle_nodegraphics(nodegraphics_data):
    style_attributes = {}
    node_label = ''
    for child in nodegraphics_data:
        # print('   ' + child.tag)
        # Realizer, Simple, etc.
        for label_or_style in child:
            if label_or_style.tag == f'{Y_NS_IN_BRACES}Realizers':
                node_label += handle_realizers(label_or_style)
        if child.tag in NODE_TAGS:
            for label_or_style in child:
                if label_or_style.tag == f'{Y_NS_IN_BRACES}NodeLabel':
                    if not ('modelName' in label_or_style.attrib and
                            'corners' == label_or_style.attrib['modelName']):
                        node_label += label_or_style.text.strip()
                        if node_label.endswith('&#10;'):
                            node_label.replace('&#10;', '')
                        if 'backgroundColor' in label_or_style.attrib:
                            style_attributes['style__background_color_for_label'] = \
                                label_or_style.attrib['backgroundColor']
                        if 'textColor' in label_or_style.attrib:
                            style_attributes['style__text_color'] = label_or_style.attrib['textColor']
                        if 'fontFamily' in label_or_style.attrib:
                            style_attributes['style__font_family'] = label_or_style.attrib['fontFamily']
                elif label_or_style.tag == f'{Y_NS_IN_BRACES}Fill':
                    if 'color' in label_or_style.attrib:
                        style_attributes['style__fill_color'] = label_or_style.attrib['color']
                elif label_or_style.tag == f'{Y_NS_IN_BRACES}BorderStyle':
                    if 'color' in label_or_style.attrib:
                        style_attributes['style__border_color'] = label_or_style.attrib['color']
                elif label_or_style.tag == f'{Y_NS_IN_BRACES}Shape':
                    if 'type' in label_or_style.attrib:
                        style_attributes['style__shape_type'] = label_or_style.attrib['type']

    return node_label, style_attributes


def handle_node(node: Element, parent_elem: SElement, node_id_to_element, graphml_keys, recursion):
    attrs = {}
    node_label = ''
    for input_data in node.findall(f'{GD_NS_IN_BRACES}data'):
        if input_data.attrib['key'] in graphml_keys:

            field_spec = graphml_keys[input_data.attrib['key']]
            if 'attr.name' in field_spec and field_spec['for'] == 'node' and input_data.text:
                if input_data.text.strip():
                    attr_name = field_spec['attr.name']
                    if f'{XML_NS_IN_BRACES}space' in input_data.attrib:
                        # preserve? = data.attrib[f'{XML_NS_IN_BRACES}space']
                        pass

                    attrs[attr_name] = input_data.text.strip()
            else:
                if 'yfiles.type' in field_spec and field_spec['yfiles.type'] == 'nodegraphics':
                    node_label, style_attributes = handle_nodegraphics(input_data)
                    if style_attributes:
                        attrs.update(style_attributes)

    if node_label:
        elem_id = node_label
    else:
        elem_id = ''

    # print('  ' * recursion, elem_id, attrs)

    if elem_id == '':
        sys.stderr.write('Cannot handle node ' + elem_id + ' under ' + parent_elem.getPath())
        return

    # Prevent slash character in node label to cause sub elements in sgraph side.
    elem_id = elem_id.replace('/', '__slash__')
    if elem_id in parent_elem.childrenDict:
        raise Exception('Overlapping node: ' + parent_elem.getPath() + '/' + elem_id)
    else:
        new_elem = parent_elem.createOrGetElement(elem_id)
        new_elem.attrs.update(attrs)
        # new_elem.attrs.update(out_from_nodegraphics)
        node_id_to_element[node.attrib['id']] = new_elem

    graphs = node.findall(f'{GD_NS_IN_BRACES}graph')
    if graphs:
        if len(graphs) > 1:
            raise Exception('Not implemented g>1')
        handle_graph(graphs[0], graphml_keys, node_id_to_element, new_elem, recursion)


def handle_edge(node, node_id_to_element, graphml_keys):
    edge_id = node.attrib['id']
    source_elem = node_id_to_element.get(node.attrib['source'])
    target_elem = node_id_to_element.get(node.attrib['target'])
    if not source_elem:
        sys.stderr.write(f'Unknown elem for {node.attrib["source"]} in e={edge_id}, ignoring')
        return
    if not target_elem:
        sys.stderr.write(f'Unknown elem for {node.attrib["target"]} in e={edge_id}, ignoring')
        return

    dep_type = ''
    attrs = {}
    for edge_data in node:
        field_spec = graphml_keys[edge_data.attrib['key']]
        if field_spec['for'] == 'edge':
            if 'attr.name' in field_spec and field_spec['attr.type'] == 'string':
                if edge_data.text and edge_data.text.strip():
                    attrs[field_spec['attr.name'].lower()] = edge_data.text.strip()
            elif 'yfiles.type' in field_spec and field_spec['yfiles.type'] == 'edgegraphics':
                for edge_elem in edge_data:
                    for edge_detail in edge_elem:
                        if edge_detail.tag == f'{Y_NS_IN_BRACES}EdgeLabel':
                            if edge_detail.text:
                                dep_type = edge_detail.text.strip()
                            if 'textColor' in edge_detail.attrib:
                                attrs['style__text_color'] = edge_detail.attrib['textColor']
                        elif edge_detail.tag == f'{Y_NS_IN_BRACES}LineStyle':
                            if 'color' in edge_detail.attrib:
                                attrs['style__color'] = edge_detail.attrib['color']
                            elif 'line_type' in edge_detail.attrib:
                                attrs['style__line_type'] = edge_detail.attrib['line_type']
                            elif 'width' in edge_detail.attrib:
                                attrs['style__width'] = edge_detail.attrib['width']
                        elif edge_detail.tag == f'{Y_NS_IN_BRACES}Arrows':
                            if 'source' in edge_detail.attrib:
                                attrs['style__source_arrow'] = edge_detail.attrib['source']
                            if 'target' in edge_detail.attrib:
                                attrs['style__target_arrow'] = edge_detail.attrib['target']

    association = SElementAssociation(source_elem, target_elem, dep_type, attrs)
    association.initElems()
    return association


def handle_graph(input_graph, graphml_keys, node_id_to_element, parent_elem, recursion=0):
    attrs = {}
    # for b in input_graph:
    #    print('  '*recursion, b.tag, b.attrib)
    for input_data in input_graph.findall(f'{GD_NS_IN_BRACES}data'):
        if input_data.attrib['key'] in graphml_keys:
            attr_name = graphml_keys[input_data.attrib['key']]['attr.name']
            if f'{XML_NS_IN_BRACES}space' in input_data.attrib:
                attrs[attr_name] = input_data.attrib[f'{XML_NS_IN_BRACES}space']

    for node in input_graph.findall(f'{GD_NS_IN_BRACES}node'):
        handle_node(node, parent_elem, node_id_to_element, graphml_keys, recursion)


def handle_main_level_graph(input_graph, graphml_keys, node_id_to_element, parent_elem,
                            output_graph, recursion=0):
    # for b in input_graph:
    #    print('  '*recursion, b.tag, b.attrib)
    for input_data in input_graph.findall(f'{GD_NS_IN_BRACES}data'):
        if input_data.attrib['key'] in graphml_keys:
            key_id = input_data.attrib['key']
            field_spec = graphml_keys[key_id]
            if field_spec['attr.type'] == 'string':
                if field_spec['for'] == 'graph':
                    if input_data.text and input_data.text.strip():
                        output_graph.modelAttrs[
                            field_spec['attr.name'].lower()] = input_data.text.strip()
                elif field_spec['for'] == 'node':
                    if input_data.text and input_data.text.strip():
                        parent_elem.attrs[field_spec['attr.name'].lower()] = input_data.text.strip()

    for node in input_graph.findall(f'{GD_NS_IN_BRACES}node'):
        handle_node(node, parent_elem, node_id_to_element, graphml_keys, recursion)

    # Only for the main level graph?
    for node in input_graph.findall(f'{GD_NS_IN_BRACES}edge'):
        handle_edge(node, node_id_to_element, graphml_keys)


def graphml_to_sgraph(graphml_data):
    doc = ET.ElementTree(ET.fromstring(graphml_data))
    graphml_elem = doc.getroot()
    output_root = SElement(None, '')
    output_graph = SGraph(output_root)
    graphml_keys = {}
    for key_value_pair in graphml_elem.findall(f'{GD_NS_IN_BRACES}key'):
        """<key attr.name="Description" attr.type="string" for="graph" id="d0"/>
  <key for="port" id="d1" yfiles.type="portgraphics"/>
  <key for="port" id="d2" yfiles.type="portgeometry"/>
  <key for="port" id="d3" yfiles.type="portuserdata"/>
  <key attr.name="url" attr.type="string" for="node" id="d4"/>
  <key attr.name="description" attr.type="string" for="node" id="d5"/>
  <key for="node" id="d6" yfiles.type="nodegraphics"/>
  <key for="graphml" id="d7" yfiles.type="resources"/>
  <key attr.name="url" attr.type="string" for="edge" id="d8"/>
  <key attr.name="description" attr.type="string" for="edge" id="d9"/>
  <key for="edge" id="d10" yfiles.type="edgegraphics"/>
        """
        key_data = {}
        for x, y in key_value_pair.attrib.items():
            if x != 'id':
                key_data[x] = y
        graphml_keys[key_value_pair.attrib['id']] = key_data

    node_id_to_element = {}
    for input_graph in graphml_elem.findall(f'{GD_NS_IN_BRACES}graph'):
        handle_main_level_graph(input_graph, graphml_keys, node_id_to_element, output_root,
                                output_graph)

    return output_graph


def generate_dom_for_edge(assoc: SElementAssociation, parent, element_to_id_map, edge_id):
    edge = etree.SubElement(parent, 'edge')
    edge.set('source', element_to_id_map[assoc.fromElement])
    edge.set('target', element_to_id_map[assoc.toElement])
    edge.set('id', edge_id)

    attrs = assoc.attrs

    if 'url' in attrs:
        etree.SubElement(edge, 'data', {'key': 'd8'}).text = attrs['url']
    if 'description' in attrs:
        etree.SubElement(edge, 'data', {'key': 'd9'}).text = attrs['description']

    if assoc.deptype:
        d10 = etree.SubElement(edge, 'data', {'key': 'd10'})
        poly_line_edge = etree.SubElement(d10, f'{Y_NS_IN_BRACES}PolyLineEdge')
        line_color = attrs.get('style__color', '#000000')
        line_type = attrs.get('style__line_type', 'line')
        line_width = attrs.get('style__width', '1.0')
        source_arrow = attrs.get('style__source_arrow', 'none')
        target_arrow = attrs.get('style__target_arrow', 'standard')
        text_color = attrs.get('style__text_color', '#000000')

        etree.SubElement(poly_line_edge, f'{Y_NS_IN_BRACES}LineStyle', {
            'color': line_color,
            'line_type': line_type,
            'width': line_width
        })
        etree.SubElement(poly_line_edge, f'{Y_NS_IN_BRACES}Arrows', {
            'source': source_arrow,
            'target': target_arrow
        })
        etree.SubElement(poly_line_edge, f'{Y_NS_IN_BRACES}EdgeLabel', {
            'textColor': text_color
        }).text = assoc.deptype

    return edge


def generate_dom_for_element(e: SElement, id_counter: Dict[SElement, int], current_node_id: str,
                             parent_dom: Element, element_to_id_map):
    elem_dom = etree.SubElement(parent_dom, 'node')
    elem_dom.set('id', current_node_id)
    if e.children:
        elem_dom.set('yfiles.foldertype', 'group')
    element_to_id_map[e] = current_node_id

    fill_color = e.attrs.get('style__fill_color', '#FFF7C8')
    bg_color = e.attrs.get('style__background_color_for_label', '#EBEBEB')
    border_color = e.attrs.get('style__border_color', '#000000')
    text_color = e.attrs.get('style__text_color', '#000000')
    shape_type = e.attrs.get('style__shape_type', 'roundrectangle')
    font_family = e.attrs.get('style__font_family', 'Dialog')

    if 'url' in e.attrs:
        etree.SubElement(elem_dom, 'data', {'key': 'd4'}).text = e.attrs['url'].strip()
    if 'description' in e.attrs:
        etree.SubElement(elem_dom, 'data', {'key': 'd5'}).text = e.attrs['description'].strip()

    if e.children:
        id_counter[e] = 0
        d10 = etree.SubElement(elem_dom, 'data', {'key': 'd6'})
        realizers = etree.SubElement(etree.SubElement(d10, f'{Y_NS_IN_BRACES}ProxyAutoBoundsNode'),
                                     f'{Y_NS_IN_BRACES}Realizers')
        realizers.set('active', '0')
        node = etree.SubElement(realizers, f'{Y_NS_IN_BRACES}GroupNode')
        etree.SubElement(
            node, f'{Y_NS_IN_BRACES}NodeLabel', {
                'alignment': 'right',
                'autoSizePolicy': 'node_width',
                'backgroundColor': bg_color,
                'borderDistance': "0.0",
                'fontFamily': font_family,
                'fontSize': "14",
                'fontStyle': "plain",
                'hasLineColor': "false",
                'height': "21.4609375",
                'horizontalTextPosition': "center",
                'iconTextGap': "4",
                'modelName': "internal",
                'modelPosition': "t",
                'textColor': text_color,
                'verticalTextPosition': "bottom",
                'visible': "true",
                'width': "273.0",
                'x': "0.0",
                'y': '0.0'
            }).text = e.name.replace(SLASH_ENCODED, '/')
        etree.SubElement(node, f'{{{Y_NS}}}Fill', {'color': fill_color, 'transparent': 'false'})
        etree.SubElement(node, f'{{{Y_NS}}}BorderStyle', {
            'color': border_color,
            'type': 'line',
            'width': '1.0'
        })
        etree.SubElement(node, f'{{{Y_NS}}}State', {'closed': 'false'})
        etree.SubElement(realizers, f'{{{Y_NS}}}GroupNode')

        graph = etree.SubElement(elem_dom, 'graph')
        graph.set('edgedefault', 'directed')

        graph.set('id', current_node_id + ':')

        for child in e.children:
            child_node_id = f'{current_node_id}:n{id_counter[e]}'
            generate_dom_for_element(child, id_counter, child_node_id, graph, element_to_id_map)
            id_counter[e] += 1
    else:
        d10 = etree.SubElement(elem_dom, 'data', {'key': 'd6'})
        node = etree.SubElement(d10, f'{{{Y_NS}}}ShapeNode')
        etree.SubElement(node, f'{{{Y_NS}}}Geometry', {'height': '30.0', 'width': '30.0'})
        etree.SubElement(node, f'{{{Y_NS}}}Fill', {'color': fill_color, 'transparent': 'false'})

        #             'hasColor': 'false'
        etree.SubElement(node, f'{{{Y_NS}}}BorderStyle', {
            'color': border_color,
            'raised': 'false',
            'type': 'line',
            'width': '1.0'
        })
        l_attrs = {
            'alignment': "center",
            'autoSizePolicy': "content",
            'fontFamily': font_family,
            'fontSize': "12",
            'fontStyle': "plain",
            'hasBackgroundColor': "false",
            'hasLineColor': "false",
            'height': "17.96875",
            'horizontalTextPosition': "center",
            'iconTextGap': "4",
            'modelName': "custom",
            'textColor': text_color,
            'verticalTextPosition': 'bottom',
            'visible': "true"
        }
        etree.SubElement(node, f'{{{Y_NS}}}NodeLabel', l_attrs).text = e.name.replace(
            SLASH_ENCODED, '/')

    etree.SubElement(node, f'{{{Y_NS}}}Shape', {'type': shape_type})


# noinspection PyPep8Naming
def generate_graphml_element_and_main_graph():
    NSMAP = {
        None: 'http://graphml.graphdrawing.org/xmlns',
        'y': 'http://www.yworks.com/xml/graphml',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }
    E = ElementMaker(nsmap=NSMAP)
    KEY = E.key
    GRAPHML = E.graphml
    graphml = GRAPHML(
        KEY({
            'id': 'd0',
            'for': 'graph',
            'attr.name': 'Description',
            'attr.type': 'string'
        }), KEY({
            'id': 'd1',
            'for': 'port',
            'yfiles.type': 'portgraphics'
        }), KEY({
            'id': 'd2',
            'for': 'port',
            'yfiles.type': 'portgeometry'
        }), KEY({
            'id': 'd3',
            'for': 'port',
            'yfiles.type': 'portuserdata'
        }), KEY({
            'id': 'd4',
            'for': 'node',
            'attr.name': 'url',
            'attr.type': 'string'
        }), KEY({
            'id': 'd5',
            'for': 'node',
            'attr.name': 'description',
            'attr.type': 'string'
        }), KEY({
            'id': 'd6',
            'for': 'node',
            'yfiles.type': 'nodegraphics'
        }), KEY({
            'id': 'd7',
            'for': 'graphml',
            'yfiles.type': 'resources'
        }), KEY({
            'id': 'd8',
            'for': 'edge',
            'attr.name': 'url',
            'attr.type': 'string'
        }), KEY({
            'id': 'd9',
            'for': 'edge',
            'attr.name': 'description',
            'attr.type': 'string'
        }), KEY({
            'id': 'd10',
            'for': 'edge',
            'yfiles.type': 'edgegraphics'
        }))

    out_graph = etree.SubElement(graphml, 'graph')
    out_graph.set('id', 'G')
    out_graph.set('edgedefault', 'directed')
    etree.SubElement(out_graph, 'data', {'key': 'd0', 'space': 'preserve'})
    data = etree.SubElement(graphml, 'data', {'key': 'd7'})
    etree.SubElement(data, f'{{{Y_NS}}}Resources')
    return graphml, out_graph


def sgraph_to_graphml_file(graph: SGraph, out_filename: str):
    root = graph.rootNode
    out_graphml, out_graph = generate_graphml_element_and_main_graph()
    id_counter = {root: 0}
    element_to_id_map = {}
    for e in root.children:
        current_node_id = f'n{id_counter[root]}'
        generate_dom_for_element(e, id_counter, current_node_id, out_graph, element_to_id_map)
        id_counter[root] += 1

    stack = [root]
    edge_number = 0
    while stack:
        elem = stack.pop(0)
        for assoc in elem.outgoing:
            generate_dom_for_edge(assoc, out_graph, element_to_id_map, f'e{edge_number}')
            edge_number += 1

        if elem.children:
            stack.extend(elem.children)

    with open(out_filename, 'wb') as doc:
        doc.write(
            etree.tostring(out_graphml, pretty_print=True,
                           doctype='<?xml version="1.0" encoding="UTF-8" standalone="no"?>'))
