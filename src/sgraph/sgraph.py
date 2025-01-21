"""

Example how to use this to parse and handle model files with this tool.

 import sys

 from sgraph.sgraph import parse_deps
 egm = parse_deps('file.txt') #see above line comment
 print 'Nodes',egm.rootNode.getNodeCount()

"""
from __future__ import annotations

import codecs
import io
import os
import sys
import uuid
import xml.sax.handler
import zipfile
from copy import copy, deepcopy
from typing import Callable
from xml.sax import parseString
from xml.sax.xmlreader import AttributesImpl

from .selement import SElement
from .selementassociation import SElementAssociation
from .sgraph_utils import ParsingIntentionallyAborted, addEA, find_assocs_between


class SGraph:
    rootNode: SElement
    # modelAttrs: dict[str, str] | dict[str, dict[str, str]]
    modelAttrs: dict[str, str | dict[str, str]]
    metaAttrs: dict[str, dict[str, str]]
    propagateActions: list[tuple[str, str]]
    totalModel: "SGraph | None"

    def __init__(self, root_node: SElement | None = None):
        self.rootNode = root_node if root_node is not None else SElement(None, '')
        self.modelAttrs = {}
        self.metaAttrs = {}
        self.propagateActions = []
        self.totalModel = None

    def addPropagateAction(self, a: str, v: str):
        self.propagateActions.append((a, v))

    def createOrGetElementFromPath(self, path: str):
        """
        Create or get existing element based on element path.
        """
        if path.startswith('/'):
            path = path[1:]
        if '/' not in path:
            child = self.rootNode.getChildByName(path)
            if child is not None:
                return child
            e = SElement(self.rootNode, path)
            return e
        elif len(path) > 0:
            e = self.rootNode.createOrGetElement(path)
            return e
        return self.rootNode

    def findElementFromPath(self, path: str):
        """
        Get an element from the model by path.
        """
        if path.startswith('/'):
            path = path[1:]
        if '/' not in path:
            return self.rootNode.getChildByName(path)
        elif len(path) > 0:
            return self.rootNode.findElement(path)
        return self.rootNode

    def setMetaAttrs(self, m: dict[str, dict[str, str]]):
        self.metaAttrs = m

    def setModelAttrs(self, m: dict[str, str | dict[str, str]]):
        self.modelAttrs = m

    def save(self, fn: str):
        if fn.endswith('.xml'):
            self.to_xml(fn)
        elif fn.endswith('.plantuml') or fn.endswith('.pu'):
            self.to_plantuml(fn)
        else:
            self.to_deps(fn)

    def verify(self, i: int):
        elems: set[SElement] = set()
        for e in self.rootNode.children:
            if e in elems:
                raise Exception('Error with element already root')
            else:
                elems.add(e)

            i += 1
            e.verify(elems, i)
        deptype_counts_or_none: dict[str, int] = {}
        self.rootNode.getEATypeCounts(deptype_counts_or_none)

    def traverse(self, traverser: Callable[[SElement], None]):
        for e in self.rootNode.children:
            traverser(e)

    def to_xml(self, fname: str | None, stdout: bool = True) -> str | None:
        rootNode = self.rootNode
        counter = Counter()
        elem_to_num: dict[SElement, str] = {}
        num_to_elem: dict[str, SElement] = {}

        # class RecLevel():
        #    def __init__(self):

        def add_number(n: SElement, counter: Counter):
            if len(n.incoming) > 0:
                if n not in elem_to_num:
                    num = str(counter.now())

                    elem_to_num[n] = num
                    num_to_elem[num] = n

            for child in n.children:
                add_number(child, counter)

            toElems = set([x.toElement for x in n.outgoing])

            for o in toElems:
                if o not in elem_to_num:
                    num = str(counter.now())
                    elem_to_num[o] = num
                    num_to_elem[num] = o

        add_number(rootNode, counter)

        if fname is not None:
            f = codecs.open(fname, 'w', encoding='utf-8')
        elif stdout:
            f = sys.stdout
        else:
            f = io.StringIO()

        f.write('<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
                '<model version="2.1">\n  <elements>\n')

        def enc_xml_a_n(n: str) -> str:
            if n[0].isdigit():
                return "_" + n
            return n

        def enc_xml_a_v(v: int | float | set[str] | dict[object, object] | list[str] | str) -> str:
            if isinstance(v, int) or isinstance(v, float):
                v = str(v)
            elif isinstance(v, set):
                v = ';'.join(sorted(map(lambda x: str(x), v)))
            elif isinstance(v, dict):
                # Dictionaries may be used only during analysis, so those are discarded from the
                # outputs.
                v = ''
            elif isinstance(v, list):
                v = ';'.join(sorted(map(lambda x: str(x), v)))
            else:
                v = str(v)
            if v:
                # https://www.w3.org/TR/xml/#NT-AttValue
                # Forbidden chars are: naked ampersand, left angle bracket, double quote
                # single quote is fine as we are using double quotes in XML for attributes
                v = v.encode('utf-8', 'replace').decode()
                return v.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(
                    '\n', '&' + '#' + '10;').replace('"', '&quot;')
            return ''

        def dump_node(c: SElement, elem_to_num: dict[SElement, str], reclevel: int, fail_if_nonstr_data: bool = False):
            sorted_attrs = sorted(
                filter(lambda x: not x[0].startswith('_tmp_attr_'), c.attrs.items()))
            # noinspection PyUnusedLocal
            current_indent = '  '.join(['' for _unused in range(0, reclevel)])
            try:
                nattrs = ' '.join([
                    enc_xml_a_n(x[0]) + '="' + enc_xml_a_v(x[1]) + '"' for x in sorted_attrs
                    if x[0] != 'type'
                ])
            except TypeError as te:
                msg = f'Failed to encode attribute value to string: {te} {c.getPath()} {sorted_attrs}'
                if fail_if_nonstr_data:
                    raise Exception(msg)
                else:
                    sys.stderr.write(msg + '\n')
                    nattrs = ''

            if c.incoming and c not in elem_to_num:
                sys.stderr.write('Error, Producing erroneous model with references to ' +
                                 c.getPath() + '\n')
            if c.getType() != '':
                nattrs = ' t="' + c.getType() + '"\n' + current_indent + '  ' + nattrs
            else:
                if nattrs != '':
                    nattrs = '\n' + current_indent + '  ' + nattrs

            x = ''
            if c in elem_to_num:
                x = ' i="' + elem_to_num[c] + '" '
            f.write(current_indent)
            written_elem_tag = False
            written_attrs = False
            try:
                f.write('<e ' + x + ' n="' + enc_xml_a_v(c.name) + '" ')
                written_elem_tag = True
                f.write(nattrs)
                written_attrs = True
                f.write('>\n')
                groups = SGraph.groupea(c.outgoing)
                for ealist, deptype, ea_attrs in groups:
                    elem_numbers: list[str] = []
                    for association in ealist:
                        if association.toElement in elem_to_num:
                            elem_numbers.append(elem_to_num[association.toElement])
                        else:
                            sys.stderr.write(f'No numeric id for '
                                             f'{association.toElement.getPath()} dep '
                                             f'from {association.fromElement.name}\n')
                    idrefs = ','.join(sorted(set(elem_numbers)))
                    if idrefs:
                        # idrefs = ','.join(map(lambda x: str(x.toElement.num), g))
                        sorted_attrs = sorted(ea_attrs.items())
                        try:
                            ea_attrs_str = ' '.join([
                                enc_xml_a_n(x[0]) + '="' + enc_xml_a_v(x[1]) + '"' for x in sorted_attrs
                            ])
                        except TypeError as te:
                            msg = f'Failed to encode assoc attribute value to string: {deptype} {te} {c.getPath()} {sorted_attrs}'
                            if fail_if_nonstr_data:
                                raise Exception(msg)
                            else:
                                sys.stderr.write(msg + '\n')
                                ea_attrs_str = ''

                        f.write('  <r r="' + idrefs + '" t="' + deptype + '" ' + ea_attrs_str +
                                '/>\n')

                for cc in sorted(c.children, key=lambda x: x.name):
                    dump_node(cc, elem_to_num, reclevel + 1)

                f.write(current_indent)
                f.write('</e>\n')

            except UnicodeEncodeError:
                if not written_elem_tag:
                    sys.stderr.write(
                        f'UnicodeEncodeError when writing elem name for some child of '
                        f'{c.parent.getPath() if c.parent else "unknown"}, skipping element\n')
                    variable_part = str(uuid.uuid4())[:8]
                    f.write(f'<e {x} n="MALFORMED_NAME__{variable_part}"/>\n')
                elif not written_attrs:
                    sys.stderr.write(
                        f'UnicodeEncodeError when writing attributes of '
                        f'{c.parent.getPath() if c.parent else "unknown"}, skipping attributes and contents\n'
                    )
                    f.write(' />\n')
                else:
                    raise Exception(
                        f'UnicodeEncodeError with {c.parent.getPath() if c.parent else "unknown"}, had to abort.'
                    )

        for c in rootNode.children:
            dump_node(c, elem_to_num, 2)
        f.write('\n</elements>\n</model>\n')
        f.flush()
        if fname is not None:
            f.close()
        elif stdout:
            pass
        else:
            # We can ignore the type because out of the possible types only TextIO doesn't have
            # getvalue and it is handled above by checking if stdout is True
            return f.getvalue()  # type: ignore

    def to_deps(self, fname: str | None):
        if fname is not None:
            f = open(fname, 'w', encoding='utf-8')
        else:
            f = sys.stdout
        withDependencies = True
        withDepDetails = True
        withAttributes = True
        printedNodes: dict[SElement, int] = {}

        autogeneratedAttributeNames = ['user_count', 'used_count', 'coupling', 'childcount']

        def encodeForDeps(s: str | int | list[str]):
            if isinstance(s, str):
                return s.replace('\r\n', '<NEWLINE>').replace('\r', '<NEWLINE>').replace(
                    '\n', '<NEWLINE>')
            return str(s)

        if withAttributes:

            def handleElem(x: SElement):
                if self.totalModel is not None and self.totalModel != self:
                    tme = self.totalModel.getElement(x)
                    if tme is not None:
                        x = tme
                m = x.attrs
                p = None

                sorted_attrs = sorted(list(m.items()))

                did_something = False
                for attrname, attrval in sorted_attrs:
                    if attrname == 'type':
                        continue
                    if attrname in autogeneratedAttributeNames:
                        continue
                    if p is None:
                        p = x.getPath()
                    f.write('@' + p + ':' + attrname + ':' + encodeForDeps(attrval) + '\n')
                    did_something = True
                if did_something:
                    printedNodes[x] = 1
                if x.getType() != '':
                    if p is None:
                        p = x.getPath()
                    if len(p) > 1:
                        f.write('@' + p + ':type:' + encodeForDeps(x.getType()) + '\n')
                    printedNodes[x] = 1

            self.rootNode.traverseElements(handleElem)

        if withDependencies:

            def handleDeps(elem: SElement):
                for x in elem.outgoing:
                    from_ = x.getFromPath()
                    to = x.getToPath()
                    f.write(from_)
                    printedNodes[x.fromElement] = 1
                    f.write(':' + to)
                    printedNodes[x.toElement] = 1

                    if withDepDetails:
                        t = x.getType()
                        if t != '':
                            f.write(':' + t + '\n')
                        else:
                            f.write(':\n')
                        m = x.getAttributes()

                        for depattr, depattrval in list(m.items()):
                            if not depattr == 'type':
                                f.write('@@' + depattr + ':' + str(depattrval) + '\n')
                    else:
                        f.write('\n')

            self.rootNode.traverseElements(handleDeps)

        def handleRemaining(elem: SElement):
            if elem not in printedNodes:
                path = elem.getPath()
                if path != '':
                    f.write(elem.getPath() + '\n')

        self.rootNode.traverseElements(handleRemaining)

        for k, v in list(self.metaAttrs.items()):
            f.write(f"@@@@{k}:{v}\n")
        for k, mmap in list(self.modelAttrs.items()):
            if isinstance(mmap, dict):
                for a, v in list(mmap.items()):
                    f.write(f"@@@{k}:{a}:{v}\n")
            else:
                f.write(f"@@@{k}: {mmap}\n")
        f.flush()
        if f != sys.stdout:
            f.close()

    def produce_deps_tuples(self):
        withDependencies = True
        withAttributes = True
        printedNodes: dict[SElement, int] = {}

        autogeneratedAttributeNames = ['user_count', 'used_count', 'coupling', 'childcount']
        attrs: list[tuple[str, str, str | int | list[str]]] = []
        deps: list[tuple[str, str, str, dict[str, str | int | list[str]]]] = []

        if withAttributes:

            def handleElem(x: SElement):
                if self.totalModel is not None and self.totalModel != self:
                    tme = self.totalModel.getElement(x)
                    if tme is not None:
                        x = tme
                m = x.attrs
                p = None
                sorted_attrs = sorted(list(m.items()))

                did_something = False
                for k, v in sorted_attrs:
                    if k in autogeneratedAttributeNames:
                        continue
                    if p is None:
                        p = x.getPath()
                    attrs.append((p, k, v))
                    did_something = True
                if did_something:
                    printedNodes[x] = 1

            self.rootNode.traverseElements(handleElem)

        if withDependencies:

            def handleDeps(elem: SElement):
                for x in elem.outgoing:
                    from_ = x.getFromPath()
                    to = x.getToPath()
                    printedNodes[x.fromElement] = 1
                    printedNodes[x.toElement] = 1
                    deps.append((from_, to, x.getType(), x.getAttributes()))
                    """ not impl/tested
                    if withDepDetails:
                        t = x.getType()
                        if t != None and not type == '':
                            f.write(':'+t+'\n')
                        else:
                            f.write(':\n')
                        m = x.getAttributes()

                        if m != None:
                            for k,v in list(m.items()):
                                if not k == 'type':
                                    f.write('@@'+k+':'+v+'\n')
                    else:
                        f.write('\n')
                    """

            self.rootNode.traverseElements(handleDeps)

        orphan: list[str] = []

        def handleRemaining(elem: SElement):
            if elem not in printedNodes:
                path = elem.getPath()
                if path != '':
                    orphan.append(path)

        self.rootNode.traverseElements(handleRemaining)
        return deps, attrs, orphan

    def calculate_model_stats(self):
        dependenciesCount = self.rootNode.getEACount()
        nodesCount = self.rootNode.getNodeCount()
        depTypeCounts: dict[str, int] = {}
        self.rootNode.getEATypeCounts(depTypeCounts)
        depToElemRatio = round(dependenciesCount / nodesCount * 100)
        return dependenciesCount, nodesCount, depTypeCounts, depToElemRatio

    def getElement(self, elem: SElement) -> SElement | None:
        if elem.parent is not None and elem.parent.parent is None:
            return self.rootNode.getChildByName(elem.name)
        elif elem.parent is None:
            return self.rootNode

        # noinspection PyTypeChecker
        parentMatch = self.getElement(elem.parent)

        if parentMatch is None:
            return None
        else:
            return parentMatch.getChildByName(elem.name)

    def createOrGetElement(self, elem: SElement):
        elems = elem.get_ancestor_names_list()

        p = self.rootNode
        for i in range(len(elems)):
            s = elems[i]
            child = p.getChildByName(s)
            if child is not None:
                p = child
            else:
                return p.createElements(elems, i)
        return p

    def create_or_get_element(self, elem: SElement) -> tuple[SElement, bool]:
        """
        Create or get element matching this element, yielding also boolean to indicate if new was
        created.
        :param elem:
        :return: tuple of the matched element and boolean describing if new element was created.
        """
        elems = elem.get_ancestor_names_list()

        p = self.rootNode
        for i in range(len(elems)):
            s = elems[i]
            child = p.getChildByName(s)
            if child is not None:
                p = child
            else:
                return p.createElements(elems, i), True
        return p, False

    @staticmethod
    def calculate_model_stats_delta(
        prev: tuple[int, int, dict[str, int], int] | None,
        stats: tuple[int, int, dict[str, int], int],
    ) -> tuple[int, int, dict[str, int], int] | None:
        delta = None
        if prev is not None:
            deptype_counts_delta: dict[str, int] = {}
            a = prev[2]
            b = stats[2]
            for k in a:
                if k not in b:
                    deptype_counts_delta[k] = -a[k]
                else:
                    deptype_counts_delta[k] = b[k] - a[k]
            for k in b:
                if k not in a:
                    deptype_counts_delta[k] = b[k]

            delta = (stats[0] - prev[0], stats[1] - prev[1], deptype_counts_delta,
                     stats[3] - prev[3])
        return delta

    @staticmethod
    def __parse_xml(
        filename_or_stream: str | io.TextIOWrapper,
        type_rules: list[str] | None = None,
        elem_attribute_filters: list[str] | None = None,
        only_root: bool = False,
        parse_string: bool = False,
        assoc_attribute_filters: list[str] | None = None
    ):
        class SGraphXMLParser(xml.sax.handler.ContentHandler):
            node: int
            property: int
            link: int
            idstack: list[str]
            elemStack: list[SElement]
            currentElementPath: str | None
            currentElement: SElement | None
            id_to_elem_map: dict[str, SElement]
            rootNode: SElement
            currentRelation: dict[str, str | int | list[str]] | None
            currentElementOutgoingDeps: list[SElementAssociation] | None
            buffer: str
            acceptableAssocTypes: set[str] | None
            ignoreAssocTypes: set[str] | None
            ignored_attributes: list[str]
            only_root: bool

            def __init__(self):
                super().__init__()
                self.node = 0
                self.property = 0
                self.link = 0
                self.idstack = []
                self.elemStack = []
                self.currentElementPath = None
                self.currentElement = None
                self.id_to_elem_map = {}  # int to elem
                self.rootNode = SElement(None, '')
                self.currentRelation = None  # map string string
                self.currentElementOutgoingDeps = []  # elem assoc objs
                self.buffer = ''

                self.acceptableAssocTypes = None
                self.ignoreAssocTypes = None

                self.ignore_all_associations = False
                self.only_root = only_root

                self.whitelisted_elem_attributes = None
                self.blacklisted_elem_attributes = []
                self.ignore_all_elem_attributes = False

                self.whitelisted_assoc_attributes = None
                self.blacklisted_assoc_attributes = []
                self.ignore_all_assoc_attributes = False

            def set_type_rules(self, type_rules: list[str]):
                if type_rules is None:
                    self.acceptableAssocTypes = None
                    self.ignoreAssocTypes = None
                else:
                    for type_rule in type_rules:
                        type_rule = type_rule.strip()
                        if type_rule.strip().startswith('IGNORE '):
                            if self.ignoreAssocTypes is None:
                                self.ignoreAssocTypes = set()

                            t = type_rule[7:].strip()
                            if t == '*':
                                self.ignore_all_associations = True
                            else:
                                self.ignoreAssocTypes.add(t)
                        else:
                            if self.acceptableAssocTypes is None:
                                self.acceptableAssocTypes = set()
                            self.acceptableAssocTypes.add(type_rule)

            def set_attribute_rules(self, elem_attribute_filters,
                                    assoc_attribute_filters: list[str]):
                if elem_attribute_filters is not None:
                    for attr_rule in elem_attribute_filters:
                        a = attr_rule.strip()
                        if a.strip().startswith('IGNORE '):
                            if self.blacklisted_elem_attributes is None:
                                self.blacklisted_elem_attributes = set()

                            t = a[7:].strip()
                            if t == '*':
                                self.ignore_all_elem_attributes = True
                            else:
                                self.blacklisted_elem_attributes.add(t)
                        else:
                            if a != '*':
                                if self.whitelisted_elem_attributes is None:
                                    self.whitelisted_elem_attributes = set()
                                self.whitelisted_elem_attributes.add(a)
                if assoc_attribute_filters is not None:
                    for attr_rule in assoc_attribute_filters:
                        a = attr_rule.strip()
                        if a.strip().startswith('IGNORE '):
                            if self.blacklisted_assoc_attributes is None:
                                self.blacklisted_assoc_attributes = set()

                            t = a[7:].strip()
                            if t == '*':
                                self.ignore_all_assoc_attributes = True
                            else:
                                self.blacklisted_assoc_attributes.add(t)
                        else:
                            if a != '*':
                                if self.whitelisted_assoc_attributes is None:
                                    self.whitelisted_assoc_attributes = set()
                                self.whitelisted_assoc_attributes.add(a)

            def startElement(self, tag_name: str, attrs: AttributesImpl):

                # if self.node % 5000 == 0 and self.node > 0:
                # print(('parsing.. currently '+str(self.node)))
                #    self.buffer = ''

                if tag_name == 'a':
                    if self.ignore_all_elem_attributes and self.ignore_all_assoc_attributes:
                        return
                    name = attrs.get('n')

                    if self.currentRelation is not None:
                        if name in self.blacklisted_assoc_attributes:
                            return
                        if self.whitelisted_assoc_attributes:
                            if name not in self.whitelisted_assoc_attributes:
                                return

                        value = attrs.get('v')
                        self.currentRelation[name] = value
                    else:
                        if self.currentElement is not None and len(self.currentElementPath) > 0:
                            if name in self.blacklisted_elem_attributes:
                                return
                            if self.whitelisted_elem_attributes:
                                if name not in self.whitelisted_elem_attributes:
                                    return

                            self.property += 1
                            value = attrs.get('v')
                            self.currentElement.addAttribute(name, value)
                        else:
                            val = attrs.get('v')
                            sys.stderr.write(f' discarding {name} {val} attrs, no element to assign the data\n')

                elif tag_name == 'e':
                    element_name = attrs.get('n')

                    if len(self.idstack) == 0:
                        e = SElement(self.rootNode, element_name)
                    else:
                        parent = self.elemStack[-1]
                        e = SElement(parent, element_name)
                    self.currentElement = e
                    self.idstack.append(element_name)
                    self.currentElementPath = '/' + '/'.join(self.idstack)
                    self.node += 1
                    self.elemStack.append(self.currentElement)

                    for aname, avalue in list(attrs.items()):
                        if aname == 't' or aname == 'type':
                            e.setType(avalue)
                            self.property += 1
                        elif aname == 'i':
                            self.id_to_elem_map[avalue] = e
                        elif aname != 'n':
                            if not self.ignore_all_elem_attributes:
                                if not aname in self.blacklisted_elem_attributes:
                                    if self.whitelisted_elem_attributes:
                                        if aname in self.whitelisted_elem_attributes:
                                            e.addAttribute(aname, avalue)
                                    else:
                                        e.addAttribute(aname, avalue)


                    if self.only_root:
                        raise ParsingIntentionallyAborted('Aborted intentionally')

                elif tag_name == 'r':
                    self.currentRelation = {}
                    referred = attrs.get('r')
                    t = attrs.get('t')
                    redirectEnabled = False
                    if not redirectEnabled:
                        self.link += 1
                        if referred and ',' in referred:
                            for referred_ in [x for x in referred.split(',') if len(x) > 0]:
                                self.createReference(referred_, t)
                        elif referred is not None:
                            self.createReference(referred, t)
                    elif referred is not None:
                        self.createReference(referred, t)

                    for aname, avalue in list(attrs.items()):
                        if len(aname) > 1:
                            self.currentRelation[aname] = avalue

            def endElement(self, name: str):
                if name == 'e':
                    self.idstack.pop()
                    self.elemStack.pop()
                    if self.elemStack:
                        self.currentElement = self.elemStack[-1]
                        path = '/' + '/'.join(self.idstack)
                        self.currentElementPath = path

                elif name == 'r':
                    if self.currentElementOutgoingDeps is not None:
                        if self.currentRelation:
                            for a in self.currentElementOutgoingDeps:
                                a.setAttrMap(self.currentRelation)
                        for x in self.currentElementOutgoingDeps:
                            if not self.currentElement:
                                raise Exception('Current element is None')
                            self.currentElement.outgoing.append(x)
                        self.currentElementOutgoingDeps = None
                    self.currentRelation = None

            def createReference(self, i: str, t: str | None):
                if self.ignore_all_associations:
                    return
                elif self.acceptableAssocTypes is None and self.ignoreAssocTypes is not None:
                    if t in self.ignoreAssocTypes:
                        return
                elif self.acceptableAssocTypes is None:
                    pass  # all is fine
                elif t and t in self.acceptableAssocTypes:
                    pass  # ok
                elif (self.acceptableAssocTypes is not None and
                      len(self.acceptableAssocTypes) == 0):
                    # do not accept any deps
                    return
                else:
                    # no match
                    return

                if self.currentElementOutgoingDeps is None:
                    self.currentElementOutgoingDeps = []
                if self.currentElement is None:
                    raise Exception('Current element is None')

                # HACK: This is probably not the best way to handle this
                to = SElement(None, i)
                to.addAttribute("translate", "1")
                ea = SElementAssociation(self.currentElement, to, t or '')
                self.currentElementOutgoingDeps.append(ea)

            def translateReferences(self):
                stack = [self.rootNode]
                while stack:
                    elem = stack.pop(0)
                    for association in elem.outgoing:
                        if association.toElement.attrs.get("translate") == "1":
                            element_id = association.toElement.name
                            if element_id in self.id_to_elem_map:
                                association.toElement = self.id_to_elem_map[element_id]
                                association.toElement.incoming.append(association)
                            else:
                                sys.stderr.write(f'Error: unknown id {element_id} n={elem.name}\n')
                                raise Exception(f'Error: unknown id in input data: {element_id}')

                    for child in elem.children:
                        stack.append(child)

        parser = xml.sax.make_parser()
        a = SGraphXMLParser()
        a.set_type_rules(type_rules)
        a.set_attribute_rules(elem_attribute_filters, assoc_attribute_filters)
        parser.setContentHandler(a)
        if isinstance(filename_or_stream, str) and not parse_string:
            filepath: str = filename_or_stream
            if os.path.exists(filepath):
                try:
                    parser.parse(filepath)  # type: ignore
                except ParsingIntentionallyAborted:
                    pass
            else:
                raise Exception('Cannot find file {}'.format(filepath))
        elif isinstance(filename_or_stream, str) and parse_string:
            parseString(filename_or_stream, a)
        else:
            try:
                parser.parse(filename_or_stream)  # type: ignore
            except ParsingIntentionallyAborted:
                pass

        a.translateReferences()
        graph = SGraph(a.rootNode)
        if len(graph.rootNode.children) == 0:
            sys.stderr.write('Warning: Parsing the model file did not yield any elements.')

        return graph

    @staticmethod
    def parse_xml_or_zipped_xml(
                model_file_path: str,
                type_rules: list[str]=None,
                elem_attribute_filters: list[str]=None,
                only_root: bool=False,
                assoc_attribute_filters: list[str]=None
    ):
        if isinstance(model_file_path, str) and '.xml.zip' in model_file_path:
            with open(model_file_path, 'rb') as filehandle:
                zfile = zipfile.ZipFile(filehandle)
                data = zfile.open(zfile.namelist()[0], 'r')
                data = io.TextIOWrapper(data)
                zfile.close()
                m = SGraph.parse_xml_file_or_stream(data, type_rules,
                                       elem_attribute_filters, only_root,
                                       assoc_attribute_filters)
                m.set_model_path(model_file_path)
        else:
            m = SGraph.__parse_xml(model_file_path,
                                                type_rules,  elem_attribute_filters,
                                                only_root,  False, assoc_attribute_filters)
            m.set_model_path(model_file_path)
        return m

    @staticmethod
    def parse_xml_file_or_stream(filename_or_stream: io.TextIOWrapper | str,
                                 type_rules: list[str]=None,
                                 elem_attribute_filters: list[str]=None,
                                 only_root: bool=False,
                                 assoc_attribute_filters: list[str]=None):
            return SGraph.__parse_xml(filename_or_stream, type_rules,
                             elem_attribute_filters, only_root, False,
                             assoc_attribute_filters)

    @staticmethod
    def parse_xml_string(xml_string: str,
                         type_rules: list[str] | None = None,
                         elem_attribute_filters: list[str] | None = None,
                         only_root: bool = False,
                         assoc_attribute_filters: list[str] | None=None):
        return SGraph.__parse_xml(xml_string, type_rules,
                                elem_attribute_filters,
                                only_root, True,
                                assoc_attribute_filters)


    @staticmethod
    def parse_deps(filename: str):
        with open(filename, errors='ignore') as f:
            return SGraph.parse_deps_lines(f.read().splitlines())

    @staticmethod
    def parse_deps_lines(content: list[str]):
        TAGLEN = len('<NEWLINE>')
        modelAttrs: dict[str, str | dict[str, str]] = {}
        metaAttrs: dict[str, dict[str, str]] = {}
        lastEA: SElementAssociation | None = None
        rootNode: SElement = SElement(None, '')
        egm: SGraph = SGraph(rootNode)
        ignore: list[str] = []
        lines: int = 0

        def correctId(i: str) -> str | None:
            if i.endswith('/'):
                i = i[0:-1]
            if len(i) < 2:
                return None
            return i

        for line in content:
            if line.endswith('\r'):
                line = line[:-1]
            line = line.strip()
            lines += 1
            if len(line) > 3 and line[0:4] == '@@@@':
                splitted = line.split(':')
                if len(splitted) >= 2 and len(splitted[0]) > 3:
                    attr = splitted[0][4:]
                    modelAttrs[attr] = splitted[1]
            elif len(line) > 2 and line[0:3] == '@@@':
                firstPos = line.find(':', 3)
                if firstPos != -1:
                    secondPos = line.find(':', firstPos + 1)
                    if secondPos != -1:
                        attribute = line[3:firstPos]
                        metaattrname = line[firstPos + 1:secondPos]
                        value = line[secondPos + 1:]
                        p = value.find('<NEWLINE>')
                        while p != -1:
                            value = value[0:p] + '\n' + value[p + TAGLEN:]
                            p = value.find('<NEWLINE>')
                        if attribute not in metaAttrs:
                            metaAttrs[attribute] = {}
                        metaAttrs[attribute][metaattrname] = value
            elif len(line) > 1 and line[0:2] == '@@':
                r = line[2:]
                if ':' in r:
                    pos = r.find(':')
                    key = r[0:pos]
                    if len(r) > pos + 1:
                        rest = r[pos + 1:]
                        if lastEA is not None:
                            lastEA.attrs[key] = rest
                        else:
                            sys.stderr.write(
                                'Data format handling error: dep attr not handled properly. line=' +
                                line + '\n')

            elif len(line) > 0 and line[0] == '@':
                firstPos = line.find(':', 1)
                if firstPos != -1:
                    secondPos = line.find(':', firstPos + 1)
                    if secondPos != -1:
                        i = line[1:firstPos]
                        attrName = line[firstPos + 1:secondPos]
                        value = line[secondPos + 1:]
                        # TODO p = value.find('<NEWLINE">')
                        if i == '/':
                            sys.stderr.write('ID /\n')
                            continue
                        elif i == '/ATTRIBUTE_PROPAGATE_FOR_MODEL':
                            egm.addPropagateAction(attrName, value)
                            continue
                        e = egm.createOrGetElementFromPath(i)
                        if attrName == 'type':
                            e.setType(value)
                        else:
                            if len(value) > 0:
                                e.addAttribute(attrName, value)
                            else:
                                ignore.append(attrName)
            elif ':' in line:
                firstPos = line.find(':')
                t = None
                info = None
                if firstPos != -1:
                    secondPos = line.find(':', firstPos + 1)
                    if secondPos != -1:
                        id2 = line[firstPos + 1:secondPos]
                        thirdPos = line.find(':', secondPos + 1)
                        if thirdPos != -1:
                            t = line[secondPos + 1:thirdPos]
                            info = line[thirdPos + 1:]
                        else:
                            t = line[secondPos + 1:]
                    else:
                        id2 = line[firstPos + 1:]
                    id1 = correctId(line[0:firstPos])
                    if id1 is None:
                        continue

                    if '//' in id2:
                        id2 = id2.replace('//', '/')
                    if t is None:
                        t = ''
                    ea = addEA(t, info, id1, id2, egm)
                    lastEA = ea
            else:
                if line.strip() != '':
                    egm.createOrGetElementFromPath(line)

        sys.stderr.write('Processed: ' + str(lines) + ' lines.\n')
        egm.setModelAttrs(modelAttrs)
        egm.setMetaAttrs(metaAttrs)
        return egm

    @staticmethod
    def groupea(eas: list[SElementAssociation]):
        tuples: list[tuple[list[SElementAssociation], str, dict[str,
                                                                str | int | list[str]], ], ] = []
        easmap: dict[str, list[SElementAssociation]] = {}
        for association in eas:
            k = str(association.attrs) + association.deptype
            if k in easmap:
                easmap[k].append(association)
            else:
                easmap[k] = [association]

        for k, v in list(easmap.items()):
            tuples.append((v, v[0].deptype, v[0].attrs))

        return tuples

    def to_plantuml(self, fname: str | None):
        if fname is not None:
            f = open(fname, 'w', encoding='utf-8')
        else:
            f = sys.stdout

        def plantuml_id(e: SElement) -> str:
            return e.getPath().replace('.', '_')[1:].replace('/', '.')

        def plantuml_deptype(assoc: SElementAssociation) -> tuple[str, str | None]:
            if assoc.getType() == 'inherits':
                return '<!--', None
            elif assoc.getType() == 'implements':
                return '<!..', None
            # TODO Support also other types if needed?
            return '<--', assoc.getType()

        def plantuml_element_type(e: SElement) -> str:
            # TODO Check the rest of types
            if e.getType() == 'file' or e.getType() == 'class' or e.getType() == 'package':
                return e.getType()
            return 'component'

        def traverse_to_plantuml(e: SElement, level: int):
            # noinspection PyUnusedLocal
            indent = ''.join([' ' for _unused in range(level)])
            is_leaf = False
            if len(e.children) == 0:
                is_leaf = True
            else:
                f.write(indent + 'namespace ' + plantuml_id(e) + ' {\n')

            e_name = e.name.replace('.', '_')
            if is_leaf:
                f.write(indent + plantuml_element_type(e) + ' ' + e_name)
            for assoc in e.outgoing:
                d1, d2 = plantuml_deptype(assoc)
                postfix = ''
                if d2 is not None:
                    postfix = ' : ' + d2
                used = plantuml_id(assoc.toElement)
                f.write(indent + ' ' + used + ' ' + d1 + ' ' + e_name + postfix + '\n')

            if not is_leaf:
                for c in e.children:
                    traverse_to_plantuml(c, level + 1)

                f.write(indent + '}\n')

        f.write('@startuml\nallow_mixing\n\n')
        for elem in self.rootNode.children:
            traverse_to_plantuml(elem, 0)
        f.write('\n@enduml\n\n')
        f.flush()

    def getDepth(self):
        depth = 0
        for c in self.rootNode.children:
            depth = max(c.getMaxDepth(1), depth)
        return depth

    def calculate_graph_density(
        self,
        elempath: str,
        detail_level: int,
        external_elem: SElement | None = None,
    ):
        elems: list[SElement] = []

        def traverse_until(elem: SElement, current_level: int, detail_level: int):
            if current_level >= detail_level and external_elem != elem:
                elems.append(elem)
            elif external_elem != elem:
                for c in elem.children:
                    traverse_until(c, current_level + 1, detail_level)

        if elempath == '/':
            # global
            e = self.rootNode
            traverse_until(e, 0, detail_level)
            for c in e.children:
                traverse_until(c, 1, detail_level)
        else:
            # TODO Not tested
            e = self.findElementFromPath(elempath)
            if e is not None:
                traverse_until(e, e.getLevel(), detail_level)

        if len(elems) == 0:
            return 0

        assocs_between: set[tuple[SElement, SElement]] = set()
        for e in elems:
            assocs_between.update(find_assocs_between(e, e, elems))

        return len(assocs_between) / len(elems)

    def copy_ea_attrs_from_other_models(
        self,
        primary_model: "SGraph",
        secondary_model: "SGraph",
    ):
        """Copy element assoc attributes from head model and base model so that head model is
        preferred as a primary data source and only if the corresponding assoc is not found from it,
        base model is also considered.

        This is usually useful when doing for a small subset graph (self) and large full graphs
        (head model, base model) in order to add information to the small graph.
        This is very slow if performed for a large graph because of the complexity of
        match_ea_from_other_sgraph function.
        :params primary_model: SGraph object
        :params secondary_model: SGraph object
        """
        def visit(
            a: SElement,
            elem_of_primary_model: SElement | None,
            elem_of_secondary_model: SElement | None,
        ):
            outgoing = list(a.outgoing)
            if elem_of_primary_model:
                for association in elem_of_primary_model.outgoing:
                    corresponding_ea = SElementAssociation.match_ea_from_other_sgraph(
                        association, outgoing)
                    if corresponding_ea:
                        outgoing.remove(corresponding_ea)
                        corresponding_ea.attrs.update(association.attrs)
            if elem_of_secondary_model:
                for association in elem_of_secondary_model.outgoing:
                    corresponding_ea = SElementAssociation.match_ea_from_other_sgraph(
                        association, outgoing)
                    if corresponding_ea:
                        outgoing.remove(corresponding_ea)
                        corresponding_ea.attrs.update(association.attrs)

        SGraph.recurse_three_models(self.rootNode, primary_model.rootNode, secondary_model.rootNode,
                                    visit)

    @staticmethod
    def recurse_three_models(
        elem_a: SElement,
        elem_b: SElement | None,
        elem_c: SElement | None,
        visitor_func: Callable[[SElement, SElement | None, SElement | None], None],
    ):
        visitor_func(elem_a, elem_b, elem_c)
        for child_a in elem_a.children:
            child_b = elem_b.getChildByName(child_a.name) if elem_b is not None else None
            child_c = elem_c.getChildByName(child_a.name) if elem_c is not None else None
            SGraph.recurse_three_models(child_a, child_b, child_c, visitor_func)

    def set_model_path(self, filepath: str):
        self.modelAttrs['model_path'] = filepath

    def __deepcopy__(self, memo):  # type: ignore # TODO: Add proper typing
        result = SGraph(SElement(None, ''))
        result.metaAttrs = copy(self.metaAttrs)
        result.modelAttrs = copy(self.modelAttrs)
        result.propagateActions = copy(self.propagateActions)

        if self.totalModel:
            if self.totalModel == self:
                result.totalModel = result
            else:
                result.totalModel = deepcopy(self.totalModel)

        stack = [self.rootNode]
        new_stack = [result.rootNode]
        old_to_new_map: dict[SElement, SElement] = {}
        while stack:
            elem = stack.pop()
            new_elem = new_stack.pop()
            old_to_new_map[elem] = new_elem
            for association in elem.outgoing:
                new_association = SElementAssociation(
                    new_elem,
                    association.toElement,
                    association.deptype,
                    association.attrs,
                )
                new_elem.outgoing.append(new_association)

            for child in elem.children:
                new_child = SElement(new_elem, child.name)
                new_child.attrs = copy(child.attrs)
                stack.append(child)
                new_stack.append(new_child)

        # All elements have been created, now fix the associations' toElement reference
        new_stack = [result.rootNode]
        while new_stack:
            new_elem = new_stack.pop()
            for association in new_elem.outgoing:
                association.toElement = old_to_new_map[association.toElement]
                association.toElement.incoming.append(association)
            for child in new_elem.children:
                new_stack.append(child)
        return result


class Counter:
    def __init__(self):
        self.i = 1

    def now(self):
        self.i += 1
        return self.i
