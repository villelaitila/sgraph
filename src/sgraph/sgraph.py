"""

Example how to use this to parse and handle model files with this tool.

 import sys

 from sgraph.sgraph import parse_deps
 egm = parse_deps('file.txt') #see above line comment
 print 'Nodes',egm.rootNode.getNodeCount()

"""
import io
import os
import xml.sax.handler
import sys
import collections
import codecs
import zipfile
from typing import Optional

from .selement import SElement
from .selementassociation import SElementAssociation


def addEA(deptype, info, id1, id2, egm):
    e1 = None
    if not id1.startswith('generate dependency'):
        e1 = egm.createOrGetElementFromPath(id1)
    e2 = None
    if not id2.startswith('generate dependency'):
        e2 = egm.createOrGetElementFromPath(id2)

    if info is not None and len(info) > 0:
        new_ea = SElementAssociation(e1, e2, deptype, {'detail': info})
    else:
        new_ea = SElementAssociation(e1, e2, deptype, {})
    new_ea.initElems()
    return new_ea


def find_assocs_between(e_orig, e, elems):
    elem_tuples = set()
    for out in e.outgoing:
        for elem in elems:
            if out.toElement.isDescendantOf(elem):
                elem_tuples.add((e_orig, elem))
    for child in e.children:
        elem_tuples.update(find_assocs_between(e_orig, child, elems))
    return elem_tuples


class ParsingIntentionallyAborted(Exception):
    pass


class SGraph:
    def __init__(self, root_node=None):
        self.rootNode = root_node if root_node is not None else SElement(
            None, '')
        self.modelAttrs = {}
        self.metaAttrs = {}
        self.propagateActions = []
        self.totalModel = None

    def addPropagateAction(self, a, v):
        self.propagateActions.append((a, v))

    def getElementFromPath(self, i):
        """TODO Rename as createOrGetElementFromPath because the name is misleading."""
        if i.startswith('/'):
            i = i[1:]
        if '/' not in i:
            return self.rootNode.getChildByName(i)
        elif len(i) > 0:
            e = self.rootNode.createOrGetElement(i)
            return e
        return self.rootNode

    def createOrGetElementFromPath(self, i: str):
        if i.startswith('/'):
            i = i[1:]
        if '/' not in i:
            child = self.rootNode.getChildByName(i)
            if child is not None:
                return child
            e = SElement(self.rootNode, i)
            return e
        elif len(i) > 0:
            e = self.rootNode.createOrGetElement(i)
            return e
        return self.rootNode

    def findElementFromPath(self, i: str):
        if i.startswith('/'):
            i = i[1:]
        if '/' not in i:
            return self.rootNode.getChildByName(i)
        elif len(i) > 0:
            return self.rootNode.findElement(i)
        return self.rootNode

    def setMetaAttrs(self, m):
        self.metaAttrs = m

    def setModelAttrs(self, m):
        self.modelAttrs = m

    def save(self, fn):
        if fn.endswith('.xml'):
            self.to_xml(fn)
        elif fn.endswith('.plantuml') or fn.endswith('.pu'):
            self.to_plantuml(fn)
        else:
            self.to_deps(fn)

    def verify(self, i):
        elems = set()
        for e in self.rootNode.children:
            if e in elems:
                raise Exception('Error with element already root')
            else:
                elems.add(e)

            i += 1
            e.verify(elems, i)
        deptype_counts_or_none = {}
        self.rootNode.getEATypeCounts(deptype_counts_or_none)

    def traverse(self, traverser):
        for e in self.rootNode.children:
            traverser(e)

    def to_xml(self, fname, stdout=True):
        rootNode = self.rootNode
        counter = Counter()
        elem_to_num = {}
        num_to_elem = {}

        # class RecLevel():
        #    def __init__(self):

        def add_number(n, counter):
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

        f.write('<model version="2.1">\n  <elements>\n')

        def enc_xml_a_n(n):
            if n[0].isdigit():
                return "_" + n
            return n

        def enc_xml_a_v(v):
            if isinstance(v, collections.Mapping) or isinstance(
                    v, int) or isinstance(v, float):
                v = str(v)
            elif isinstance(v, set):
                v = ';'.join(sorted(v))
            elif isinstance(v, dict):
                # Dictionaries may be used only during analysis, so those are discarded from the
                # outputs.
                v = ''
            elif isinstance(v, list):
                v = ';'.join(v)
            elif not isinstance(v, str):
                v = str(v)
            if v:
                # https://www.w3.org/TR/xml/#NT-AttValue
                # Forbidden chars are: naked ampersand, left angle bracket, double quote
                # single quote is fine as we are using double quotes in XML for attributes
                return v.replace('&', '&amp;').replace('<', '&lt;').replace(
                    '>',
                    '&gt;').replace('\n',
                                    '&' + '#' + '10;').replace('"', '&quot;')
            return ''

        def dump_node(c, elem_to_num, reclevel):
            sorted_attrs = sorted(
                filter(lambda x: not x[0].startswith('_tmp_attr_'),
                       c.attrs.items()))
            # noinspection PyUnusedLocal
            current_indent = '  '.join(['' for _unused in range(0, reclevel)])
            nattrs = ' '.join([
                enc_xml_a_n(x[0]) + '="' + enc_xml_a_v(x[1]) + '"'
                for x in sorted_attrs if x[0] != 'type'
            ])
            if c.incoming and c not in elem_to_num:
                sys.stderr.write(
                    'Error, Producing erroneous model with references to ' +
                    c.getPath() + '\n')
            if c.getType() != '':
                nattrs = ' t="' + c.getType(
                ) + '"\n' + current_indent + '  ' + nattrs
            else:
                if nattrs != '':
                    nattrs = '\n' + current_indent + '  ' + nattrs

            if c in elem_to_num:
                x = 'i="' + elem_to_num[c] + '"'
                f.write(current_indent)
                f.write('<e ' + x + ' n="' + enc_xml_a_v(c.name) + '" ' +
                        nattrs + '>\n')
            else:
                f.write(current_indent)
                f.write('<e n="' + enc_xml_a_v(c.name) + '" ' + nattrs + '>\n')

            groups = SGraph.groupea(c.outgoing)
            for ealist, deptype, ea_attrs in groups:
                elem_numbers = []
                for ea in ealist:
                    if ea.toElement in elem_to_num:
                        elem_numbers.append(elem_to_num[ea.toElement])
                    else:
                        sys.stderr.write('No numeric id for ' +
                                         ea.toElement.getPath() +
                                         '  dependency from ' +
                                         ea.fromElement.name + '\n')
                idrefs = ','.join(sorted(set(elem_numbers)))
                if idrefs:
                    # idrefs = ','.join(map(lambda x: str(x.toElement.num), g))
                    sorted_attrs = sorted(ea_attrs.items())
                    ea_attrs_str = ' '.join([
                        enc_xml_a_n(x[0]) + '="' + enc_xml_a_v(x[1]) + '"'
                        for x in sorted_attrs
                    ])
                    if deptype is None:
                        deptype = ''
                    f.write('  <r r="' + idrefs + '" t="' + deptype + '" ' +
                            ea_attrs_str + '/>\n')

            for cc in sorted(c.children, key=lambda x: x.name):
                dump_node(cc, elem_to_num, reclevel + 1)

            f.write(current_indent)
            f.write('</e>\n')

        for c in rootNode.children:
            dump_node(c, elem_to_num, 2)
        f.write('\n</elements>\n</model>\n')
        f.flush()
        if fname is not None:
            f.close()
        elif stdout:
            pass
        else:
            return f.getvalue()

    def to_deps(self, fname):
        if fname is not None:
            f = open(fname, 'w')
        else:
            f = sys.stdout
        withDependencies = True
        withDepDetails = True
        withAttributes = True
        printedNodes = {}

        autogeneratedAttributeNames = [
            'user_count', 'used_count', 'coupling', 'childcount'
        ]

        def encodeForDeps(s):
            if isinstance(s, str):
                return s.replace('\r\n', '<NEWLINE>').replace(
                    '\r', '<NEWLINE>').replace('\n', '<NEWLINE>')
            return str(s)

        if withAttributes:

            def handleElem(x):
                if self.totalModel is not None and self.totalModel != self:
                    tme = self.totalModel.getElement(x)
                    if tme is not None:
                        x = tme
                m = x.attrs
                p = None
                if m is not None:
                    sorted_attrs = sorted(list(m.items()))

                    did_something = False
                    for attrname, attrval in sorted_attrs:
                        if attrname == 'type':
                            continue
                        if attrname in autogeneratedAttributeNames:
                            continue
                        if p is None:
                            p = x.getPath()
                        f.write('@' + p + ':' + attrname + ':' +
                                encodeForDeps(attrval) + '\n')
                        did_something = True
                    if did_something:
                        printedNodes[x] = 1
                if x.getType() != '':
                    if p is None:
                        p = x.getPath()
                    if len(p) > 1:
                        f.write('@' + p + ':type:' +
                                encodeForDeps(x.getType()) + '\n')
                    printedNodes[x] = 1

            self.rootNode.traverseElements(handleElem)

        if withDependencies:

            def handleDeps(elem):
                for x in elem.outgoing:
                    from_ = x.getFromPath()
                    to = x.getToPath()
                    f.write(from_)
                    printedNodes[x.fromElement] = 1
                    f.write(':' + to)
                    printedNodes[x.toElement] = 1

                    if withDepDetails:
                        t = x.getType()
                        if t is not None and type != '':
                            f.write(':' + t + '\n')
                        else:
                            f.write(':\n')
                        m = x.getAttributes()

                        if m is not None:
                            for depattr, depattrval in list(m.items()):
                                if not depattr == 'type':
                                    f.write('@@' + depattr + ':' +
                                            str(depattrval) + '\n')
                    else:
                        f.write('\n')

            self.rootNode.traverseElements(handleDeps)

        def handleRemaining(elem):
            if elem not in printedNodes:
                path = elem.getPath()
                if path != '':
                    f.write(elem.getPath() + '\n')

        self.rootNode.traverseElements(handleRemaining)

        for k, v in list(self.metaAttrs.items()):
            f.write('@@@@' + k + ':' + v + '\n')
        for k, mmap in list(self.modelAttrs.items()):
            if isinstance(mmap, dict):
                for a, v in list(mmap.items()):
                    f.write('@@@' + k + ':' + a + ':' + v + '\n')
            else:
                f.write('@@@' + k + ': ' + mmap + '\n')
        f.flush()
        if f != sys.stdout:
            f.close()

    def produce_deps_tuples(self):
        withDependencies = True
        withAttributes = True
        printedNodes = {}

        autogeneratedAttributeNames = [
            'user_count', 'used_count', 'coupling', 'childcount'
        ]
        attrs = []
        deps = []

        if withAttributes:

            def handleElem(x):
                if self.totalModel is not None and self.totalModel != self:
                    tme = self.totalModel.getElement(x)
                    if tme is not None:
                        x = tme
                m = x.attrs
                if m is not None:
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

            def handleDeps(elem):
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

        orphan = []

        def handleRemaining(elem):
            if elem not in printedNodes:
                path = elem.getPath()
                if path != '':
                    orphan.append(path)

        self.rootNode.traverseElements(handleRemaining)
        return deps, attrs, orphan

    def calculate_model_stats(self):
        dependenciesCount = self.rootNode.getEACount()
        nodesCount = self.rootNode.getNodeCount()
        depTypeCounts = {}
        self.rootNode.getEATypeCounts(depTypeCounts)
        depToElemRatio = round(dependenciesCount / nodesCount * 100)
        return dependenciesCount, nodesCount, depTypeCounts, depToElemRatio

    def getElement(self, elem: SElement) -> Optional[SElement]:
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
        elems = list(reversed(elem.getPathAsList()))

        p = self.rootNode
        for i in range(len(elems)):
            s = elems[i]
            child = p.getChildByName(s)
            if child is not None:
                p = child
            else:
                return p.createElements(elems, i)
        return p

    @staticmethod
    def calculate_model_stats_delta(prev, stats):
        delta = None
        if prev is not None:
            deptype_counts_delta = {}
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

            delta = (stats[0] - prev[0], stats[1] - prev[1],
                     deptype_counts_delta, stats[3] - prev[3])
        return delta

    @staticmethod
    def parse_xml_or_zipped_xml(model_file_path,
                                type_rules=None,
                                ignored_attributes=None,
                                only_root=False):
        if isinstance(model_file_path, str) and '.xml.zip' in model_file_path:
            with open(model_file_path, 'rb') as filehandle:
                zfile = zipfile.ZipFile(filehandle)
                data = zfile.open('modelfile.xml', 'r')
                data = io.TextIOWrapper(data)
                zfile.close()
                m = SGraph.parse_xml(data, type_rules, ignored_attributes,
                                     only_root)
                m.set_model_path(model_file_path)
        else:
            m = SGraph.parse_xml(model_file_path, type_rules,
                                 ignored_attributes, only_root)
            m.set_model_path(model_file_path)
        return m

    @staticmethod
    def parse_xml(filename_or_stream,
                  type_rules=None,
                  ignored_attributes=None,
                  only_root=False):
        class SGraphXMLParser(xml.sax.handler.ContentHandler):
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
                self.rootNode = None
                self.currentRelation = None  # map string string
                self.currentElementOutgoingDeps = []  # elem assoc objs
                self.rootNode = SElement(None, '')
                self.buffer = ''

                self.acceptableAssocTypes = None
                self.ignoreAssocTypes = None
                self.ignored_attributes = ignored_attributes or []
                self.only_root = only_root

            def set_type_rules(self, type_rules):
                if type_rules is None:
                    self.acceptableAssocTypes = None
                    self.ignoreAssocTypes = None
                else:
                    for type_rule in type_rules:
                        type_rule = type_rule.strip()
                        if type_rule.strip().startswith('IGNORE '):
                            if self.ignoreAssocTypes is None:
                                self.ignoreAssocTypes = set()
                            self.ignoreAssocTypes.add(type_rule[7:].strip())
                        else:
                            if self.acceptableAssocTypes is None:
                                self.acceptableAssocTypes = set()
                            self.acceptableAssocTypes.add(type_rule)

            def startElement(self, qualifiedName, atts):

                if self.node % 5000 == 0 and self.node > 0:
                    # print(('parsing.. currently '+str(self.node)))
                    self.buffer = ''
                if qualifiedName == 'a':
                    name = atts.get('n')
                    value = atts.get('v')
                    if self.currentRelation is not None:
                        self.currentRelation[name] = value
                    else:
                        if self.currentElement is not None and len(
                                self.currentElementPath) > 0:
                            self.property += 1
                            if name not in self.ignored_attributes:
                                self.currentElement.addAttribute(name, value)
                        else:
                            print(('discarding ' + name + ' ' + value +
                                   ' name value pair'))

                elif qualifiedName == 'e':
                    name = atts.get('n')

                    if len(self.idstack) == 0:
                        e = SElement(self.rootNode, name)
                    else:
                        parent = self.elemStack[-1]
                        e = SElement(parent, name)
                    self.currentElement = e
                    self.idstack.append(name)
                    self.currentElementPath = '/' + '/'.join(self.idstack)
                    self.node += 1
                    self.elemStack.append(self.currentElement)

                    for aname, avalue in list(atts.items()):
                        if aname == 't' or aname == 'type':
                            e.setType(avalue)
                            self.property += 1
                        elif aname == 'i':
                            self.id_to_elem_map[avalue] = e
                        elif aname != 'n' and aname not in self.ignored_attributes:
                            e.addAttribute(aname, avalue)

                    if self.only_root:
                        raise ParsingIntentionallyAborted(
                            'Aborted intentionally')

                elif qualifiedName == 'r':
                    self.currentRelation = {}
                    referred = atts.get('r')
                    t = atts.get('t')
                    redirectEnabled = False
                    if not redirectEnabled:
                        self.link += 1
                        if ',' in referred:
                            for referred_ in [
                                    x for x in referred.split(',')
                                    if len(x) > 0
                            ]:
                                self.createReference(referred_, t)
                        else:
                            self.createReference(referred, t)
                    else:

                        self.createReference(referred, t)

                    for aname, avalue in list(atts.items()):
                        if len(aname) > 1:
                            self.currentRelation[aname] = avalue

            def characters(self, data):
                pass

            def endElement(self, name):
                if name == 'e':
                    self.idstack.pop()
                    self.elemStack.pop()
                    if self.elemStack:
                        self.currentElement = self.elemStack[-1]
                        path = '/' + '/'.join(self.idstack)
                        self.currentElementPath = path

                elif name == 'r':
                    if self.currentElementOutgoingDeps is not None:
                        for a in self.currentElementOutgoingDeps:
                            a.setAttrMap(self.currentRelation)
                        for x in self.currentElementOutgoingDeps:
                            self.currentElement.outgoing.append(x)
                        self.currentElementOutgoingDeps = None
                    self.currentRelation = None

            def createReference(self, i, t):
                if self.acceptableAssocTypes is None and self.ignoreAssocTypes is not None:
                    if t in self.ignoreAssocTypes:
                        return
                elif self.acceptableAssocTypes is None:
                    pass  # all is fine
                elif t in self.acceptableAssocTypes:
                    pass  # ok
                elif self.acceptableAssocTypes is not None and len(
                        self.acceptableAssocTypes) == 0:
                    # do not accept any deps
                    return
                else:
                    # no match
                    return

                dep = SElementAssociation(None, None, '', {})
                if self.currentElementOutgoingDeps is None:
                    self.currentElementOutgoingDeps = []
                if i == 0:
                    sys.stderr.write('zero as ref id\n')
                dep.fromElement = self.currentElement
                dep.toElement = i
                dep.deptype = t
                self.currentElementOutgoingDeps.append(dep)

            def translateReferences(self):
                stack = [self.rootNode]
                while stack:
                    elem = stack.pop(0)
                    for ea in elem.outgoing:
                        if ea.toElement in self.id_to_elem_map:
                            ea.toElement = self.id_to_elem_map[ea.toElement]
                            ea.toElement.incoming.append(ea)
                        else:
                            sys.stderr.write(
                                f'Error: unknown id {ea.toElement} n={elem.name}\n'
                            )
                            raise Exception(
                                f'Error: unknown id in input data: {ea.toElement}'
                            )

                    for child in elem.children:
                        stack.append(child)

        parser = xml.sax.make_parser()
        a = SGraphXMLParser()
        a.set_type_rules(type_rules)
        parser.setContentHandler(a)
        if isinstance(filename_or_stream, str):
            filepath = filename_or_stream
            if os.path.exists(filepath):
                try:
                    parser.parse(filepath)
                except ParsingIntentionallyAborted:
                    pass
            else:
                raise Exception('Cannot find file {}'.format(filepath))
        else:
            try:
                parser.parse(filename_or_stream)
            except ParsingIntentionallyAborted:
                pass

        a.translateReferences()
        egm = SGraph(a.rootNode)

        return egm

    @staticmethod
    def parse_deps(filename):
        with open(filename, errors='ignore') as fn:
            return SGraph.parse_deps_lines(fn)

    @staticmethod
    def parse_deps_lines(content):
        TAGLEN = len('<NEWLINE>')
        modelAttrs = {}
        metaAttrs = {}
        lastEA = None
        rootNode = SElement(None, '')
        egm = SGraph(rootNode)
        ignore = []
        lines = 0

        def correctId(i):
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
                                'Data format handling error: dep attr not handled properly. line='
                                + line + '\n')

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
    def groupea(eas):
        tuples = []
        easmap = {}
        for ea in eas:
            if ea.deptype is not None:
                k = str(ea.attrs) + ea.deptype
            else:
                k = str(ea.attrs)
            if k in easmap:
                easmap[k].append(ea)
            else:
                easmap[k] = [ea]

        for k, v in list(easmap.items()):
            tuples.append((v, v[0].deptype, v[0].attrs))

        return tuples

    def to_plantuml(self, fname):
        if fname is not None:
            f = open(fname, 'w')
        else:
            f = sys.stdout

        def plantuml_id(e):
            return e.getPath().replace('.', '_')[1:].replace('/', '.')

        def plantuml_deptype(assoc):
            if assoc.getType() == 'inherits':
                return '<!--', None
            elif assoc.getType() == 'implements':
                return '<!..', None
            # TODO Support also other types if needed?
            return '<--', assoc.getType()

        def plantuml_element_type(e):
            # TODO Check the rest of types
            if e.getType() == 'file' or e.getType() == 'class' or e.getType(
            ) == 'package':
                return e.getType()
            return 'component'

        def traverse_to_plantuml(e, level):
            # noinspection PyUnusedLocal
            indent = ''.join([' ' for _unused in range(level)])
            is_leaf = False
            if e.children is None or len(e.children) == 0:
                is_leaf = True
            else:
                f.write(indent + 'namespace ' + plantuml_id(e) + ' {\n')

            e_name = e.name.replace('.', '_')
            if is_leaf:
                f.write(indent + plantuml_element_type(e) + ' ' + e_name)
            if e.outgoing is not None:
                for assoc in e.outgoing:
                    d1, d2 = plantuml_deptype(assoc)
                    postfix = ''
                    if d2 is not None:
                        postfix = ' : ' + d2
                    used = plantuml_id(assoc.toElement)
                    f.write(indent + ' ' + used + ' ' + d1 + ' ' + e_name +
                            postfix + '\n')

            if not is_leaf:
                if e.children is not None:
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

    def calculate_graph_density(self, elempath, detail_level, external_elem):
        elems = []

        def traverse_until(elem, current_level, detail_level):
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
            traverse_until(e, e.getLevel(), detail_level)

        if len(elems) == 0:
            return 0

        assocs_between = set()
        for e in elems:
            assocs_between.update(find_assocs_between(e, e, elems))

        return len(assocs_between) / len(elems)

    def copy_ea_attrs_from_other_models(self, primary_model, secondary_model):
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
        def visit(a, elem_of_primary_model, elem_of_secondary_model):
            outgoing = list(a.outgoing)
            if elem_of_primary_model:
                for ea in elem_of_primary_model.outgoing:
                    corresponding_ea = SElementAssociation.match_ea_from_other_sgraph(
                        ea, outgoing)
                    if corresponding_ea:
                        outgoing.remove(corresponding_ea)
                        corresponding_ea.attrs.update(ea.attrs)
            if elem_of_secondary_model:
                for ea in elem_of_secondary_model.outgoing:
                    corresponding_ea = SElementAssociation.match_ea_from_other_sgraph(
                        ea, outgoing)
                    if corresponding_ea:
                        outgoing.remove(corresponding_ea)
                        corresponding_ea.attrs.update(ea.attrs)

        SGraph.recurse_three_models(self.rootNode, primary_model.rootNode,
                                    secondary_model.rootNode, visit)

    @staticmethod
    def recurse_three_models(elem_a, elem_b, elem_c, visitor_func):
        visitor_func(elem_a, elem_b, elem_c)
        for child_a in elem_a.children:
            child_b = elem_b.getChildByName(
                child_a.name) if elem_b is not None else None
            child_c = elem_c.getChildByName(
                child_a.name) if elem_c is not None else None
            SGraph.recurse_three_models(child_a, child_b, child_c,
                                        visitor_func)

    def set_model_path(self, filepath):
        self.modelAttrs['model_path'] = filepath


class Counter():
    def __init__(self):
        self.i = 1

    def now(self):
        self.i += 1
        return self.i
