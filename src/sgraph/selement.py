import sys
from typing import Optional, Dict

from sgraph.selementmergedexception import SElementMergedException
from sgraph.selementassociation import SElementAssociation

DEBUG = False


class SElement:
    __slots__ = 'name', 'parent', 'children', 'childrenDict', 'outgoing', 'incoming', 'attrs', \
                'human_readable_name'

    def __init__(self, parent: Optional['SElement'], name: str):
        if name == '':
            # sys.stderr.write('Creating with empty name\n')
            pass
        if '/' in name:
            name = name.replace('/', '__slash__')

        if self == parent:
            raise Exception('Self loop in model\n')

        self.name = name
        self.human_readable_name = ''
        self.parent = None  # type: Optional[SElement]
        if parent is not None:
            self.parent = parent
            if self.name not in self.parent.childrenDict:
                self.parent.children.append(self)
                self.parent.childrenDict[self.name] = self
            else:
                if DEBUG:
                    raise Exception(
                        'Error: overlapping elements related to {} under {}, types: '
                        '{} and {}'.format(
                            self.name, self.parent.getPath(), '<not known>',
                            self.parent.childrenDict[self.name].getType()))
                else:
                    raise SElementMergedException(
                        'Element {} tried to be merged with an existing element '
                        'under same parent={}'.format(name, parent.getPath()))
        else:
            self.parent = None

        self.children = []
        self.childrenDict = {}
        self.outgoing = []
        self.incoming = []
        self.attrs = {}
        # self.num = '0'

    def addChild(self, child: 'SElement'):
        """
        Add child, but if there is an overlapping element, merge instead and return merged element.
        :param child: the child to be added.
        :return: None or the element where the child has been merged with (differs from child)
        """
        if child == self:
            sys.stderr.write('Error with data model loop\n')
            raise Exception('Aborting due to addChild self != child violation')
        if child.name not in self.childrenDict:
            self.children.append(child)
            self.childrenDict[child.name] = child
        else:
            if DEBUG:
                raise Exception(
                    'Error: overlapping elements related to {} under {}, types: {} '
                    'and {}'.format(child.name, self.getPath(),
                                    child.getType(),
                                    self.childrenDict[child.name].getType()))
            else:
                self.childrenDict[child.name].merge(child)
                return self.childrenDict[child.name]

        child.parent = self

    def addChildIgnoreWithSameName(self, child, elemWithSameName):
        """
        Add child, but if there is an overlapping element, merge instead and return merged element.
        Overwrite is allowed for the elemWithSameName

        :param child: the child to be added
        :param elemWithSameName: Overwrite allowed for this element.
        :return:
        """
        if child == self:
            sys.stderr.write('Error with data model loop\n')
            raise Exception('Aborting due to addChild self != child violation')
        if child.name not in self.childrenDict:
            self.children.append(child)
            self.childrenDict[child.name] = child
        else:
            if self.childrenDict[child.name] == elemWithSameName:
                self.children.append(child)
                self.childrenDict[child.name] = child
                child.parent = self
                return child
            else:
                if DEBUG:
                    raise Exception(
                        'Error: overlapping elements related to {} under {}, types: {} and {}'
                        .format(child.name, self.getPath(), child.getType(),
                                self.childrenDict[child.name].getType()))
                else:
                    self.childrenDict[child.name].merge(child)
                    return self.childrenDict[child.name]
        child.parent = self

    def addAttribute(self, a, v):
        self.attrs[a] = v

    def enclosingFilenameEndswith(self, postfix):
        e = self
        while e.parent is not None:
            if e.name.endswith(postfix):
                return True
            else:
                e = e.parent
        return False

    def cumulateAttribute(self, a, v):
        if a not in self.attrs:
            self.attrs[a] = str(v)
        else:
            x = float(self.attrs[a]) + (v * 1.0)
            self.attrs[a] = str(x)

    def cumulateListAttribute(self, a, v, avoid_duplicates):
        if a not in self.attrs:
            self.attrs[a] = str(v)
        else:
            if not avoid_duplicates or v not in self.attrs[a]:
                self.attrs[a] += ';' + v

    def cumulateIntAttribute(self, a, v):
        if a not in self.attrs:
            self.attrs[a] = v
        else:
            self.attrs[a] += v

    def traverseElements(self, visit):
        visit(self)
        for c in self.children:
            c.traverseElements(visit)

    def traverseIncoming(self, visited):
        for incoming_element in set(self.incoming) - visited:
            visited.add(incoming_element.fromElement)
            incoming_element.fromElement.traverseIncoming(visited)
        return visited

    def removeElements(self, path):
        splitted = path.split('/')
        self.removeElementsWithList(splitted)

    def removeElementsWithList(self, splitted):
        if self.name == splitted[0]:
            if len(splitted) == 1:
                self.remove()
            else:
                for x in self.children:
                    x.removeElementsWithList(splitted[1:])

    def detachChild(self, elem):
        """Always do this first before addChild"""
        elem.parent = None
        self.children.remove(elem)
        if elem.name in self.childrenDict:
            self.childrenDict.pop(elem.name)
        else:
            sys.stderr.write(
                'Error: Probably duplicated element {} under {}'.format(
                    elem.name, self.getPath()))

    def remove(self, leaveParentUntouched=False):
        if not leaveParentUntouched:
            if self.parent is not None:
                self.parent.detachChild(self)

        for ea in self.outgoing:
            ea.toElement.incoming.remove(ea)
        self.outgoing = []

        for ea in self.incoming:
            ea.fromElement.outgoing.remove(ea)

        self.incoming = []

        for c in self.children:
            c.remove(True)
        self.children = []
        self.childrenDict = {}

    def update_children_dict(self):
        self.childrenDict.clear()
        for c in self.children:
            self.childrenDict[c.name] = c

    def getNodeCount(self):
        i = 1
        for x in self.children:
            i += x.getNodeCount()

        return i

    def getEACount(self):

        i = len(self.outgoing)
        for x in self.children:
            i += x.getEACount()

        return i

    def getEATypes(self, theSet):

        for ea in self.outgoing:
            theSet.add(ea.deptype)

        for x in self.children:
            x.getEATypes(theSet)

    def getEATypeCounts(self, d: Dict[str, int]):
        for ea in self.outgoing:
            if ea.deptype not in d:
                d[ea.deptype] = 1
            else:
                d[ea.deptype] += 1

        for x in self.children:
            x.getEATypeCounts(d)

    def getPath(self) -> str:
        p = self.parent
        pathparts = [self.name]
        while p is not None and p.parent != p:
            pathparts.append(p.name)
            p = p.parent
        pathparts.reverse()
        return '/'.join(pathparts)

    def getElementsByNameOnLevel(self, name, level, current_level=0):
        out = []
        if current_level == level - 1:
            if name in self.childrenDict:
                out.append(self.childrenDict[name])

                # for c in self.children:
                #    if c.name == name:
                #        out.append(c)
        elif current_level < level:
            for c in self.children:
                out += c.getElementsByNameOnLevel(name, level,
                                                  current_level + 1)
        return out

    def recurseIncomingDependencies(self,
                                    elemlist,
                                    assoclist,
                                    outside_level=0):
        for c in self.incoming:
            if outside_level == 0 or c.fromElement.getAncestorOfLevel(
                    outside_level) != c.toElement.getAncestorOfLevel(
                        outside_level):
                elemlist.append(c.fromElement)
                if assoclist is not None:
                    assoclist.append(c)
        for c in self.children:
            c.recurseIncomingDependencies(elemlist, assoclist)

    def getAllUsers(self, outside_level=0):
        elems = []
        self.recurseIncomingDependencies(elems, None, outside_level)
        return set(elems)

    def getAncestorOfLevel(self, level):
        x = self.getLevel()
        delta = x - level
        ancestor = self
        while delta > 0:
            ancestor = ancestor.parent
            delta -= 1
        return ancestor

    def getAncestorOfType(self, t):
        """
        Return ancestor that has matching type.
        :param t: type (str)
        :return: SElement or None
        """
        if self.typeEquals(t):
            return self
        ancestor = self
        while ancestor is not None and ancestor.parent is not None:
            ancestor = ancestor.parent
            if ancestor.typeEquals(t):
                return ancestor
        return None

    def getAncestorOfTypes(self, types):
        """
        Return ancestor that has matching type.
        :param types: type list or set
        :return: SElement or None
        """
        for t in types:
            if self.typeEquals(t):
                return self
        ancestor = self
        while ancestor is not None and ancestor.parent is not None:
            ancestor = ancestor.parent
            for t in types:
                if ancestor.typeEquals(t):
                    return ancestor
        return None

    def getAncestors(self):
        ancestor = self
        ancestors = []
        while ancestor is not None and ancestor.parent is not None:
            ancestor = ancestor.parent
            ancestors.append(ancestor)
        return ancestors

    def isDescendantOf(self, anc):
        if self == anc:
            return False
        p = self.parent
        while p is not None:
            if p == anc:
                return True
            else:
                p = p.parent
        return False

    def getRoot(self):
        p = self
        while p.parent is not None:
            p = p.parent
        return p

    def getLevel(self) -> int:
        e = self.parent
        level = 0
        while e is not None:
            e = e.parent
            level += 1
        return level

    def getChildByName(self, n):
        if n in self.childrenDict:
            return self.childrenDict[n]

        # for c in self.children:
        #    if c.name == n:
        #        return c
        return None

    def findElement(self, n):
        if n.startswith('/'):
            # sys.stderr.write('invalid id (2): '+n+'\n')
            n = n[1:]

        if '/' not in n:
            return self.getChildByName(n)
        else:
            pos = n.find('/')
            root = n[0:pos]
            if len(self.children) == 0:
                return None
            else:
                child = self.getChildByName(root)
                if child is not None:
                    return child.findElement(n[pos + 1:])
                else:
                    return None

    def createOrGetElement(self, n: str):
        if n.startswith('/'):
            # sys.stderr.write('invalid id (1): '+n+'\n')
            n = n[1:]

        if '/' not in n:
            child = self.getChildByName(n)
            if child is not None:
                return child
            # print 'FOO',n
            return SElement(self, n)
        else:
            pos = n.find('/')
            root = n[0:pos]
            if len(self.children) == 0:
                return self.createElementChain(n)
            else:
                child = self.getChildByName(root)
                if child is not None:
                    return child.createOrGetElement(n[pos + 1:])
                else:
                    return self.createElementChain(n)

    def createElementChain(self, elemid):
        # print 'FOO2',elemid
        current = self
        for n in elemid.split('/'):
            current = SElement(current, n)
        return current

    def hasSiblingsRecursive(self):
        if self.parent is None:
            return False
        found = -1
        for i in range(len(self.parent.children)):
            if self == self.parent.children[i]:
                found = i
                break
        i = found + 1
        if i < len(self.parent.children):
            return True
        else:
            return self.parent.hasSiblingsRecursive()

    def setType(self, t):
        if 'type' in self.attrs and self.attrs['type'] == 'repository':
            if t == 'dir':
                # Do not overwrite existing type=repository, e.g. with less meaningful "dir" etc.
                # This happens e.g. when some analyzer collects dir elements to the model and it
                # already has the "repository" marked for the same directory (done in the
                # beginning of the analysis).
                pass
            else:
                # Unpredicted case, so let it go..
                self.attrs['type'] = t
        else:
            self.attrs['type'] = t

    def getType(self) -> str:
        if 'type' in self.attrs:
            return self.attrs['type']
        return ''

    def getNextSiblingRecursive(self):
        if self.parent is None:
            return None
        c = self.parent.children
        i = c.index(self) + 1
        if i < len(c):
            return c[i]
        else:
            return self.parent.getNextSiblingRecursive()

    def verify(self, elems, i):
        # if i % 1000 == 0:
        #    print(i)
        if self.children is not None:
            elems_by_name = {}
            for c in self.children:
                i += 1
                if c.name in elems_by_name:
                    raise Exception('Duplicate element? ' + c.getPath())
                elems_by_name[c.name] = c

                if c.parent != self:
                    print('Problem with element parent self ref..')
                    print(self.getPath())
                    print(c.parent.getPath())
                    raise Exception('Error: broken model related to elem ' +
                                    c.name + ' under ' + c.parent.name + '\n')

                if c in elems:
                    print('Problem with element path')
                    print(c.parent.parent.getPath())
                    print(len(self.children))
                    raise Exception('Error: broken model related to elem ' +
                                    c.name + ' under ' + c.parent.name + '\n')
                else:
                    elems.add(c)
                    c.verify(elems, i)
        return None

    def merge(self, other, ignore_type=False, ignore_attrs=False):
        """
        Merge self with other, leaving other to irrelevancy.
        :param other: SElement to be merged into self
        :return:
        """
        # print('Merge', other.getPath())
        for c in list(other.children):
            other.detachChild(c)
            # TODO Have some logic here to do merge correctly if overlapping children exists?
            self.addChild(c)

        current_deps = {}
        for ea in self.outgoing:
            current_deps.setdefault(ea.toElement, []).append(ea.deptype)

        # TODO This could be faster if assocs would be recycled instead of throw away + create new

        for ea in list(other.outgoing):
            if ea.toElement in current_deps and ea.deptype in current_deps[
                    ea.toElement]:
                # already exists
                pass
            elif self != ea.toElement:
                newEa = SElementAssociation(self, ea.toElement, ea.deptype,
                                            ea.attrs)
                newEa.initElems()

        for ea in list(other.outgoing):
            ea.remove()

        current_deps = {}
        for ea in self.incoming:
            current_deps.setdefault(ea.fromElement, []).append(ea.deptype)

        for ea in list(other.incoming):
            if ea.fromElement in current_deps and ea.deptype in current_deps[
                    ea.fromElement]:
                # already exists
                pass
            elif ea.fromElement != self:
                newEa = SElementAssociation(ea.fromElement, self, ea.deptype,
                                            ea.attrs)
                newEa.initElems()

        for ea in list(other.incoming):
            ea.remove()

        for k, v in other.attrs.items():
            if not ignore_attrs and k != 'type':
                if k not in self.attrs:
                    self.attrs[k] = v
                else:
                    if self.attrs[k] != v:
                        if isinstance(v, list):
                            for item in v:
                                if item not in self.attrs[k]:
                                    self.attrs[k].append(item)
                        else:
                            # TODO Later inspect these when doing func/class relocation
                            self.attrs[k] = str(
                                self.attrs[k]) + ' -merged- ' + str(v)
                    else:
                        pass

            elif not ignore_type and k == 'type':
                if v != '' and not self.typeEquals(v):
                    self.setType(self.getType() + '_' + v)

        if other.parent is not None:
            other.parent.detachChild(other)
            other.parent = None

    def typeEquals(self, t):
        if 'type' in self.attrs:
            return self.attrs['type'] == t
        else:
            if t == '':
                # Both types missing or empty
                return True
        return False

    def hasType(self):
        return 'type' in self.attrs and self.attrs['type'] != ''

    def getPathAsList(self):
        a = list()
        a.append(self.name)
        p = self.parent
        while p is not None and p.parent is not None:
            a.append(p.name)
            p = p.parent
        return a

    def createElements(self, elems, startFrom):
        p = self
        for i in range(startFrom, len(elems)):
            p = SElement(p, elems[i])
        return p

    def equalsAttributes(self, e) -> bool:
        if self.attrs is not None and e.attrs is not None:
            return self.attrs == e.attrs
        elif self.attrs is not None or e.attrs is not None:
            return False
        return True

    def createAttributesFrom(self, attrs):
        if attrs is not None and len(attrs) > 0:
            self.attrs.update(attrs)

    def sibling_with(self, elem: 'SElement') -> bool:
        return self.parent == elem.parent

    def isExternalElement(self):
        for projlevel in self.getRoot().children:
            for c in projlevel.children:
                if c.name == 'External':
                    return self.isDescendantOf(c)
        return False

    def removeDescendantsIf(self, checker):
        for child in list(self.children):
            if checker(child):
                child.remove()
        for child in self.children:
            child.removeDescendantsIf(checker)

    def getDescendants(self, descendants_list):
        for child in self.children:
            descendants_list.append(child)
            child.getDescendants(descendants_list)

    def getMaxDepth(self, cur_depth: int) -> int:
        if not self.children:
            return cur_depth
        depth = 0
        for e in self.children:
            depth = max(e.getMaxDepth(cur_depth + 1), depth)
        if depth == 0:
            return cur_depth
        return depth

    def clean_duplicate_associations(self):
        if self.outgoing:
            ea_hashes = set()
            dupes = []
            for ea in self.outgoing:
                num = ea.getHashNum()
                c = num
                if c in ea_hashes:
                    dupes.append(ea)
                else:
                    ea_hashes.add(c)
            """
            For debugging purposes:
            for d in dupes:
                print('Removing dupe: ' + str(d))
                d.remove()
            if dupes:
                for ea in self.outgoing:
                    print('Preserving: ' + str(ea))
                print('\n\n')
            """

        for child in self.children:
            child.clean_duplicate_associations()

    def elem_location_matches(self, elem):
        if self.parent and elem.parent:
            if self.parent.name == elem.parent.name:
                return self.parent.elem_location_matches(elem.parent)
            else:
                return False
        elif self.parent:
            return False
        elif elem.parent:
            return False
        else:
            # self.parent is None and elem.parent is None
            return True


class ElementIterator:
    def __init__(self, elem):
        self.current = elem

    def hasNext(self):
        if len(self.current.children) > 0:
            return True
        else:
            if self.current.hasSiblingsRecursive():
                return True
        return False

    def __next__(self):
        if len(self.current.children) > 0:
            self.current = self.current.children[0]
            return self.current
        else:
            if self.current.parent is not None:
                e = self.current.getNextSiblingRecursive()
                if e is not None:
                    self.current = e
                    return e
                else:
                    return None
            else:
                return None
