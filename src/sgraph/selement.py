from __future__ import annotations

import sys
from typing import Callable, Optional

from sgraph.exceptions import SElementMergedException
from sgraph.selementassociation import SElementAssociation

DEBUG = False


class SElement:
    __slots__ = 'name', 'parent', 'children', 'childrenDict', 'outgoing', 'incoming', 'attrs', \
        'human_readable_name'

    name: str
    parent: Optional["SElement"]
    children: list["SElement"]
    childrenDict: dict[str, "SElement"]
    outgoing: list["SElementAssociation"]
    incoming: list["SElementAssociation"]
    attrs: dict[str, str | int | list[str]]
    human_readable_name: str

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
        self.parent = None
        if parent is not None:
            self.parent = parent
            if self.name not in self.parent.childrenDict:
                self.parent.children.append(self)
                self.parent.childrenDict[self.name] = self
            else:
                if DEBUG:
                    raise Exception('Error: overlapping elements related to {} under {}, types: '
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

    def __str__(self):
        children_info = str(len(self.children)) + 'C'
        inbound_info = str(len(self.incoming)) + 'I'
        outbound_info = str(len(self.outgoing)) + 'O'
        if self.parent is not None:
            return f'{self.name} ({self.getType()}) under {self.parent.name} {children_info} {outbound_info} {inbound_info}'
        else:
            return f'{self.name} ({self.getType()}) {children_info} {outbound_info} {inbound_info}'

    def addChild(self, child: "SElement"):
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
                raise Exception('Error: overlapping elements related to {} under {}, types: {} '
                                'and {}'.format(child.name, self.getPath(), child.getType(),
                                                self.childrenDict[child.name].getType()))
            else:
                self.childrenDict[child.name].merge(child)
                return self.childrenDict[child.name]

        child.parent = self

    def addChildIgnoreWithSameName(self, child: "SElement", elemWithSameName: "SElement"):
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

    def addAttribute(self, a: str, v: str | list[str]):
        self.attrs[a] = v

    def enclosingFilenameEndswith(self, postfix: str):
        e = self
        while e.parent is not None:
            if e.name.endswith(postfix):
                return True
            else:
                e = e.parent
        return False

    def cumulateAttribute(self, a: str, v: float):
        if a not in self.attrs:
            self.attrs[a] = str(v)
        else:
            attr = self.attrs[a]
            if isinstance(attr, list):
                raise ValueError(f"Attribute {a} is a list")
            x = float(attr) + (v * 1.0)
            self.attrs[a] = str(x)

    def cumulateListAttribute(self, a: str, v: str, avoid_duplicates: bool):
        if a not in self.attrs:
            self.attrs[a] = str(v)
        else:
            attr = self.attrs[a]
            if not isinstance(attr, str):
                raise ValueError(f"Attribute {a} is not a string")
            if not avoid_duplicates or v not in attr:
                attr += ';' + v
                self.attrs[a] = attr

    def cumulateIntAttribute(self, a: str, v: int):
        if a not in self.attrs:
            self.attrs[a] = v
        else:
            attr = self.attrs[a]
            if not isinstance(attr, int):
                raise ValueError(f"Attribute {a} is not an integer")
            attr += v
            self.attrs[a] = attr

    def traverseElements(self, visit: Callable[["SElement"], None]):
        visit(self)
        for c in self.children:
            c.traverseElements(visit)

    def traverseIncoming(self, visited: set["SElement"]):
        #? Was this fixed correctly?
        for incoming_element in self.incoming:
            if incoming_element.fromElement in visited:
                continue
            visited.add(incoming_element.fromElement)
            incoming_element.fromElement.traverseIncoming(visited)
        return visited

    def removeElements(self, path: str):
        splitted = path.split('/')
        self.removeElementsWithList(splitted)

    def removeElementsWithList(self, splitted: list[str]):
        if self.name == splitted[0]:
            if len(splitted) == 1:
                self.remove()
            else:
                for x in self.children:
                    x.removeElementsWithList(splitted[1:])

    def detachChild(self, elem: "SElement"):
        """Always do this first before addChild"""
        elem.parent = None
        self.children.remove(elem)
        if elem.name in self.childrenDict:
            self.childrenDict.pop(elem.name)
        else:
            sys.stderr.write('Error: Probably duplicated element {} under {}'.format(
                elem.name, self.getPath()))

    def remove(self, leaveParentUntouched: bool = False):
        if not leaveParentUntouched:
            if self.parent is not None:
                self.parent.detachChild(self)

        for association in list(self.outgoing):
            association.remove()

        self.outgoing.clear()

        for association in list(self.incoming):
            association.remove()

        self.incoming.clear()

        for c in self.children:
            c.remove(True)
        self.children.clear()
        self.childrenDict.clear()

    def update_children_dict(self):
        self.childrenDict.clear()
        for c in self.children:
            self.childrenDict[c.name] = c

    def getNodeCount(self) -> int:
        i = 1
        for x in self.children:
            i += x.getNodeCount()

        return i

    def getEACount(self) -> int:
        i = len(self.outgoing)
        for x in self.children:
            i += x.getEACount()

        return i

    def getEATypes(self, theSet: set[str]):

        for association in self.outgoing:
            theSet.add(association.deptype)

        for x in self.children:
            x.getEATypes(theSet)

    def getEATypeCounts(self, d: dict[str, int]):
        for association in self.outgoing:
            if association.deptype not in d:
                d[association.deptype] = 1
            else:
                d[association.deptype] += 1

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

    def getElementsByNameOnLevel(
        self,
        name: str,
        level: int,
        current_level: int = 0,
    ) -> list["SElement"]:
        out: list[SElement] = []
        if current_level == level - 1:
            if name in self.childrenDict:
                out.append(self.childrenDict[name])

                # for c in self.children:
                #    if c.name == name:
                #        out.append(c)
        elif current_level < level:
            for c in self.children:
                out += c.getElementsByNameOnLevel(name, level, current_level + 1)
        return out

    def recurseIncomingDependencies(
        self,
        elemlist: list["SElement"],
        assoclist: list[SElementAssociation] | None,
        outside_level: int = 0,
    ):
        for c in self.incoming:
            if outside_level == 0 or c.fromElement.getAncestorOfLevel(
                    outside_level) != c.toElement.getAncestorOfLevel(outside_level):
                elemlist.append(c.fromElement)
                if assoclist is not None:
                    assoclist.append(c)
        for c in self.children:
            #? Should outside_level be passed?
            c.recurseIncomingDependencies(elemlist, assoclist)

    def getAllUsers(self, outside_level: int = 0) -> set["SElement"]:
        elems: list["SElement"] = []
        self.recurseIncomingDependencies(elems, None, outside_level)
        return set(elems)

    def getAncestorOfLevel(self, level: int) -> "SElement | None":
        x = self.getLevel()
        delta = x - level
        ancestor = self
        while delta > 0 and ancestor is not None:
            ancestor = ancestor.parent
            delta -= 1
        return ancestor

    def getAncestorOfType(self, t: str) -> "SElement | None":
        """
        Return ancestor that has matching type.
        :param t: type (str)
        :return: SElement or None
        """
        if self.typeEquals(t):
            return self
        ancestor = self
        while ancestor.parent is not None:
            ancestor = ancestor.parent
            if ancestor.typeEquals(t):
                return ancestor
        return None

    def getAncestorOfTypes(self, types: list[str] | set[str]) -> "SElement | None":
        """
        Return ancestor that has matching type.
        :param types: type list or set
        :return: SElement or None
        """
        for t in types:
            if self.typeEquals(t):
                return self
        ancestor = self
        while ancestor.parent is not None:
            ancestor = ancestor.parent
            for t in types:
                if ancestor.typeEquals(t):
                    return ancestor
        return None

    def getAncestors(self) -> list["SElement"]:
        ancestor: SElement | None = self
        ancestors: list[SElement] = []
        while ancestor.parent is not None:
            ancestor = ancestor.parent
            ancestors.append(ancestor)
        return ancestors

    def isDescendantOf(self, anc: "SElement"):
        if self == anc:
            return False
        p = self.parent
        while p is not None:
            if p == anc:
                return True
            else:
                p = p.parent
        return False

    def getRoot(self) -> "SElement":
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

    def getChildByName(self, n: str):
        if n in self.childrenDict:
            return self.childrenDict[n]

        # for c in self.children:
        #    if c.name == n:
        #        return c
        return None

    def findElement(self, n: str) -> "SElement | None":
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

    def createOrGetElement(self, n: str) -> "SElement":
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

    def createElementChain(self, elemid: str) -> "SElement":
        # print 'FOO2',elemid
        current = self
        for n in elemid.split('/'):
            current = SElement(current, n)
        return current

    def hasSiblingsRecursive(self) -> bool:
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

    def setType(self, t: str):
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
            elem_type = self.attrs['type']
            if not isinstance(elem_type, str):
                raise ValueError(f"Element attribute 'type' is not a string: {elem_type}")
            return elem_type
        return ''

    def getNextSiblingRecursive(self) -> "SElement | None":
        if self.parent is None:
            return None
        c = self.parent.children
        i = c.index(self) + 1
        if i < len(c):
            return c[i]
        else:
            return self.parent.getNextSiblingRecursive()

    def verify(self, elems: set["SElement"], i: int):
        # if i % 1000 == 0:
        #    print(i)
        elems_by_name = {}
        for c in self.children:
            i += 1
            if c.name in elems_by_name:
                raise Exception('Duplicate element? ' + c.getPath())
            elems_by_name[c.name] = c

            if not c.parent or c.parent != self:
                print('Problem with element parent self ref..')
                print(self.getPath())
                if self.parent is not None:
                    print(self.parent.getPath())
                else:
                    print('No parent?')
                raise Exception('Error: broken model related to elem ' + c.name + ' under ' +
                                c.parent.name if c.parent is not None else 'no parent' + '\n')

            if c in elems:
                print('Problem with element path')
                print(c.parent.parent.getPath() if c.parent.parent else 'no parent')
                print(len(self.children))
                raise Exception('Error: broken model related to elem ' + c.name + ' under ' +
                                c.parent.name + '\n')
            else:
                elems.add(c)
                c.verify(elems, i)
        return None

    def merge(self, other: "SElement", ignore_type: bool = False, ignore_attrs: bool = False):
        """
        Merge self with other, leaving other to irrelevancy.
        :param ignore_attrs: If True, ignore attributes
        :param ignore_type: If True, ignore type
        :param other: SElement to be merged into self
        :return:
        """
        # print('Merge', other.getPath())
        for c in list(other.children):
            other.detachChild(c)
            # TODO Have some logic here to do merge correctly if overlapping children exists?
            self.addChild(c)

        current_deps: dict["SElement", list[str]] = {}
        for association in self.outgoing:
            current_deps.setdefault(association.toElement, []).append(association.deptype)

        # TODO This could be faster if assocs would be recycled instead of throw away + create new

        for association in list(other.outgoing):
            if association.toElement in current_deps and association.deptype in current_deps[
                    association.toElement]:
                # already exists
                pass
            elif self != association.toElement:
                newEa = SElementAssociation(self, association.toElement, association.deptype,
                                            association.attrs)
                newEa.initElems()

        for association in list(other.outgoing):
            association.remove()

        current_deps = {}
        for association in self.incoming:
            current_deps.setdefault(association.fromElement, []).append(association.deptype)

        for association in list(other.incoming):
            if association.fromElement in current_deps and association.deptype in current_deps[
                    association.fromElement]:
                # already exists
                pass
            elif association.fromElement != self:
                newEa = SElementAssociation(association.fromElement, self, association.deptype,
                                            association.attrs)
                newEa.initElems()

        for association in list(other.incoming):
            association.remove()

        for k, v in other.attrs.items():
            if not ignore_attrs and k != 'type':
                if k not in self.attrs:
                    self.attrs[k] = v
                else:
                    attr = self.attrs[k]
                    if attr != v:
                        if isinstance(v, list):
                            if not isinstance(attr, list):
                                raise ValueError(
                                    f"Attribute '{k}' is expected to be a list but is not: {attr}")
                            for item in v:
                                if item not in attr:
                                    attr.append(item)
                            self.attrs[k] = attr
                        else:
                            # TODO Later inspect these when doing func/class relocation
                            self.attrs[k] = str(self.attrs[k]) + ' -merged- ' + str(v)
                    else:
                        pass

            elif not ignore_type and k == 'type':
                if not isinstance(v, str):
                    raise ValueError(f"Element attribute 'type' is not a string: {v}")
                if v != '' and not self.typeEquals(v):
                    self.setType(self.getType() + '_' + v)

        if other.parent is not None:
            other.parent.detachChild(other)
            other.parent = None

    def typeEquals(self, t: str) -> bool:
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
        ancestor_names_ordered: list[str] = []
        p = self
        while p:
            ancestor_names_ordered.append(p.name)
            p = p.parent
        if ancestor_names_ordered:
            ancestor_names_ordered.pop()
        return ancestor_names_ordered

    def get_ancestor_names_list(self):
        ancestor_names_ordered: list[str] = []
        p = self
        while p:
            ancestor_names_ordered.insert(0, p.name)
            p = p.parent
        if ancestor_names_ordered:
            ancestor_names_ordered.pop(0)
        return ancestor_names_ordered

    def createElements(self, elems: list[str], startFrom: int):
        p: SElement = self
        for i in range(startFrom, len(elems)):
            p = SElement(p, elems[i])
        return p

    def equalsAttributes(self, e: "SElement") -> bool:
        return self.attrs == e.attrs

    def createAttributesFrom(self, attrs: dict[str, str | int | list[str]]):
        if len(attrs) > 0:
            self.attrs.update(attrs)

    def sibling_with(self, elem: "SElement") -> bool:
        return self.parent == elem.parent

    def isExternalElement(self):
        for projlevel in self.getRoot().children:
            for c in projlevel.children:
                if c.name == 'External':
                    return self.isDescendantOf(c)
        return False

    def removeDescendantsIf(self, checker: Callable[["SElement"], bool]):
        for child in list(self.children):
            if checker(child):
                child.remove()
        for child in self.children:
            child.removeDescendantsIf(checker)

    def getDescendants(self, descendants_list: list["SElement"]):
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
            ea_hashes: set[int] = set()
            dupes: list[SElementAssociation] = []
            for association in self.outgoing:
                num = association.getHashNum()
                c = num
                if c in ea_hashes:
                    dupes.append(association)
                else:
                    ea_hashes.add(c)
            """
            For debugging purposes:
            for d in dupes:
                print('Removing dupe: ' + str(d))
                d.remove()
            if dupes:
                for association in self.outgoing:
                    print('Preserving: ' + str(association))
                print('\n\n')
            """

        for child in self.children:
            child.clean_duplicate_associations()

    def elem_location_matches(self, elem: "SElement") -> bool:
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

    def create_or_get_element(self, n: str) -> tuple["SElement", bool]:
        if n.startswith('/'):
            # sys.stderr.write('invalid id (1): '+n+'\n')
            n = n[1:]

        if '/' not in n:
            child = self.getChildByName(n)
            if child is not None:
                return child, False
            # print 'FOO',n
            return SElement(self, n), True
        else:
            pos = n.find('/')
            root = n[0:pos]
            if len(self.children) == 0:
                return self.createElementChain(n), True
            else:
                child = self.getChildByName(root)
                if child is not None:
                    return child.create_or_get_element(n[pos + 1:])
                else:
                    return self.createElementChain(n), True

    def rename(self, new_name: str):
        self.parent.childrenDict.pop(self.name)
        self.name = new_name
        self.parent.childrenDict[new_name] = self


class ElementIterator:
    current: SElement

    def __init__(self, elem: SElement):
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
