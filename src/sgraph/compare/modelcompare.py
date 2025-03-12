from __future__ import annotations

import sys

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.compare.attributecomparison import compare_attrs
from sgraph.compare.comparegraphattrs import CompareGraphAttrs
from sgraph.compare.compareutils import tag_change_count, debunk_uniqueness
from sgraph.compare.renamedetector import RenameDetector



class ModelCompare:
    def __init__(self):
        pass

    def compare(self, path1: str, path2: str):
        model1 = SGraph.parse_xml_or_zipped_xml(path1)
        model2 = SGraph.parse_xml_or_zipped_xml(path2)
        return self.compareModels(model1, model2)

    def compareModels(self, model1: SGraph, model2: SGraph, rename_detection: bool = False):
        rootNode = SElement(None, '')
        compareModel = SGraph(rootNode)
        createdDeps: list[SElementAssociation] = []
        removedDeps: list[SElementAssociation] = []

        # If there is already a attr_temporary.csv that has been "spoiling" the compare,
        # by introducing some removed elements to the B model that should not be there..
        model2.rootNode.removeDescendantsIf(
            lambda x: 'compare' in x.attrs and x.attrs['compare'] == 'removed')
        self.compareWith(model1, model2, compareModel, True, createdDeps, removedDeps,
                         rename_detection)
        for r in createdDeps:
            r.addAttribute("compare", "added")
        for r in removedDeps:
            r.addAttribute("compare", "removed")
        return compareModel

    # self == SGraph
    def compareWith(
        self,
        ma: SGraph,
        mb: SGraph,
        elementCompareGraphModel: SGraph,
        compareDeps: bool,
        createdDeps: list[SElementAssociation],
        removedDeps: list[SElementAssociation],
        renameDetection: bool,
    ):

        renamed_elem__old_name = {}
        rename_detector = None
        if renameDetection:
            rename_detector = RenameDetector()
            # pre-step to identify all renamed, and changes in func params (and moved in the future)
            rename_detector.identify_rename_pairs(ma.rootNode, mb.rootNode, renamed_elem__old_name)

        for child in ma.rootNode.children:
            eChild = mb.getElement(child)
            compareElement = elementCompareGraphModel.createOrGetElement(child)
            if eChild is not None:
                self.compareElement(child, eChild, elementCompareGraphModel, compareElement,
                                    compareDeps, "A", "B", createdDeps, removedDeps)
            else:
                compareElement.addAttribute(CompareGraphAttrs.ONLY_IN, "A")
                compareElement.createAttributesFrom(child.attrs)
                if child.children is not None:
                    for e in child.children:
                        cchild = compareElement.createElementChain(e.name)
                        cchild.createAttributesFrom(e.attrs)
                        self.recurseNodesMarkInexisting(e, cchild, createdDeps, removedDeps, "A")

        for child in mb.rootNode.children:
            eChild = ma.getElement(child)
            compareElement = elementCompareGraphModel.createOrGetElement(child)
            if eChild is not None:
                self.compareElement(child, eChild, elementCompareGraphModel, compareElement,
                                    compareDeps, "B", "A", createdDeps, removedDeps)
            else:
                compareElement.addAttribute(CompareGraphAttrs.ONLY_IN, "B")
                compareElement.createAttributesFrom(child.attrs)
                if child.children is not None:
                    for e in child.children:
                        cchild = compareElement.createElementChain(e.name)
                        cchild.createAttributesFrom(e.attrs)
                        self.recurseNodesMarkInexisting(e, cchild, createdDeps, removedDeps, "B")

        if rename_detector:
            # mark renamed elements as changed.
            rename_detector.annotate_renamed_elems(elementCompareGraphModel, renamed_elem__old_name)

        # createdDeps and removedDeps will contain some duplicates because of how comparison works.
        easCreated: set[SElementAssociation] = set()
        for e in createdDeps:
            easCreated.add(e)
        easRemoved: set[SElementAssociation] = set()
        for e in removedDeps:
            easRemoved.add(e)

        if compareDeps:
            for child in ma.rootNode.children:
                compareElement = elementCompareGraphModel.getElement(child)
                if compareElement:
                    self.recurseNodesCreateDeps(child, compareElement, elementCompareGraphModel,
                                                easRemoved, "A", False)

            for child in mb.rootNode.children:
                compareElement = elementCompareGraphModel.getElement(child)
                if compareElement:
                    self.recurseNodesCreateDeps(child, compareElement, elementCompareGraphModel,
                                                easCreated, "B", True)

    def compareElement(
        self,
        thisElement: SElement,
        eOther: SElement,
        compMod: SGraph,
        compareElement: SElement,
        compareDeps: bool,
        aSide: str,
        bSide: str,
        createdDeps: list,
        removedDeps: list,
    ):
        cElem = compMod.createOrGetElement(thisElement)
        if aSide == 'B':
            cElem.attrs.update(thisElement.attrs)
        else:
            cElem.attrs.update(eOther.attrs)

        childDiff = False
        handled: set[SElement] = set()  # Elements
        changecount = 0
        if thisElement.children is not None and len(thisElement.children) != 0:
            for childOfThis in thisElement.children:
                if aSide == "A":
                    child = cElem.createElementChain(childOfThis.name)
                    child.setType(childOfThis.getType())
                else:
                    child = cElem.getChildByName(childOfThis.name)

                eChild = eOther.getChildByName(childOfThis.name)
                if cElem.attrs is None:
                    cElem.initalizeAttributes()

                if child is not None and eChild is not None:
                    handled.add(eChild)
                    if aSide == 'A' and not eChild.equalsAttributes(childOfThis):
                        attrDiff, change_count = compare_attrs(childOfThis.attrs,
                                                               eChild.attrs, child.attrs,
                                                               childOfThis.getType(),
                                                               eChild.getType())
                        child.attrs[CompareGraphAttrs.CHANGED_ATTRIBUTES] = attrDiff
                        child.attrs.update(eChild.attrs)
                        if change_count > 0:
                            if CompareGraphAttrs.CHANGE_COUNT in child.attrs:
                                attr = child.attrs[CompareGraphAttrs.CHANGE_COUNT]
                                if isinstance(attr, int):
                                    attr += change_count
                                    child.attrs[CompareGraphAttrs.CHANGE_COUNT] = attr
                                else:
                                    raise Exception(
                                        'Unexpected situation in compareElement, CHANGE_COUNT not int..'
                                    )
                            else:
                                child.attrs[CompareGraphAttrs.CHANGE_COUNT] = change_count

                    changecount += self.compareElement(childOfThis, eChild, compMod, child,
                                                       compareDeps, aSide, bSide, createdDeps,
                                                       removedDeps)

                else:
                    childDiff = True
                    if child is not None:
                        self.recurseNodesMarkInexisting(childOfThis, child, createdDeps,
                                                        removedDeps, aSide)
            if eOther.children is not None:
                for othrChild in eOther.children:
                    if othrChild not in handled:
                        if cElem.getChildByName(othrChild.name) is not None:
                            if bSide == "B":
                                sys.stderr.write("Error: comparing " + othrChild.name + '\n')
                                # todo consider comparison of
                                # cElem.getChildByName(othrChild.name).attrs and type with
                                # othrChild here.
                        else:
                            child = cElem.createElementChain(othrChild.name)
                            child.setType(othrChild.getType())
                            child.createAttributesFrom(othrChild.attrs)
                            child.attrs['_only_in'] = bSide
                            changecount += self.recurseNodesMarkInexisting(
                                othrChild, child, createdDeps, removedDeps, bSide)

        else:
            if eOther.children is not None and len(eOther.children) != 0:
                childDiff = True
                for e in eOther.children:
                    child = cElem.getChildByName(e.name)
                    if child is not None:
                        if bSide == "B":
                            pass  # never here.. sys.stderr.write("BP FAIL " + e.name + '\n')
                    else:
                        child = cElem.createElementChain(e.name)
                        child.setType(e.getType())
                        child.createAttributesFrom(e.attrs)
                        changecount += self.recurseNodesMarkInexisting(
                            e, child, createdDeps, removedDeps, bSide)

        if childDiff:
            compareElement.attrs[CompareGraphAttrs.CHANGED_CHILD] = "true"

        if compareDeps:
            if aSide == 'A':
                changecount += self.compareDeps(compareElement, thisElement, eOther, createdDeps,
                                                removedDeps, aSide)

        tag_change_count(compareElement, changecount)
        return changecount

    def recurseNodesMarkInexisting(
        self,
        thisElem: SElement,
        compModItem: SElement,
        createdDeps: list[SElementAssociation],
        removedDeps: list[SElementAssociation],
        strModel: str,
    ):
        changecount = 0
        compModItem.attrs['_only_in'] = strModel
        for child in thisElem.children:
            alreadyExists = compModItem.getChildByName(child.name)
            if alreadyExists is None:
                x = SElement(compModItem, child.name)
                x.setType(child.getType())
                x.attrs.update(child.attrs)
                x.attrs['_only_in'] = strModel
                changecount += 1
                changecount += self.recurseNodesMarkInexisting(child, x, createdDeps, removedDeps,
                                                               strModel)
            else:
                changecount += self.recurseNodesMarkInexisting(child, alreadyExists, createdDeps,
                                                               removedDeps, strModel)

        changecount += self.compareDeps(compModItem, thisElem, None, createdDeps, removedDeps,
                                        strModel)

        return changecount


    def recurseNodesCreateDeps(
        self,
        thisElem: SElement,
        compareElem: SElement,
        elementCompareGraphModel: SGraph,
        easR: set,
        val: str,
        avoidOverlap: bool,
    ):
        if thisElem.outgoing is not None:
            for association in thisElem.outgoing:
                to = association.toElement
                cme = elementCompareGraphModel.getElement(to)

                if cme is None:
                    raise Exception('Unexpected situation in recurseNodesCreateDeps, cme is None..')

                if association in easR:
                    ea2 = SElementAssociation(compareElem, cme, association.deptype)
                    ea2.initElems()
                    ea2.addAttribute('_only_in', val)
                    if val == 'A':
                        ea2.addAttribute('compare', 'removed')
                    else:
                        ea2.addAttribute('compare', 'added')
                    # TODO changed is too vague, so using just this _changed_dep?
                    if '_only_in' not in compareElem.attrs:
                        compareElem.addAttribute('_changed_dep', 'true')
                        # TODO? self.tagChangeCount(compareElem, 1)

                else:
                    if avoidOverlap:
                        pass
                    else:
                        if cme != compareElem:
                            ea2 = SElementAssociation(compareElem, cme, association.deptype,
                                                      association.attrs)
                            ea2.initElems()
                            if '_only_in' in compareElem.attrs:
                                onlyIn = compareElem.attrs['_only_in']
                                ea2.addAttribute('_only_in', onlyIn)
                                if (val == 'A' and onlyIn == 'A') or (val == 'B' and onlyIn == 'B'):
                                    ea2.addAttribute('compare', 'removed')
                                elif (val == 'A' and onlyIn == 'B') or (val == 'B'
                                                                        and onlyIn == 'A'):
                                    ea2.addAttribute('compare', 'added')
                            else:
                                # TODO changed is too vague, using just this _changed_dep?
                                compareElem.addAttribute('_changed_dep', 'true')
                                # TODO? self.tagChangeCount(compareElem, 1)

        if thisElem.children is not None:
            for x in thisElem.children:
                compareChild = compareElem.getChildByName(x.name)
                if compareChild is not None:
                    self.recurseNodesCreateDeps(x, compareChild, elementCompareGraphModel, easR,
                                                val, avoidOverlap)

    def newAndRemovedDependenciesLists(self, compareModel):
        newDepsList = list()
        removedDepsList = list()

        def traverseDeps(x):
            for o in x.outgoing:
                if '_only_in' in o.attrs:
                    if o.attrs['_only_in'] == 'A':
                        removedDepsList.append(o)
                    elif o.attrs['_only_in'] == 'B':
                        newDepsList.append(o)
            for c in x.children:
                traverseDeps(c)

        compareModel.traverse(traverser=traverseDeps)

        newDeps_infos = []
        for n in newDepsList:
            newDeps_infos.append((n, n.get_dependency_length()))

        newDeps_infos.sort(key=lambda x: x[1], reverse=True)

        removedDeps_infos = []
        for n in removedDepsList:
            removedDeps_infos.append((n, n.get_dependency_length()))

        removedDeps_infos.sort(key=lambda x: x[1], reverse=True)

        return newDeps_infos, removedDeps_infos

    def newAndRemovedElems(self, compareModel):
        """New and removed element lists (in form parent-name/name, SElement)"""
        newlist = list()
        removedlist = list()

        def traverseElems(x):
            if '_only_in' in x.attrs:
                if x.attrs['_only_in'] == 'A':
                    removedlist.append(x)
                elif x.attrs['_only_in'] == 'B':
                    newlist.append(x)
            for c in x.children:
                traverseElems(c)

        compareModel.traverse(traverser=traverseElems)

        newlist_infos = []
        for n in newlist:
            newlist_infos.append((n.parent.name + '/' + n.name, n))

        newlist_infos.sort(key=lambda x: x[0])

        removedlist_infos = []
        for n in removedlist:
            removedlist_infos.append((n.parent.name + '/' + n.name, n))

        removedlist_infos.sort(key=lambda x: x[0])

        return newlist_infos, removedlist_infos

    def elemsWithChanges(self, compareModel):
        """Changed element paths and their change counts, in descending order by change count."""
        changed = dict()

        def traverseElems(x):
            if CompareGraphAttrs.CHANGE_COUNT in x.attrs:
                changed[x] = x.attrs[CompareGraphAttrs.CHANGE_COUNT]
            for c in x.children:
                traverseElems(c)

        compareModel.traverse(traverser=traverseElems)

        change_infos = []
        for elem, change_count in changed.items():
            change_infos.append((elem, int(change_count)))

        change_infos.sort(key=lambda x: x[1], reverse=True)

        return change_infos

    def elemsWithAttrChanges(self, compareModel):
        """Changed element paths and their change counts, in descending order by change count."""
        changed = dict()

        def traverseElems(x):
            if CompareGraphAttrs.CHANGE_COUNT not in x.attrs and '_attr_diff' in x.attrs:
                changed[x] = x.attrs['_attr_diff']
            for c in x.children:
                traverseElems(c)

        compareModel.traverse(traverser=traverseElems)

        change_infos = []
        for elem, attr_diff in changed.items():
            change_infos.append((elem, attr_diff))

        change_infos.sort(key=lambda x: len(x[1]), reverse=True)

        return change_infos

    def getCompareInfos(self, compareModel):
        newDeps, removedDeps = self.newAndRemovedDependenciesLists(compareModel)

        newElems, removedElems = self.newAndRemovedElems(compareModel)

        elemsWithChanges = self.elemsWithChanges(compareModel)

        elemsWithAttrChanges = self.elemsWithAttrChanges(compareModel)

        return newDeps, removedDeps, elemsWithChanges, newElems, removedElems, elemsWithAttrChanges

    def printCompareInfos(self, compareModel):
        newDeps, removedDeps, elemsWithChanges, newElems, removedElems, elemsWithAttrChanges = \
            self.getCompareInfos(compareModel)

        print('\n\nNew dependencies:')
        for dep, deplen in newDeps:
            print('New dep: ' + str(dep.fromElement.getPath() + ' --> ' + dep.toElement.getPath() +
                                    ' : ' + dep.deptype) + ' ' + str(dep.attrs) + ' DEP.LENGTH=' +
                  str(deplen))

        print('\n\nRemoved dependencies:')
        for dep, deplen in removedDeps:
            print('Removed dep: ' + str(dep.fromElement.getPath() + ' --> ' +
                                        dep.toElement.getPath() + ' : ' + dep.deptype) + ' ' +
                  str(dep.attrs) + ' DEP.LENGTH=' + str(deplen))

        print('\n\nNew elements:')
        print('  '.join(map(lambda x: x[0] + ' (' + x[1].getPath() + ')', newElems)))
        print('\n\nRemoved elements:')
        print('  '.join(map(lambda x: x[0] + ' (' + x[1].getPath() + ')', removedElems)))

        print('\n\nElements and the change counts:')
        print(' \n'.join(map(lambda x: str(x[1]) + '\t' + x[0].getPath(), elemsWithChanges)))

        print('\n\nElements with attr changes:')
        print(' \n'.join(map(lambda x: str(x[1]) + '\t' + x[0].getPath(), elemsWithAttrChanges)))

        return newDeps, removedDeps, elemsWithChanges, newElems, removedElems, elemsWithAttrChanges

    def uniqueConnectionsCreated(self, compareModel):
        return self.uniqueConnections(compareModel, 'B')

    def uniqueConnectionsRemoved(self, compareModel):
        return self.uniqueConnections(compareModel, 'A')

    def uniqueConnections(self, compareModel, side):
        elemtoelem = {}

        def traverseDeps(x):
            for o in x.outgoing:
                if '_only_in' in o.attrs and o.attrs['_only_in'] == side:
                    user = o.fromElement
                    used = o.toElement
                    levelUser = user.getLevel()
                    levelUsed = used.getLevel()
                    if levelUsed != levelUser:

                        if levelUser > levelUsed:
                            user = user.getAncestorOfLevel(levelUsed)
                        elif levelUser < levelUsed:
                            used = used.getAncestorOfLevel(levelUser)
                    if user != used:
                        elemtoelem.setdefault(user, set()).add(used)

            for c in x.children:
                traverseDeps(c)

        compareModel.traverse(traverser=traverseDeps)

        uniqueconnections = {}

        eliminate_side = 'B' if side == 'A' else 'A'

        def process_user_used(user, used):

            # debunk its uniqueness
            if not debunk_uniqueness(user, used, eliminate_side):

                # if debunk not successfull, add to unique list
                uniqueconnections.setdefault(user, set()).add(used)
                user_parent = user.parent
                used_parent = used.parent
                if user_parent.parent is not None:
                    process_user_used(user_parent, used_parent)

        for user, usedset in elemtoelem.items():
            for used in usedset:
                process_user_used(user, used)

        tuples = []
        for user, usedlist in uniqueconnections.items():
            for used in usedlist:
                tuples.append((user.getPath(), used.getPath(), user.getLevel()))

        return sorted(set(tuples))

    def externalChanges(self, compareModel):
        new_ext_elems = []
        new_ext_deps = []
        removed_ext_elems = []
        removed_ext_deps = []

        def traverseExternal(x):
            if '_only_in' in x.attrs and x.attrs['_only_in'] == 'B':
                new_ext_elems.append(x)
            elif '_only_in' in x.attrs and x.attrs['_only_in'] == 'A':
                removed_ext_elems.append(x)
            for association in x.incoming:
                if '_only_in' in association.attrs and association.attrs['_only_in'] == 'B':
                    new_ext_deps.append(association)
                elif '_only_in' in association.attrs and association.attrs['_only_in'] == 'A':
                    removed_ext_deps.append(association)

            for c in x.children:
                traverseExternal(c)

        for projlevel in compareModel.rootNode.children:
            for c in projlevel.children:
                if c.name == 'External':
                    traverseExternal(c)

        return new_ext_elems, new_ext_deps, removed_ext_elems, removed_ext_deps

    def getElementsWithAttrDiff(self, compareModel: SGraph, attribute):
        matched_elems = []

        def traverseElems(elem):
            if CompareGraphAttrs.CHANGED_ATTRIBUTES in elem.attrs:
                if attribute in elem.attrs[CompareGraphAttrs.CHANGED_ATTRIBUTES].split(';'):
                    matched_elems.append(elem)

            for c in elem.children:
                traverseElems(c)

        compareModel.traverse(traverseElems)
        return matched_elems

    @staticmethod
    def checkAssocLists(
            outgoing1: list[SElementAssociation],
            outgoing2: list[SElementAssociation],
            createdDeps: list[SElementAssociation],
            removedDeps: list[SElementAssociation],
    ):
        codes1: dict[int, SElementAssociation] = {}
        codes2: dict[int, SElementAssociation] = {}
        for association in outgoing1:
            to = association.toElement.getPath()
            codes1[hash(to) + hash(association.deptype)] = association
        for association in outgoing2:
            to = association.toElement.getPath()
            codes2[hash(to) + hash(association.deptype)] = association
        if sorted(codes1.keys()) == sorted(codes2.keys()):
            return 0
        else:
            changeCount = 0
            for h in filter(lambda a: a not in codes2, codes1.keys()):
                removedDeps.append(codes1[h])
                changeCount += 1

            for h in filter(lambda a: a not in codes1, codes2.keys()):
                createdDeps.append(codes2[h])
                changeCount += 1
            return changeCount


    @staticmethod
    def compareDeps(
        compareElem: SElement,
        element: SElement,
        eOther: SElement | None,
        createdDeps: list[SElementAssociation],
        removedDeps: list[SElementAssociation],
        aSide: str,
    ):
        if element.outgoing is not None and len(element.outgoing) > 0:
            if eOther is not None and eOther.outgoing is not None and len(eOther.outgoing) > 0:
                if aSide == "A":
                    changeCount = ModelCompare.checkAssocLists(element.outgoing, eOther.outgoing,
                                                               createdDeps, removedDeps)
                else:
                    changeCount = ModelCompare.checkAssocLists(element.outgoing, eOther.outgoing,
                                                               removedDeps, createdDeps)
                if changeCount > 0:
                    compareElem.addAttribute(CompareGraphAttrs.CHANGED_DEP, "true")
                    return changeCount
                else:
                    return 0
            else:
                if aSide == 'A':
                    removedDeps += element.outgoing
                else:
                    createdDeps += element.outgoing

                compareElem.addAttribute(CompareGraphAttrs.CHANGED_DEP, "true")
                return len(element.outgoing)
        else:
            if eOther is not None and eOther.outgoing is not None and len(eOther.outgoing) > 0:
                if aSide == 'A':
                    createdDeps += eOther.outgoing
                compareElem.addAttribute(CompareGraphAttrs.CHANGED_DEP, "true")
                return len(eOther.outgoing)
            else:
                # both null
                return 0



