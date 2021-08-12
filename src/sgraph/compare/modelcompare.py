import difflib
import sys
from Levenshtein import StringMatcher

from sgraph.compare.comparegraphattrs import CompareGraphAttrs
from sgraph import SElementAssociation
from sgraph import SGraph, SElement

ignoredAttrs = {'days_since_modified'}


def getnotnullattr(attributes2, attr):
    if attr in attributes2:
        if attributes2[attr] is None:
            return ''
        return attributes2[attr]
    return ''


def debunk_uniqueness(user, used, side):
    for x in user.outgoing:
        if x.toElement == used:
            if '_only_in' not in x.attrs:
                return True
            elif x.attrs['_only_in'] == side:
                return True
        elif x.toElement.isDescendantOf(used):
            if '_only_in' not in x.attrs:
                return True
            elif x.attrs['_only_in'] == side:
                return True
    for c in user.children:
        result = debunk_uniqueness(c, used, side)
        if result:
            return True
    return False


def compare_parameters(elem_a, elem_b):
    """
    params is like "self;email;team_id;password;name"

    :param elem_a:
    :param elem_b:
    :return: ratio
    """
    if 'params' in elem_a.attrs and 'params' in elem_b.attrs:
        if elem_a.attrs['params'] == elem_b.attrs['params']:
            return 1
        else:
            params_a = elem_a.attrs['params'].split(';')
            params_b = elem_b.attrs['params'].split(';')
            sm = difflib.SequenceMatcher(None, params_a, params_b)
            return sm.ratio()
    return 0


def add_up_change_count(attrs):
    change_count = 0
    if 'hash' in attrs:
        change_count += 1
    if 'license' in attrs:
        change_count += 1
    return change_count


class ModelCompare:
    def __init__(self):
        pass

    def compare(self, path1, path2):
        model1 = SGraph(path1)
        model2 = SGraph(path2)
        return self.compareModels(model1, model2)

    def compareModels(self, model1, model2, rename_detection=False):
        rootNode = SElement(None, '')
        compareModel = SGraph(rootNode)
        createdDeps = []
        removedDeps = []

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
    def compareWith(self, ma, mb, elementCompareGraphModel: 'SGraph', compareDeps: bool,
                    createdDeps: list, removedDeps: list, renameDetection: bool):

        renamed_elem__old_name = {}
        if renameDetection:
            # pre-step to identify all renamed, and changes in func params (and moved in the future)
            self.identify_rename_pairs(ma.rootNode, mb.rootNode, renamed_elem__old_name)

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

        if renameDetection:
            # mark renamed elements as changed.
            self.mark_rename_elems_changed(renamed_elem__old_name, elementCompareGraphModel)

        # createdDeps and removedDeps will contain some duplicates because of how comparison works.
        easCreated = set()
        for e in createdDeps:
            easCreated.add(e)
        easRemoved = set()
        for e in removedDeps:
            easRemoved.add(e)

        if compareDeps:
            for child in ma.rootNode.children:
                compareElement = elementCompareGraphModel.getElement(child)
                self.recurseNodesCreateDeps(child, compareElement, elementCompareGraphModel,
                                            easRemoved, "A", False)

            for child in mb.rootNode.children:
                compareElement = elementCompareGraphModel.getElement(child)
                self.recurseNodesCreateDeps(child, compareElement, elementCompareGraphModel,
                                            easCreated, "B", True)

    def compareElement(self, thisElement, eOther: 'SElement', compMod: 'SGraph',
                       compareElement: 'SElement', compareDeps: bool, aSide: str, bSide: str,
                       createdDeps: list, removedDeps: list):
        cElem = compMod.createOrGetElement(thisElement)
        if aSide == 'B':
            cElem.attrs.update(thisElement.attrs)
        else:
            cElem.attrs.update(eOther.attrs)

        childDiff = False
        handled = set()  # Elements
        changecount = 0
        if thisElement.children is not None and len(thisElement.children) != 0:
            for childOfThis in thisElement.children:
                if aSide == "A":
                    child = cElem.createElementChain(childOfThis.name)
                    child.setType(childOfThis.getType())
                else:
                    child = cElem.getChildByName(childOfThis.name)

                eChild = eOther.getChildByName(childOfThis.name)
                handled.add(eChild)
                if cElem.attrs is None:
                    cElem.initalizeAttributes()
                if eChild is not None:
                    if aSide == 'A' and not eChild.equalsAttributes(childOfThis):
                        attrDiff, change_count = self.compareAttrs(childOfThis.attrs,
                                                                   eChild.attrs, child.attrs,
                                                                   childOfThis.getType(),
                                                                   eChild.getType())
                        child.attrs[CompareGraphAttrs.CHANGED_ATTRIBUTES] = attrDiff
                        child.attrs.update(eChild.attrs)
                        if change_count > 0:
                            if CompareGraphAttrs.CHANGE_COUNT in child.attrs:
                                child.attrs[CompareGraphAttrs.CHANGE_COUNT] += change_count
                            else:
                                child.attrs[CompareGraphAttrs.CHANGE_COUNT] = change_count

                    changecount += self.compareElement(childOfThis, eChild, compMod, child,
                                                       compareDeps, aSide, bSide, createdDeps,
                                                       removedDeps)

                else:
                    childDiff = True
                    self.recurseNodesMarkInexisting(childOfThis, child, createdDeps, removedDeps,
                                                    aSide)
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

        self.tagChangeCount(compareElement, changecount)
        return changecount

    @staticmethod
    def tagChangeCount(compareElement, changecount):
        if changecount > 0:
            if compareElement.attrs is not None and CompareGraphAttrs.CHANGE_COUNT in \
                    compareElement.attrs:
                val = compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT]
                compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT] = changecount + val
            else:
                if compareElement.attrs is None:
                    compareElement.attrs = {}
                compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT] = changecount

    @staticmethod
    def compareDeps(compareElem: SElement, element: SElement, eOther, createdDeps, removedDeps,
                    aSide):
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

    @staticmethod
    def checkAssocLists(outgoing1, outgoing2, createdDeps, removedDeps):
        codes1 = {}
        codes2 = {}
        for ea in outgoing1:
            to = ea.toElement.getPath()
            codes1[hash(to) + hash(ea.deptype)] = ea
        for ea in outgoing2:
            to = ea.toElement.getPath()
            codes2[hash(to) + hash(ea.deptype)] = ea
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

    def recurseNodesCreateDeps(self, thisElem: SElement, compareElem: SElement,
                               elementCompareGraphModel: SGraph, easR: set, val: str,
                               avoidOverlap: bool):
        if thisElem.outgoing is not None:
            for ea in thisElem.outgoing:
                to = ea.toElement
                cme = elementCompareGraphModel.getElement(to)
                if ea in easR:
                    ea2 = SElementAssociation(compareElem, cme, ea.deptype)
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
                            ea2 = SElementAssociation(compareElem, cme, ea.deptype, ea.attrs)
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
                self.recurseNodesCreateDeps(x, compareElem.getChildByName(x.name),
                                            elementCompareGraphModel, easR, val, avoidOverlap)

    def recurseNodesMarkInexisting(self, thisElem: SElement, compModItem: SElement, createdDeps,
                                   removedDeps, strModel: str):
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

    def compareAttrs(self, attributes1, attributes2, outmap, type1, type2):
        attrs = set()

        # Severe changes like hash change and license change are treated as "real" changes that
        # add up into change count metrics.

        c = CompareGraphAttrs.CHANGED_ATTRIBUTES
        if type1 is not None and type2 is not None:
            if type1 != type2:
                outmap[c + '_type'] = type1 + ';' + type2
        elif type1 is None and type2 is not None:
            outmap[c + '_type'] = '__;' + type2
        elif type1 is not None:
            outmap[c + '_type'] = type1 + ';--'

        if attributes1 is None:
            for attr in attributes2.keys():
                outmap[c + '_' + attr] = '--;' + getnotnullattr(attributes2, attr)
            return ';'.join(attributes2.keys()), add_up_change_count(attributes2)
        if attributes2 is None:
            for k, v in attributes1.items():
                outmap[c + '_' + k] = v + ';--'
            return ';'.join(attributes1.keys()), add_up_change_count(attributes1)

        keys1 = set(attributes1.keys())
        keys2 = set(attributes2.keys())

        intersection = set(keys1)
        intersection.intersection(keys2)
        intersection -= ignoredAttrs

        # TODO: Similar logic needed as implemented in desktop
        # attributes need special handling here depending on the kind of attribute

        for attrName in intersection:
            val1 = attributes1.get(attrName)
            val2 = attributes2.get(attrName)
            if not val1 or not val2:
                attrs.add(attrName)
                outmap[c + '_' + attrName] = "new attribute"
                continue

            if val1 == val2:
                pass  # Identical
            else:
                if not self.isListAttribute(attrName) or (isinstance(val1, str)
                                                          and len(val1) != len(val2)):
                    outmap[c+'_'+attrName] = str(attributes1[attrName]) + \
                                             self.getDelim(val1, val2) + str(attributes2[attrName])
                    attrs.add(attrName)
                elif self.isListAttribute(attrName):
                    items1 = list()
                    if isinstance(val1, float):
                        sys.stderr.write('Problematic value for a list attr {}, val={}\n'.format(
                            attrName, val1))
                    else:
                        items1 = list(val1.split(';'))
                    items2 = list()
                    if isinstance(val2, float):
                        pass
                    else:
                        items2 = list(val2.split(';'))
                    items1.sort()
                    items2.sort()

                    if items1 != items2:
                        outmap[c+'_'+attrName] = attributes1[attrName] + self.getDelim(val1, val2) \
                                                 + attributes2[attrName]
                        attrs.add(attrName)

        keys1 = filter(lambda x: x not in intersection, keys1)
        for attribute_in_a in keys1:
            val = attributes1[attribute_in_a]
            if val != '':
                outmap[c + '_' + attribute_in_a] = '{};--'.format(val)
                attrs.add(attribute_in_a)

        keys2 = filter(lambda x: x not in intersection, keys2)
        for attribute_in_b in keys2:
            val = attributes2[attribute_in_b]
            if val != '':
                outmap[c + '_' + attribute_in_b] = '--;{}'.format(val)
                attrs.add(attribute_in_b)

        return ';'.join(attrs), add_up_change_count(attrs)

    @staticmethod
    def getDelim(val1, val2):
        delim = ';'
        if isinstance(val1, str) and isinstance(val2, str):
            if ';' in val1 or ';' in val2:
                delim = ';;'
        return delim

    @staticmethod
    def isListAttribute(attrName):
        return attrName == 'license' or '_list' in attrName

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
            for ea in x.incoming:
                if '_only_in' in ea.attrs and ea.attrs['_only_in'] == 'B':
                    new_ext_deps.append(ea)
                elif '_only_in' in ea.attrs and ea.attrs['_only_in'] == 'A':
                    removed_ext_deps.append(ea)

            for c in x.children:
                traverseExternal(c)

        for projlevel in compareModel.rootNode.children:
            for c in projlevel.children:
                if c.name == 'External':
                    traverseExternal(c)

        return new_ext_elems, new_ext_deps, removed_ext_elems, removed_ext_deps

    def identify_rename_pairs(self, a_elem, b_elem, renamed_elem__old_name):
        if len(a_elem.children) > 0 and len(b_elem.children) > 0:
            rename_pairs = []
            self.identify_renamed_children(a_elem.childrenDict, b_elem.childrenDict, rename_pairs)

            # set all renamed elements to have the updated name/params in the old model
            for p in rename_pairs:
                # Save the original name for later use
                renamed_elem__old_name[p[1]] = p[0].name

                if p[0].name == p[1].name:
                    raise Exception('Unexpected situation in rename detection, names equal.. ' +
                                    p[0].name)
                if p[0].name in p[0].parent.childrenDict:
                    p[0].parent.childrenDict.pop(p[0].name)
                else:
                    raise Exception('Unexpected situation in rename detection, childrenDict not in '
                                    'sync.. ' + p.getPath())
                p[0].name = p[1].name
                if p[0].name in p[0].parent.childrenDict:
                    raise Exception(
                        'Unexpected situation #2 in rename detection, childrenDict not in '
                        'sync.. ' + p.getPath())
                else:
                    p[0].parent.childrenDict[p[0].name] = p[0]

            for c_a in a_elem.children:
                c_b = b_elem.getChildByName(c_a.name)
                if c_b is not None:
                    self.identify_rename_pairs(c_a, c_b, renamed_elem__old_name)

    def apply_renames_to_b_model(self, pairs):
        for p in pairs:
            if p[0].name == p[1].name:
                raise Exception('Unexpected situation in rename detection, names equal.. ' +
                                p[0].name)
            if p[0].name in p[0].parent.childrenDict:
                p[0].parent.childrenDict.pop(p[0].name)
            else:
                raise Exception('Unexpected situation in rename detection, childrenDict not in '
                                'sync.. ' + p.getPath())
            p[0].name = p[1].name
            if p[0].name in p[0].parent.childrenDict:
                raise Exception('Unexpected situation #2 in rename detection, childrenDict not in '
                                'sync.. ' + p.getPath())
            else:
                p[0].parent.childrenDict[p[0].name] = p[0]

    def mark_rename_elems_changed(self, renamed_elem__old_name, model):
        for renamed_elem, old_name in renamed_elem__old_name.items():
            compareElem = model.getElement(renamed_elem)
            compareElem.addAttribute('compare', 'changed')
            compareElem.addAttribute('renamed', 'true')
            compareElem.addAttribute('old_name', old_name)
            self.tagChangeCount(compareElem, 1)

    def identify_renamed_children(self, a_children, b_children, rename_pairs):
        """
        Identify renamed children
        :param a_children: children dict in A model
        :param b_children: children dict in B model
        :param rename_pairs: output list of renamed element pairs
        :return: None
        """
        # case 0:
        # identical sets, and names
        if a_children.keys() == b_children.keys():
            return

        # case 1:
        # 1 child in A and B, name is different
        a_set = set(a_children.keys())
        b_set = set(b_children.keys())
        if len(a_set) == len(b_set) == 1:
            a_elem = a_children[next(iter(a_set))]
            b_elem = b_children[next(iter(b_set))]
            # TODO this is good for rename cases but what if the actual element has moved under
            # some of the sub directories?
            # Should we check for the element type here also?
            rename_pairs.append((a_elem, b_elem))

        elif len(a_set) == len(b_set):
            # case k:
            # n children in A, n children in B
            unique_a = a_set.difference(b_set)
            unique_b = b_set.difference(a_set)
            if len(unique_a) == 1 and len(unique_b) == 1:
                a_elem = a_children[next(iter(unique_a))]
                b_elem = b_children[next(iter(unique_b))]
                # TODO this is good for rename cases but what if the actual element has moved under
                # Should we check for the element type here also?
                rename_pairs.append((a_elem, b_elem))
            elif len(unique_b) > 1:  # len(unique_a) == len(unique_a) also
                found_a = set()
                for a_name in unique_a:
                    a_elem = a_children[a_name]
                    matched_to = None
                    for b_name in unique_b:
                        b_elem = b_children[b_name]
                        if self.elem_similarity(a_elem, b_elem, 80, False):
                            # TODO: Improve this to seek for the best similarity points instead
                            # of stopping on first that has enough points.
                            rename_pairs.append((a_elem, b_elem))
                            matched_to = b_name
                            break
                    if matched_to is not None:
                        unique_b.remove(matched_to)
                        found_a.add(a_name)
                for f in found_a:
                    unique_a.remove(f)
                if len(unique_a) > 0:
                    self.match_with_points(a_children, b_children, rename_pairs, unique_a, unique_b)

        else:
            # case x:
            # n children in A, m children in B, maybe everything has restructured, maybe nothing
            # common
            unique_a = a_set.difference(b_set)
            unique_b = b_set.difference(a_set)

            if len(unique_a) == 0:
                # Only new elements
                pass

            elif len(unique_b) == 0:
                # Only removed elements
                pass

            else:
                self.match_with_points(a_children, b_children, rename_pairs, unique_a, unique_b)

    def match_with_points(self, a_children, b_children, rename_pairs, unique_a, unique_b):
        similarity_points = {}
        for a_name in sorted(unique_a):
            a_elem = a_children[a_name]
            for b_name in sorted(unique_b):
                b_elem = b_children[b_name]
                p = self.elem_similarity(a_elem, b_elem, 80, True)
                similarity_points.setdefault(p, []).append((a_elem, b_elem))
        matched_a = set()
        matched_b = set()
        for p in sorted(similarity_points.keys(), reverse=True):
            if p >= 50:
                for pair in similarity_points[p]:
                    if pair[0] not in matched_a and pair[1] not in matched_b:
                        rename_pairs.append(pair)
                        matched_a.add(pair[0])
                        matched_b.add(pair[1])
            else:
                break

    def elem_similarity(self, elem_a, elem_b, points_level, return_points):
        points = 0

        if not elem_a.typeEquals(elem_b.getType()):
            # Type change always means a new element.
            if return_points:
                return 0
            else:
                return False
        else:
            points += 5

        def name_points(name_a, name_b):
            # Compare name similarity
            edit_distance = StringMatcher.distance(name_a, name_b)
            if edit_distance < 1:
                raise Exception('Invalid edit distance by stringmatcher')

            # Scale edit_distance to 0..65 with formula "n = 65 - 4e"
            name_similarity_points = max(0, 65 - 4 * edit_distance)
            # TODO Use also synonym database to identify cursory name changes that have big
            # edit_distance but mean the same.
            return name_similarity_points

        if elem_a.typeEquals('function'):
            pos_a = elem_a.name.find('(')
            pos_b = elem_b.name.find('(')
            if pos_a != -1 and pos_b != -1:
                # Name equals, just a param change
                name_a = elem_a.name[:pos_a]
                name_b = elem_b.name[:pos_b]
                if name_a == name_b:
                    points += 65
                    if points >= points_level:
                        if not return_points:
                            return True

                ratio = compare_parameters(elem_a, elem_b)
                points += ratio * 20
                if points >= points_level:
                    if not return_points:
                        return True

                if name_a != name_b:
                    # name and params are not equal, compare only name part
                    points += name_points(name_a, name_b)

            elif pos_a != -1:
                pass  # no () in b --> so different that it does not make sense to compare name.
            elif pos_b != -1:
                pass  # no () in a --> so different that it does not make sense to compare name.
            else:
                # no () in function name, compare just name part
                points += name_points(elem_a.name, elem_b.name)

            # TODO Consider also the function source code and the relative position in the code
        else:
            # other types like class, file, dir, etc.
            points += name_points(elem_a.name, elem_b.name)

        if len(elem_a.outgoing) > 0 and len(elem_b.outgoing) > 0:
            related_a = list(map(lambda x: x.toElement.name, elem_a.outgoing))
            related_b = list(map(lambda x: x.toElement.name, elem_b.outgoing))
            if len(related_a) > 0 and len(related_b) > 0:
                sm = difflib.SequenceMatcher(None, related_a, related_b)
                points += 55 * sm.ratio()
                if points >= points_level:
                    if not return_points:
                        return True
        if len(elem_a.outgoing) == 0 and len(elem_b.outgoing) == 0:
            points += 2
            if points >= points_level:
                if not return_points:
                    return True

        if len(elem_a.incoming) > 0 and len(elem_b.incoming) > 0:
            related_a = list(map(lambda x: x.fromElement.name, elem_a.incoming))
            related_b = list(map(lambda x: x.fromElement.name, elem_b.incoming))
            if len(related_a) > 0 and len(related_b) > 0:
                sm = difflib.SequenceMatcher(None, related_a, related_b)
                points += 55 * sm.ratio()
                if points >= points_level:
                    if not return_points:
                        return True
        if len(elem_a.incoming) == 0 and len(elem_b.incoming) == 0:
            points += 2
            if points >= points_level:
                if not return_points:
                    return True

        if len(elem_a.children) == 0 and len(elem_b.children) == 0:
            points += 4
            if points >= points_level:
                if not return_points:
                    return True

        if len(elem_a.children) > 0 and len(elem_b.children) > 0:
            related_a = list(map(lambda x: x.name, elem_a.children))
            related_b = list(map(lambda x: x.name, elem_b.children))
            if len(related_a) > 0 and len(related_b) > 0:
                sm = difflib.SequenceMatcher(None, related_b, related_b)
                points += 80 * sm.ratio()
                if points >= points_level:
                    if not return_points:
                        return True

        if points >= points_level:
            if not return_points:
                return True

        # TODO What else to be used in comparison

        if return_points:
            return points
        else:
            return points > 90

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
