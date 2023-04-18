from sgraph import SGraph
from sgraph import SElementAssociation


def test_same_association_is_not_created_twice():
    graph = SGraph()
    element1 = graph.createOrGetElementFromPath('/test/element1')
    element2 = graph.createOrGetElementFromPath('/test/element2')
    SElementAssociation.create_unique_element_association(
        element1, element2, '', {})
    assert len(element1.outgoing) == 1
    assert len(element2.incoming) == 1
    SElementAssociation.create_unique_element_association(
        element1, element2, '', {})
    assert len(element1.outgoing) == 1
    assert len(element2.incoming) == 1


def test_attributes_are_combined():
    graph = SGraph()
    element1 = graph.createOrGetElementFromPath('/test/element1')
    element2 = graph.createOrGetElementFromPath('/test/element2')
    SElementAssociation.create_unique_element_association(
        element1, element2, '', {'attribute1': 'value1'})
    SElementAssociation.create_unique_element_association(
        element1, element2, '',  {'attribute2': 'value2'})
    assert element1.outgoing[0].attrs == {'attribute1': 'value1',
                                          'attribute2': 'value2'}
