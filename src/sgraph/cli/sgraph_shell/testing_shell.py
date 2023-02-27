
import shell
from sgraph import SGraph

sgraph = SGraph()
current_location = sgraph.rootNode
current_location.createOrGetElement('asd/qwer/foo/bar')
current_location.createOrGetElement('asf/qwer/foo/bar')
current_location = current_location.childrenDict['asf']
current_location.addAttribute('moi', 'hello')

out = shell.enter_shell(sgraph)