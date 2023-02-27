
import shell
from sgraph import SGraph

sgraph = SGraph()
current_location = sgraph.rootNode
current_location.createOrGetElement('asd/qwer/foo/bar')
current_location.createOrGetElement('asf/qwer/foo/bar')
current_location = current_location.childrenDict['asf']

current_location.addAttribute('attribute1', 'hello')
current_location.childrenDict['qwer'].addAttribute('attribute2', 'stuff')

# commandline = 'ls && echo jees && cat attributes.json && pwd && grep attribute1 *'
# commandline = 'pwd && grep attribute1 * && cd .. && ls && pwd'
# commandline = 'ls | xargs ls'
# commandline = 'ls && ls && ls qwer && ls .. && cd .. && ls asf asd && ls asd/qwer && ls ..'
# commandline = 'find . -type f'
# commandline = 'find . -type f |xargs grep attr '
# commandline = 'rm qwer'
commandline = 'mv qwer ../asd/qwerty && sgraph visualize'
print(commandline)
state = {'current_location': current_location}
out = shell.execute_command_model(shell.parse_command(commandline), sgraph, state)
