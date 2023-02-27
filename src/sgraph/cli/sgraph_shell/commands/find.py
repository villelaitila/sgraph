from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction

SPECIAL_FILE_NAMES = ['attributes.json', 'outgoing.json', 'incoming.json']


class FindCommand:

    def __init__(self):
        pass

    def execute(self, _command_input, cmd, graph, state) -> CommandResult:
        path_ref = '.' if cmd.path_ref == '' else cmd.path_ref
        file = create_file_abstraction(path_ref, state)

        get_files = not cmd.find_args or cmd.find_args and cmd.find_args.files
        get_directories = not cmd.find_args or cmd.find_args and cmd.find_args.directories
        if file.isdir(graph):
            stack = [file.resolved_element]
            found = []
            while stack:
                elem = stack.pop(len(stack) - 1)
                if get_directories:
                    found.append(elem.getPath())

                if get_files:
                    if elem.attrs:
                        found.append(elem.getPath() + '/attributes.json')
                    if elem.outgoing:
                        found.append(elem.getPath() + '/outgoing.json')
                    if elem.incoming:
                        found.append(elem.getPath() + '/incoming.json')

                stack.extend(elem.children)

            return CommandResult(output=found, errors=[], return_code=0)
        else:
            return CommandResult(output=[], errors=[f'Not a directory {path_ref}'], return_code=1)
