from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


def get_line_at(pos, s):
    first_linefeed = s[:pos].rfind('\n')
    last_linefeed = s.find('\n', pos+1)
    return s[first_linefeed+1:last_linefeed]


class GrepCommand:

    def __init__(self):
        pass

    def execute(self, command_input, cmd, graph, state, from_xargs=None) -> CommandResult:
        files = []
        for path_ref in cmd.path_refs:
            files.append(create_file_abstraction(path_ref, state))

        if from_xargs:
            for arg in from_xargs:
                files.append(create_file_abstraction(arg, state))

        if not cmd.path_refs and cmd.asterisk:
            if state['current_location'].outgoing:
                files.append(create_file_abstraction('outgoing.json', state))
            if state['current_location'].incoming:
                files.append(create_file_abstraction('incoming.json', state))
            if state['current_location'].attrs:
                files.append(create_file_abstraction('attributes.json', state))

        import re
        output = []
        errors = []
        for file in files:
            if file.isfile(graph):
                content = file.content()
                for match in re.finditer(cmd.keyword, content):
                    # TODO Produce whoe line
                    match_line = get_line_at(match.start(), content)
                    output.append(match_line)
            else:
                errors.append('File not found: ' + file.relative_path)

        return_code = 0 if output else 1
        return CommandResult(output=output, errors=errors, return_code=return_code)

