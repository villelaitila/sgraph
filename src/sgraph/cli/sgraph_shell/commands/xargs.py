from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult


class XargsCommand:

    def __init__(self):
        pass

    def execute(self, command_input, cmd, graph, state, commands) -> CommandResult:
        p = cmd.xargs_sub_command
        cmd_object = commands[p] if isinstance(p, str) else commands[p.__class__.__name__]
        return cmd_object.execute([], cmd.xargs_sub_command, graph, state, from_xargs=command_input)
