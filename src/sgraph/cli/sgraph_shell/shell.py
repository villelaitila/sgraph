import sys
from typing import List

from textx import metamodel_from_file, TextXSyntaxError

from sgraph.cli.sgraph_shell.commands.commandregistry import commands
from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.commands.xargs import XargsCommand


def enter_shell(graph):
    current_location = graph.rootNode

    import readline
    import threading

    def prompt():
        path = current_location.getPath()
        return f'sgraph {path} $'


    def interrupt():
        print()  # Don't want to end up on the same line the user is typing on.
        print('Interrupting cow -- moo!')
        print(prompt(), readline.get_line_buffer(), sep='', end='')

    def cli():
        state = {'current_location': current_location}
        while True:
            command = str(input(prompt()))
            try:
                command_model = parse_command(command)
                for output in execute_command_model(command_model, graph, state):
                    print(output)

            except TextXSyntaxError as syntax_error:
                sys.stderr.write(f'{syntax_error}\n')

    threading.Thread(target=cli).start()
    threading.Timer(2, interrupt).start()


def parse_command(cmdline):
    #TODO Where to put this shell.tx
    shell_metamodel = metamodel_from_file('shell.tx')
    shell_model = shell_metamodel.model_from_str(cmdline)
    return shell_model


def execute_real_command(command_input, p, graph, state) -> CommandResult:
    cmd_object = commands[p] if isinstance(p, str) else commands[p.__class__.__name__]
    if type(cmd_object) == XargsCommand:
        return cmd_object.execute(command_input, p, graph, state, commands)
    else:
        return cmd_object.execute(command_input, p, graph, state)


def execute_single_main_command(main_command, graph, state) -> CommandResult:
    piped_commands = list(main_command.pipedCommands)
    cmd_input = []
    return_code = 0
    err_output = []
    while piped_commands:
        # print('\nPIPED:')
        first_command = piped_commands.pop(0)
        cmd_output = execute_real_command(cmd_input, first_command, graph, state)
        # print('DEBUG: ' + str(cmd_output))
        return_code = cmd_output.return_code
        err_output.extend(cmd_output.errors)
        cmd_input = cmd_output.output
    final_output = cmd_input
    return CommandResult(output=final_output, errors=err_output, return_code=return_code)


def execute_command_model(command_model, graph, state) -> List[CommandResult]:
    outputs = []
    for main_command in command_model.commands:
        # print('\nMAIN:')
        cmd_output = execute_single_main_command(main_command, graph, state)
        outputs.append(cmd_output)
        print('stdout:')
        for out in cmd_output.output:
            print(out)
        sys.stdout.flush()
        for errors in cmd_output.errors:
            sys.stderr.write(str(errors) + '\n')
        if cmd_output.return_code != 0:
            break
    return outputs
