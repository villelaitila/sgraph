from sgraph.cli.sgraph_shell.commands.cat import CatCommand
from sgraph.cli.sgraph_shell.commands.cd import CdCommand
from sgraph.cli.sgraph_shell.commands.echo import EchoCommand
from sgraph.cli.sgraph_shell.commands.find import FindCommand
from sgraph.cli.sgraph_shell.commands.grep import GrepCommand
from sgraph.cli.sgraph_shell.commands.ls import LsCommand
from sgraph.cli.sgraph_shell.commands.pwd import PwdCommand
from sgraph.cli.sgraph_shell.commands.sgraph_save import SGraphSaveCommand
from sgraph.cli.sgraph_shell.commands.sgraph_visualize import SGraphVisualizeCommand
from sgraph.cli.sgraph_shell.commands.xargs import XargsCommand
from sgraph.cli.sgraph_shell.commands.exit import ExitCommand
from sgraph.cli.sgraph_shell.commands.mv import MvCommand
from sgraph.cli.sgraph_shell.commands.rm import RmCommand
from sgraph.cli.sgraph_shell.commands.mkdir import MkdirCommand
from sgraph.cli.sgraph_shell.commands.cp import CpCommand

commands = {'ls': LsCommand(),
            'cd': CdCommand(),
            'cat': CatCommand(),
            'grep': GrepCommand(),
            'echo': EchoCommand(),
            'find': FindCommand(),
            'pwd': PwdCommand(),
            'xargs': XargsCommand(),
            'exit': ExitCommand(),
            'mv': MvCommand(),
            'rm': RmCommand(),
            'mkdir': MkdirCommand(),
            'cp': CpCommand(),
            'SGraphSaveCommand': SGraphSaveCommand(),
            'SGraphVisualizeCommand': SGraphVisualizeCommand()}

for command_name in set(commands.keys()):
    commands[command_name[0].upper() + command_name[1:] + 'Command'] = commands[command_name]
