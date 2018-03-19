# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from azure.cli.core import (AzCommandsLoader)
from azure.cli.core.commands.parameters import (get_location_type, resource_group_name_type, file_type)
from azure.cli.core.profiles import (ResourceType)
from argcomplete.completers import FilesCompleter
import azext_block._help  # pylint: disable=unused-import

class BlockCommandsLoader(AzCommandsLoader):
    def __init__(self, cli_ctx=None):
        from azure.cli.core.commands import CliCommandType
        block_custom = CliCommandType(operations_tmpl='azext_block.custom#{}')
        super(BlockCommandsLoader, self).__init__(cli_ctx=cli_ctx,
                                                  custom_command_type=block_custom, min_profile='2017-03-10-profile')

    def load_command_table(self, args):
        with self.command_group('block', resource_type=ResourceType.MGMT_RESOURCE_RESOURCES) as g:
            g.custom_command('deploy', 'deploy_block')
            g.custom_command('process', 'process_block')
        with self.command_group('block config') as g:
            g.custom_command('show', 'show_config')
        return self.command_table

    def load_arguments(self, command):
        with self.argument_context('block process') as c:
            c.argument('resource_group_name', arg_type=resource_group_name_type, required=True)
            c.argument('location', arg_type=get_location_type(self.cli_ctx), required=True)
            c.argument('parameter_file', options_list=('--parameter-file', '-p'), type=file_type, completer=FilesCompleter(), required=True, help="a parameter file path in the file system")
        with self.argument_context('block deploy') as c:
            c.argument('resource_group_name', arg_type=resource_group_name_type, required=True)
            c.argument('location', arg_type=get_location_type(self.cli_ctx), required=True)
            c.argument('parameter_file', options_list=('--parameter-file', '-p'), type=file_type, completer=FilesCompleter(), required=True, help="a parameter file path in the file system")

COMMAND_LOADER_CLS = BlockCommandsLoader
