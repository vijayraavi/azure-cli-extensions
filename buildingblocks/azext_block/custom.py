# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import json
import os
from azure.cli.core.commands import (LongRunningOperation)
from azure.cli.core.util import get_file_json, shell_safe_json_parse
from azure.cli.core.profiles import ResourceType, get_sdk
from knack.log import get_logger
from knack.util import CLIError
from ._client_factory import (_resource_client_factory)
from .block import (BLOCK)
from .models.building_block_settings import (BuildingBlocksParameterFile)

logger = get_logger(__name__)

def show_config(cmd):
    print(json.dumps(BLOCK._storage.data, indent=2))

def create_resource_group_if_not_exists(cmd, resource_group_name, location, subscription_id, tags=None):
    # From azure-cli-resource command_modules
    # We need to reimplement this so we can do cross subscription creations
    rcf = _resource_client_factory(cmd.cli_ctx, subscription_id=subscription_id)
    if not rcf.resource_groups.check_existence(resource_group_name):
        ResourceGroup = cmd.get_models('ResourceGroup')
        parameters = ResourceGroup(
            location=location,
            tags=tags
        )
        rcf.resource_groups.create_or_update(resource_group_name, parameters)

def deploy_building_block(cmd, processed_building_block):
        DeploymentProperties, TemplateLink, DeploymentMode = get_sdk(cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES,
                                                    'DeploymentProperties', 'TemplateLink', 'DeploymentMode', mod='models')
        template_link = TemplateLink(uri=processed_building_block.building_block.get_template_url(cmd.cli_ctx))
        parsed = get_file_json(processed_building_block.template_parameters_file, throw_on_empty=False)
        properties = DeploymentProperties(template_link=template_link,
                                          parameters=parsed.get('parameters'),
                                          mode=DeploymentMode.incremental)

        create_resource_group_if_not_exists(cmd,
                                            resource_group_name=processed_building_block.resource_group_name,
                                            location=processed_building_block.location,
                                            subscription_id=processed_building_block.subscription_id)
        smc = _resource_client_factory(cmd.cli_ctx, subscription_id=processed_building_block.subscription_id)
        return smc.deployments.create_or_update(processed_building_block.resource_group_name,
                                                processed_building_block.deployment_name, properties, raw=False)

def process_blocks(cmd, parameter_file=None, resource_group_name=None, location=None, deploy_blocks=False):
    from azure.cli.core.cloud import (get_active_cloud, get_cloud_subscription)
    cloud = get_active_cloud()
    subscription_id = get_cloud_subscription(cloud.name)
    try:
        parameters = get_file_json(parameter_file, throw_on_empty=False)
    except ValueError as json_ex:
        raise CLIError('Unable to parse parameters: {}'.format(json_ex))

    # Force the building blocks to load so we can "register" them dynamically, although in the CLI they should already have been loaded.
    plugin_module = __import__('azext_block.models')
    cmd_line_attrs = {
        'subscription_id': subscription_id,
        'resource_group_name': resource_group_name,
        'location': location
    }

    import json
    bb = BuildingBlocksParameterFile.deserialize(
        # We should probably change the deserialize to take the pre-parsed json, since the az cli does it safely.
        json.dumps(parameters),
        **cmd_line_attrs)

    print(bb.validate())
    deployments = [building_block.process(os.path.splitext(os.path.basename(parameter_file))[0], index, None) for index, building_block in enumerate(bb.parameters.building_blocks)]
    if deploy_blocks:
        for building_block in deployments:
            for resource_group in building_block.resource_groups:
                create_resource_group_if_not_exists(cmd, resource_group_name=resource_group.resource_group_name, location=resource_group.location, subscription_id=subscription_id)
            LongRunningOperation(cmd.cli_ctx)(deploy_building_block(cmd, building_block))

def process_block(cmd, parameter_file=None, resource_group_name=None, location=None):
    from .validations import (patch_validation)
    with patch_validation():
        process_blocks(cmd, parameter_file=parameter_file, resource_group_name=resource_group_name, location=location, deploy_blocks=False)

def deploy_block(cmd, parameter_file=None, resource_group_name=None, location=None):
    from .validations import patch_validation
    with patch_validation():
        process_blocks(cmd, parameter_file=parameter_file, resource_group_name=resource_group_name, location=location, deploy_blocks=True)
