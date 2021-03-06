# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
import os
import shutil
from knack.util import CLIError
from knack.log import get_logger
from azure.mgmt.botservice.models import Bot, BotProperties, Sku
from azure.cli.command_modules.botservice.custom import (
    provisionConvergedApp,
    get_bot_site_name,
    publish_app as publish_appv3)
from azure.cli.command_modules.botservice._webutils import (
    deploy_arm_template,
    enable_zip_deploy,
    get_app_settings,
    _get_site_credential,
    _get_scm_url)
from azure.cli.core._profile import Profile  # pylint: disable=unused-import

logger = get_logger(__name__)


def _get_app_insights_location(key):
    region_map = {
        'australiaeast': 'southeastasia',
        'australiacentral': 'southeastasia',
        'australiacentral2': 'southeastasia',
        'australiasoutheast': 'southeastasia',
        'eastasia': 'southeastasia',
        'southeastasia': 'westus',
        'eastus': 'eastus',
        'eastus2': 'eastus',
        'southcentralus': 'southcentralus',
        'westcentralus': 'westus2',
        'westus': 'westus2',
        'westus2': 'westus2',
        'brazilsouth': 'southcentralus',
        'centralus': 'southcentralus',
        'northcentralus': 'southcentralus',
        'japanwest': 'southeastasia',
        'japaneast': 'southeastasia',
        'southindia': 'southeastasia',
        'centralindia': 'southeastasia',
        'westindia': 'southeastasia',
        'canadacentral': 'southcentralus',
        'canadaeast': 'eastus',
        'koreacentral': 'southeastasia',
        'koreasouth': 'southeastasia',
        'northeurope': 'northeurope',
        'westeurope': 'westeurope',
        'uksouth': 'westeurope',
        'ukwest': 'westeurope',
        'francecentral': 'westeurope',
        'francesouth': 'westeurope'
    }
    return region_map[key]


def create(cmd, client, resource_group_name, resource_name, kind, description=None, display_name=None,
           endpoint=None, msa_app_id=None, password=None, tags=None, storageAccountName=None,
           location='Central US', sku_name='F0', appInsightsLocation='South Central US',
           language='Csharp', version='v3'):
    display_name = display_name or resource_name
    kind = kind.lower()

    if not msa_app_id:
        msa_app_id, password = provisionConvergedApp(resource_name)
        logger.warning('obtained msa app id and password. Provisioning bot now.')

    if kind == 'registration':
        kind = 'bot'
        if not endpoint or not msa_app_id:
            raise CLIError('Endpoint and msa app id are required for creating a registration bot')
        parameters = Bot(
            location='global',
            sku=Sku(name=sku_name),
            kind=kind,
            tags=tags,
            properties=BotProperties(
                display_name=display_name,
                description=description,
                endpoint=endpoint,
                msa_app_id=msa_app_id
            )
        )
        return client.bots.create(
            resource_group_name=resource_group_name,
            resource_name=resource_name,
            parameters=parameters
        )
    if kind in ('webapp', 'function'):
        return create_app(cmd, client, resource_group_name, resource_name, description, kind, msa_app_id, password,
                          storageAccountName, location, sku_name, appInsightsLocation, language, version)
    else:
        raise CLIError('Invalid Bot Parameter : Kind')


def create_bot_json(cmd, client, resource_group_name, resource_name, app_password=None, raw_bot_properties=None):
    if not raw_bot_properties:
        raw_bot_properties = client.bots.get(
            resource_group_name=resource_group_name,
            resource_name=resource_name
        )
    if not app_password:
        site_name = get_bot_site_name(raw_bot_properties.properties.endpoint)
        app_settings = get_app_settings(
            cmd=cmd,
            resource_group_name=resource_group_name,
            name=site_name
        )
        app_password = [item['value'] for item in app_settings if item['name'] == 'MicrosoftAppPassword'][0]

    profile = Profile(cli_ctx=cmd.cli_ctx)
    return {
        'type': 'abs',
        'id': raw_bot_properties.name,
        'name': raw_bot_properties.properties.display_name,
        'appId': raw_bot_properties.properties.msa_app_id,
        'appPassword': app_password,
        'endpoint': raw_bot_properties.properties.endpoint,
        'resourceGroup': str(resource_group_name),
        'tenantId': profile.get_subscription(subscription=client.config.subscription_id)['tenantId'],
        'subscriptionId': client.config.subscription_id,
        'serviceName': resource_name
    }


def create_app(cmd, client, resource_group_name, resource_name, description, kind, appid, password, storageAccountName,  # pylint: disable=too-many-locals
               location, sku_name, appInsightsLocation, language, version):  # pylint: disable=too-many-locals
    if version == 'v3':
        if kind == 'function':
            template_name = 'functionapp.template.json'
            if language == 'Csharp':
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/csharp-abs-functions_emptybot.zip'
            else:
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/node.js-abs-functions_emptybot_funcpack.zip'  # pylint: disable=line-too-long

        else:
            kind = 'sdk'
            template_name = 'webapp.template.json'
            if language == 'Csharp':
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/csharp-abs-webapp_simpleechobot_precompiled.zip'  # pylint: disable=line-too-long
            else:
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/node.js-abs-webapp_hello-chatconnector.zip'  # pylint: disable=line-too-long
    elif version == 'v4':
        if kind == 'function':
            raise CLIError('Function bot creation is not supported for v4 bot sdk.')

        else:
            kind = 'sdk'
            template_name = 'webappv4.template.json'
            if language == 'Csharp':
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/csharp-abs-webapp-v4_echobot_precompiled.zip'  # pylint: disable=line-too-long
            else:
                zip_url = 'https://connectorprod.blob.core.windows.net/bot-packages/node.js-abs-webapp-v4_echobot.zip'  # pylint: disable=line-too-long

    create_new_storage = False
    if not storageAccountName:
        import re
        import string
        import random
        create_new_storage = True
        storageAccountName = re.sub(r'[^a-z0-9]', '', resource_name[:10] +
                                    ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4)))
        site_name = re.sub(r'[^a-z0-9]', '', resource_name[:15] +
                           ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4)))

    appInsightsLocation = _get_app_insights_location(location.lower().replace(' ', ''))
    paramsdict = {
        "location": location,
        "kind": kind,
        "sku": sku_name,
        "siteName": site_name,
        "appId": appid,
        "appSecret": password,
        "storageAccountResourceId": "",
        "serverFarmId": "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Web/serverfarms/{2}".format(
            client.config.subscription_id, resource_group_name, resource_name),
        "zipUrl": zip_url,
        "createNewStorage": create_new_storage,
        "storageAccountName": storageAccountName,
        "botEnv": "prod",
        "useAppInsights": True,
        "appInsightsLocation": appInsightsLocation,
        "createServerFarm": True,
        "serverFarmLocation": location.lower().replace(' ', ''),
        "azureWebJobsBotFrameworkDirectLineSecret": "",
        "botId": resource_name
    }
    if description:
        paramsdict['description'] = description
    if template_name == 'webappv4.template.json':
        import requests
        response = requests.get('https://scratch.botframework.com/api/misc/botFileEncryptionKey')
        if response.status_code not in [200]:
            raise CLIError('Unable to provision a bot file encryption key. Please try again.')
        bot_encrpytion_key = response.text[1:-1]
        paramsdict['botFileEncryptionKey'] = bot_encrpytion_key
    params = {k: {'value': v} for k, v in paramsdict.items()}

    dir_path = os.path.dirname(os.path.realpath(__file__))
    deploy_result = deploy_arm_template(
        cli_ctx=cmd.cli_ctx,
        resource_group_name=resource_group_name,
        template_file=os.path.join(dir_path, template_name),
        parameters=[[json.dumps(params)]],
        deployment_name=resource_name,
        mode='Incremental'
    )

    deploy_result.wait()
    return create_bot_json(cmd, client, resource_group_name, resource_name, app_password=password)


def get_bot(cmd, client, resource_group_name, resource_name, bot_json=None):
    raw_bot_properties = client.bots.get(
        resource_group_name=resource_group_name,
        resource_name=resource_name
    )
    if bot_json:
        return create_bot_json(cmd, client, resource_group_name, resource_name, raw_bot_properties=raw_bot_properties)

    return raw_bot_properties


def create_upload_zip(code_dir, include_node_modules=True):
    import zipfile
    file_excludes = ['upload.zip', 'db.lock', '.env']
    folder_excludes = ['packages', 'bin', 'obj']
    if not include_node_modules:
        folder_excludes.append('node_modules')
    zip_filepath = os.path.abspath('upload.zip')
    save_cwd = os.getcwd()
    os.chdir(code_dir)
    try:
        with zipfile.ZipFile(zip_filepath, 'w',
                             compression=zipfile.ZIP_DEFLATED) as zf:
            path = os.path.normpath(os.curdir)
            for dirpath, dirnames, filenames in os.walk(os.curdir, topdown=True):
                for item in folder_excludes:
                    if item in dirnames:
                        dirnames.remove(item)
                for name in sorted(dirnames):
                    path = os.path.normpath(os.path.join(dirpath, name))
                    zf.write(path, path)
                for name in filenames:
                    if name in file_excludes:
                        continue
                    path = os.path.normpath(os.path.join(dirpath, name))
                    if os.path.isfile(path):
                        zf.write(path, path)
    finally:
        os.chdir(save_cwd)
    return zip_filepath


def check_response_status(response, expected_code=None):
    expected_code = expected_code or 200
    if response.status_code != expected_code:
        raise CLIError('Failed with status code {} and reason {}'.format(
            response.status_code, response.text))


def find_proj(proj_file):
    for root, _, files in os.walk(os.curdir):
        for file_name in files:
            if proj_file == file_name.lower():
                return os.path.relpath(os.path.join(root, file_name))
    raise CLIError('project file not found. Please pass a valid --proj-file.')


def prepare_publish_v4(code_dir, proj_file):
    save_cwd = os.getcwd()
    os.chdir(code_dir)
    try:
        if not os.path.exists(os.path.join('.', 'package.json')):
            if proj_file is None:
                raise CLIError('expected --proj-file parameter for csharp v4 project.')
            with open('.deployment', 'w') as f:
                f.write('[config]\n')
                proj_file = proj_file.lower()
                proj_file = proj_file if proj_file.endswith('.csproj') else proj_file + '.csproj'
                f.write('SCM_SCRIPT_GENERATOR_ARGS=--aspNetCore {0}\n'.format(find_proj(proj_file)))

        else:
            # put iisnode.yml and web.config
            import requests
            response = requests.get('https://icscratch.blob.core.windows.net/bot-packages/node_v4_publish.zip')
            with open('temp.zip', 'wb') as f:
                f.write(response.content)
            import zipfile
            zip_ref = zipfile.ZipFile('temp.zip')
            zip_ref.extractall()
            zip_ref.close()
            os.remove('temp.zip')
    finally:
        os.chdir(save_cwd)


def publish_app(cmd, client, resource_group_name, resource_name, code_dir=None, proj_file=None, sdk_version='v3'):
    if sdk_version == 'v3':
        return publish_appv3(cmd, client, resource_group_name, resource_name, code_dir)
    # get the bot and ensure it's not a registration only bot
    raw_bot_properties = client.bots.get(
        resource_group_name=resource_group_name,
        resource_name=resource_name
    )
    if raw_bot_properties.kind == 'bot':
        raise CLIError('Source publish is not supported for registration only bots')

    if not code_dir:
        code_dir = os.getcwd()

    if not os.path.isdir(code_dir):
        raise CLIError('Please supply a valid directory path containing your source code')
    # ensure that the directory contains appropriate post deploy scripts folder
    if 'PostDeployScripts' not in os.listdir(code_dir):
        prepare_publish_v4(code_dir, proj_file)

    zip_filepath = create_upload_zip(code_dir, include_node_modules=False)
    site_name = get_bot_site_name(raw_bot_properties.properties.endpoint)
    # first try to put the zip in clirepo
    user_name, password = _get_site_credential(cmd.cli_ctx, resource_group_name, site_name, None)
    scm_url = _get_scm_url(cmd, resource_group_name, site_name, None)

    import urllib3
    authorization = urllib3.util.make_headers(basic_auth='{0}:{1}'.format(user_name, password))
    headers = authorization

    import requests
    payload = {
        'command': 'rm -rf clirepo',
        'dir': r'site'
    }
    headers['content-type'] = 'application/json'
    response = requests.post(scm_url + '/api/command', data=json.dumps(payload), headers=headers)
    response = requests.put(scm_url + '/api/vfs/site/clirepo/', headers=headers)
    check_response_status(response, 201)
    headers['content-type'] = 'application/octet-stream'
    with open(zip_filepath, 'rb') as fs:
        zip_content = fs.read()
        response = requests.put(scm_url + '/api/zip/site/clirepo', headers=headers, data=zip_content)

    output = enable_zip_deploy(cmd, resource_group_name, site_name, 'upload.zip')
    os.remove('upload.zip')
    if os.path.exists(os.path.join('.', 'package.json')):
        payload = {
            'command': 'npm install',
            'dir': r'site\wwwroot'
        }
        response = requests.post(scm_url + '/api/command', data=json.dumps(payload), headers=headers)

    return output


def download_app(cmd, client, resource_group_name, resource_name, file_save_path=None):  # pylint: disable=too-many-statements, too-many-locals
    # get the bot and ensure it's not a registration only bot
    raw_bot_properties = client.bots.get(
        resource_group_name=resource_group_name,
        resource_name=resource_name
    )
    if raw_bot_properties.kind == 'bot':
        raise CLIError('Source download is not supported for registration only bots')

    file_save_path = file_save_path or os.getcwd()
    if not os.path.isdir(file_save_path):
        raise CLIError('Path name not valid')
    folder_path = os.path.join(file_save_path, resource_name)
    if os.path.exists(folder_path):
        raise CLIError('The path {0} already exists. Please delete this folder or specify an alternate path'.format(folder_path))  # pylint: disable=line-too-long
    os.mkdir(folder_path)

    site_name = get_bot_site_name(raw_bot_properties.properties.endpoint)

    user_name, password = _get_site_credential(cmd.cli_ctx, resource_group_name, site_name, None)
    scm_url = _get_scm_url(cmd, resource_group_name, site_name, None)

    import urllib3
    authorization = urllib3.util.make_headers(basic_auth='{0}:{1}'.format(user_name, password))
    headers = authorization
    headers['content-type'] = 'application/json'

    # if repository folder exists, then get those contents for download
    import requests
    response = requests.get(scm_url + '/api/zip/site/clirepo/', headers=authorization)
    if response.status_code != 200:
        # try getting the bot from wwwroot instead
        payload = {
            'command': 'PostDeployScripts\\prepareSrc.cmd {0}'.format(password),
            'dir': r'site\wwwroot'
        }
        response = requests.post(scm_url + '/api/command', data=json.dumps(payload), headers=headers)
        check_response_status(response)
        response = requests.get(scm_url + '/api/vfs/site/bot-src.zip', headers=authorization)
        check_response_status(response)

    download_path = os.path.join(file_save_path, 'download.zip')
    with open(os.path.join(file_save_path, 'download.zip'), 'wb') as f:
        f.write(response.content)
    import zipfile
    zip_ref = zipfile.ZipFile(download_path)
    zip_ref.extractall(folder_path)
    zip_ref.close()
    os.remove(download_path)
    if (os.path.exists(os.path.join(folder_path, 'PostDeployScripts', 'deploy.cmd.template')) and
            os.path.exists(os.path.join(folder_path, 'deploy.cmd'))):
        shutil.copyfile(os.path.join(folder_path, 'deploy.cmd'),
                        os.path.join(folder_path, 'PostDeployScripts', 'deploy.cmd.template'))
    # if the bot contains a bot
    bot_file_path = os.path.join(folder_path, '{0}.bot'.format(resource_name))
    if os.path.exists(bot_file_path):
        app_settings = get_app_settings(
            cmd=cmd,
            resource_group_name=resource_group_name,
            name=site_name
        )
        bot_secret = [item['value'] for item in app_settings if item['name'] == 'botFileSecret']
        # write a .env file #todo: write an appsettings.json file
        bot_env = {
            'botFileSecret': bot_secret[0],
            'botFilePath': '{0}.bot'.format(resource_name),
            'NODE_ENV': 'development'
        }
        if os.path.exists(os.path.join(folder_path, 'package.json')):
            with open(os.path.join(folder_path, '.env'), 'w') as f:
                for key, value in bot_env.items():
                    f.write('{0}={1}\n'.format(key, value))
        else:
            app_settings_path = os.path.join(folder_path, 'appsettings.json')
            existing = None
            if not os.path.exists(app_settings_path):
                existing = '{}'
            else:
                with open(app_settings_path, 'r') as f:
                    existing = json.load(f)
            with open(os.path.join(app_settings_path), 'w+') as f:
                for key, value in bot_env.items():
                    existing[key] = value
                f.write(json.dumps(existing))

        if not bot_secret:
            bot_env['downloadPath'] = folder_path
            return bot_env

    return {'downloadPath': folder_path}
