import os
from knack.log import get_logger
from azure.cli.core.cloud import (get_active_cloud_name)
from azure.cli.core._config import (GLOBAL_CONFIG_DIR)
from azure.cli.core._environment import get_config_dir
from azure.cli.core._session import (Session)

BLOCK_CONFIG_FILE = os.path.join(GLOBAL_CONFIG_DIR, 'block.json')
DEFAULT_TEMPLATE_BASE_URI = "https://raw.githubusercontent.com/mspnp/template-building-blocks/v2.1.0/templates/"
_CLOUDS = "clouds"
_TEMPLATE_BASE_URI = "templateBaseUri"
logger = get_logger(__name__)

class BlockConfig(object):
    def __init__(self):
        super(BlockConfig, self).__init__()
        self._storage = Session()
        self._storage.load(BLOCK_CONFIG_FILE)

    def _get_clouds(self):
        clouds = self._storage[_CLOUDS]
        if not clouds:
            self._storage[_CLOUDS] = {}
            clouds = {}
        return clouds

    def get_template_base_uri(self, cli_ctx, cloud_name=None):
        clouds = self._get_clouds()
        if not cloud_name:
            #cloud_name = get_active_cloud_name(cli_ctx)
            cloud_name = cli_ctx.cloud.name
        cloud = clouds.get(cloud_name)
        if not cloud:
            # Cloud entry does not exist so create a default
            cloud = {
                _TEMPLATE_BASE_URI: DEFAULT_TEMPLATE_BASE_URI
            }
            clouds[cloud_name] = cloud
            self._storage[_CLOUDS] = clouds

        template_base_uri = cloud[_TEMPLATE_BASE_URI]
        if not template_base_uri.endswith("/"):
            # Log a warning!
            logger.warning("Template base URI '%s' does not end in '/'.  Repairing.", template_base_uri)
            template_base_uri += "/"
            cloud[_TEMPLATE_BASE_URI] = template_base_uri
            clouds[cloud_name] = cloud
            self._storage[_CLOUDS] = clouds
        return template_base_uri

BLOCK = BlockConfig()
