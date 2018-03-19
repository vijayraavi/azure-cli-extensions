# The msrest serialization stuff needs the module flattened here
from .building_block_settings import (
    BuildingBlocksParameterFile,
    BuildingBlocksParameters,
    BuildingBlock
)

from .load_balancer import (
    LoadBalancer,
    LoadBalancerBuildingBlock
)

from .virtual_network_gateway import (
    VirtualNetworkGateway,
    VirtualNetworkGatewayBuildingBlock
)

from .virtual_network_gateway_connection import (
    ExpressRouteCircuitReference,
    LocalNetworkGateway,
    VirtualNetworkGatewayConnection,
    VirtualNetworkGatewayConnectionBuildingBlock,
    VirtualNetworkGatewayReference
)

from .network_security_group import (
    NetworkSecurityGroup,
    SecurityRule,
    NetworkSecurityGroupBuildingBlock,
    NetworkSecurityGroupNetworkInterface,
    NetworkSecurityGroupSubnet
)

from .resources import (
    Resource,
    ResourceReference,
    TopLevelResource
)

from .route_table import (
    Route,
    RouteTable,
    RouteTableBuildingBlock,
    RouteTableSubnet
)

from .virtual_network_reference import (
    VirtualNetworkReference
)

from .virtual_network import (
    RemoteVirtualNetworkReference,
    Subnet,
    VirtualNetwork,
    VirtualNetworkPeering,
    VirtualNetworkBuildingBlock
)