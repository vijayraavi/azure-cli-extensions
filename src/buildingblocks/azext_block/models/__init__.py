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

"""
from .network_interface import (
    NetworkInterface,
    NetworkInterfaceBuildingBlock
)

from .virtual_machine import (
    VirtualMachine,
    VirtualMachineBuildingBlock
)
"""

from .virtual_machine_extension import (
    VirtualMachineExtension,
    VirtualMachineExtensionBuildingBlock,
    Extension
)
from .virtual_network import (
    VirtualNetwork,
    VirtualNetworkBuildingBlock
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

from .application_gateway import (
    ApplicationGatewayBuildingBlock,
    ApplicationGateway,
    Sku,
    GatewayIPConfiguration,
    FrontendIPConfiguration,
    InternalApplicationGatewaySetting,
    BackendAddressPool,
    BackendAddress,
    BackendHttpSettings,
    ConnectionDraining,
    HttpListener,
    RedirectConfiguration,
    UrlPathMap,
    PathRule,
    RequestRoutingRule,
    WebApplicationFirewallConfiguration,
    DisabledRuleGroup,
    Probe,
    Match,
    SslCertificate,
    AuthenticationCertificate,
    SslPolicy,
    FrontendPort
)