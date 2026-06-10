"""
Network Client Module.

Bridges the transport layer to the sync service.

Components

ReqRespClient
    Implements NetworkRequester using ConnectionManager.
    Handles BlocksByRoot and Status requests.

LiveNetworkEventSource
    Bridges connection events to NetworkService events.
"""

from lean_spec.node.networking.client.event_source import LiveNetworkEventSource

__all__ = [
    "LiveNetworkEventSource",
]
