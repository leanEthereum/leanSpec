"""
Network Client Module.

Bridges the transport layer to the sync service by implementing
the NetworkRequester and NetworkEventSource protocols.

Components
----------
ReqRespClient
    Implements NetworkRequester using ConnectionManager.
    Handles BlocksByRoot and Status requests.

LiveNetworkEventSource
    Implements NetworkEventSource.
    Bridges connection events to NetworkService events.
"""

from .event_source import LiveNetworkEventSource
from .reqresp_client import ReqRespClient

__all__ = [
    "LiveNetworkEventSource",
    "ReqRespClient",
]
