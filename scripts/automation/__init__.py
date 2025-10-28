"""Automation connector registry for controlled exploitation."""

from .base import AutomationConnector
from .metasploit import MetasploitConnector
from .zap import ZAPConnector
from .nuclei import NucleiConnector
from .sqlmap import SQLMapConnector


def get_connector_registry():
    """Return mapping of connector identifiers to classes."""
    return {
        MetasploitConnector.name: MetasploitConnector,
        ZAPConnector.name: ZAPConnector,
        NucleiConnector.name: NucleiConnector,
        SQLMapConnector.name: SQLMapConnector,
    }


__all__ = [
    'AutomationConnector',
    'MetasploitConnector',
    'ZAPConnector',
    'NucleiConnector',
    'SQLMapConnector',
    'get_connector_registry',
]
