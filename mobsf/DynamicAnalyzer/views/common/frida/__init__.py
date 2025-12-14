"""
Frida utilities for MobSF Dynamic Analysis.

This package contains utilities for working with Frida in MobSF:
- bridge_loader: Handles Frida bridge injection for version 17.0.0+
- views: Frida-related web views and API endpoints
"""

from .bridge_loader import FridaBridgeLoader, get_bridge_loader

__all__ = ['FridaBridgeLoader', 'get_bridge_loader']
