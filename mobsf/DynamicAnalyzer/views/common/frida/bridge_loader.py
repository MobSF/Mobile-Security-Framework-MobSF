"""
Frida Bridge Loader Utility.

This module provides utilities for injecting Frida bridges into scripts
to support newer Frida versions (17.0.0+) where bridges are no longer
bundled with the runtime.
"""

import logging
from pathlib import Path

from packaging.version import Version

logger = logging.getLogger(__name__)


class FridaBridgeLoader:
    """Utility class for injecting Frida bridges into scripts for Frida 17.0.0+."""

    def __init__(self):
        self._frida_17_plus = False
        self._bridge_files_path = None
        self._init_frida_info()

    def _init_frida_info(self):
        """Initialize Frida version information and bridge availability."""
        try:
            import frida
            frida_version = frida.__version__
            self._frida_17_plus = Version(frida_version) >= Version('17.0.0')

            if self._frida_17_plus:
                self._check_bridge_files_availability()
        except ImportError:
            logger.error('Frida not available')
        except Exception:
            logger.exception('Error detecting Frida version')

    def _check_bridge_files_availability(self):
        """Check if bridge files are available in frida_tools."""
        try:
            import frida_tools
            frida_tools_path = Path(frida_tools.__file__).parent
            bridges_path = frida_tools_path / 'bridges'

            if bridges_path.exists():
                java_bridge = bridges_path / 'java.js'
                objc_bridge = bridges_path / 'objc.js'

                if java_bridge.exists() and objc_bridge.exists():
                    self._bridge_files_path = bridges_path
                else:
                    logger.error(
                        'Bridge files not found in frida_tools: %s', bridges_path)
            else:
                logger.error(
                    'No bridges directory found in frida_tools: %s', bridges_path)

        except ImportError:
            logger.error(
                'frida_tools not available - scripts using Java/ObjC objects '
                'will FAIL')
        except Exception:
            logger.exception('Error checking bridge files')

    def is_required_and_available(self):
        """Check if bridge injection is required and available."""
        return self._frida_17_plus and self._bridge_files_path is not None

    def inject_bridge_support(self, script_content, bridge_type='java'):
        """
        Inject bridge support into script for Frida 17.0.0+.

        For Frida 17+, bridges are required and must be concatenated as text
        since frida.Compiler.build() creates bundles, not injectable JavaScript.
        This method prepends bridge JavaScript to the script content.
        """
        try:
            # Select the appropriate bridge file
            if bridge_type.lower() == 'objc':
                bridge_file = self._bridge_files_path / 'objc.js'
                bridge_name = 'ObjC'
            else:
                bridge_file = self._bridge_files_path / 'java.js'
                bridge_name = 'Java'

            if not bridge_file.exists():
                logger.error('Bridge file not found: %s', bridge_file)
                return script_content

            # Read bridge content as text
            bridge_content = bridge_file.read_text('utf-8')

            # For Frida 17+, we concatenate bridge + script as plain text
            # This creates injectable JavaScript that includes the bridge
            combined_script = f"""// Frida 17+ Bridge Support - {bridge_name}

{bridge_content}

Object.defineProperty(globalThis, '{bridge_name}', {{
    value: bridge,
    writable: false,
    enumerable: true,
    configurable: false
}});

// User Script Contents starts here
{script_content}
"""

            return combined_script

        except Exception:
            logger.exception('Failed to inject bridge support into script')
            logger.warning(
                'Returning original script - may not work with Frida 17.0.0+')
            return script_content


def get_bridge_loader():
    """Get the global bridge loader instance."""
    return FridaBridgeLoader()
