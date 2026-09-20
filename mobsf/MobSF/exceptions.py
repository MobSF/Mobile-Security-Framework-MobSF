"""MobSF custom exceptions."""


class PathTraversalError(Exception):
    """Raised when a path traversal attempt is detected."""


class ZipBombError(Exception):
    """Raised when a ZIP member exceeds the decompression limit."""
