class DcpError(Exception):
    """Base class of the errors thrown by this DCP lib."""
    pass


class DcpTimeoutError(DcpError):
    """Thrown if a timeout occurs withing this DCP lib."""
    pass
