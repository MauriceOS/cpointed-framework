# Made by Sn0w8ird


class CPointedError(Exception):
    """Base error for cpointed."""


class SessionError(CPointedError):
    """HTTP session or TLS failure."""


class ExploitFailedError(CPointedError):
    """Exploit chain did not achieve expected outcome."""


class UnauthorizedOperationError(CPointedError):
    """Operation blocked pending explicit research authorization."""
