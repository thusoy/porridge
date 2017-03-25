class PorridgeError(Exception):
    """
    Superclass of all porridge exceptions.

    Never thrown directly.
    """


class MissingKeyError(PorridgeError):
    """
    Raised if trying to verify a password encoded with a key we don't have.

    This should never be raised in a well-configured environment. The missing
    key id is in ``args[0]``.
    """
