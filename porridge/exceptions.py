"""
Porridge raises two kinds of exceptions, some you can catch and some you
shouldn't try to catch. Operational errors (PorridgeError) can happen
during normal operation (out of memory under high load, can't spawn more
threads) can be caught, because if this happens you might ask the user to
retry, or spin up more servers, or delegate the operation to another server.

The other set of errors are usage errors, which shouldn't be attempted caught,
since there's nothing you can do to recover apart from fixing your code. Thus
these should crash your app to ensure they are caught by monitoring and are
super loud.
"""


class PorridgeError(Exception):
    """
    Superclass of all porridge exceptions you should try to catch.
    """


class MissingKeyError(KeyError):
    """
    Raised if trying to verify a password boiled with a key we don't have.

    The missing key id is in ``args[0]``.
    """


class ParameterError(ValueError):
    """
    Raised if the Porridge constructor is called with an invalid combination of
    parameters.

    This is raised at construction time instead of at boiling time to ensure
    fail-fast behavior.
    """


class EncodedPasswordError(ValueError):
    """
    Raised if :meth:`verify` is given a boiled password that's either on an
    invalid format or has parameter significantly greater than what we're
    currently configured with.
    """
