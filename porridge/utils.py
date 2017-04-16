import base64
import sys

PY2 = sys.version_info < (3, 0, 0)

if PY2: # pragma: no cover
    string_types = (str, unicode)
else:
    string_types = (str,)


def ensure_bytes(s, encoding):
    """
    Ensure *s* is a bytes string.  Encode using *encoding* if it isn't.
    """
    if isinstance(s, bytes):
        return s
    return s.encode(encoding)


def check_types(**kw):
    """
    Check each ``name: (value, types)`` in *kw*.

    Returns a human-readable string of all violations or `None``.
    """
    errors = []
    for name, (value, types) in kw.items():
        if not isinstance(value, types):
            if isinstance(types, tuple):
                types = " or ".join(t.__name__ for t in types)
            else:
                types = types.__name__
            errors.append("'{name}' must be a {type} (got {actual})".format(
                name=name,
                type=types,
                actual=type(value).__name__,
            ))

    if errors:
        return ", ".join(errors) + "."


def b64_decode_raw(encoded):
    '''Decode basse64 string without padding'''
    return base64.b64decode(encoded + ('='*((4 - len(encoded) % 4) % 4)))


def b64_encode_raw(bytestring):
    return base64.b64encode(bytestring).decode('ascii').rstrip('=')
