# coding: utf-8

from __future__ import unicode_literals

import pytest

from porridge.utils import ensure_bytes, b64_decode_raw, b64_encode_raw

raw_b64_string = pytest.mark.parametrize('raw_b64_string', [
    ('YQ', b'a'),
    ('YWE', b'aa'),
    ('YWFh', b'aaa'),
    ('', b''),
    ('AA==', b'\x00'),
    ('AA', b'\x00'),
])


def test_ensure_bytes_with_bytes():
    """
    Bytes are just returned.
    """
    s = "föö".encode("utf-8")

    rv = ensure_bytes(s, "doesntmatter")

    assert isinstance(rv, bytes)
    assert s == rv


def test_ensure_bytes_with_unicode():
    """
    Unicode is encoded using the specified encoding.
    """
    s = u"föö"

    rv = ensure_bytes(s, "latin1")

    assert isinstance(rv, bytes)
    assert s.encode("latin1") == rv


@raw_b64_string
def test_b64_decode_raw(raw_b64_string):
    raw_string, expected = raw_b64_string
    assert b64_decode_raw(raw_string) == expected


def test_b64_encode_raw():
    # assert b64_encode_raw('') == ''
    assert b64_encode_raw(b'') == ''
    assert b64_encode_raw(b'a') == 'YQ'
    assert b64_encode_raw(b'aa') == 'YWE'
    assert b64_encode_raw(b'aaa') == 'YWFh'
