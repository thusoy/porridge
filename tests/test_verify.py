# coding: utf-8

from __future__ import unicode_literals

import pytest

from porridge import Porridge, MissingKeyError, EncodedPasswordError
from porridge.utils import ensure_bytes


@pytest.mark.parametrize('password', (
    "pässword".encode("latin-1"),
    "pässword",
))
def test_verify(password):
    """
    Verification works with unicode and bytes.
    """
    porridge = Porridge('keyid1:key1', encoding='latin1')
    encoded = (  # handrolled test vector lifted from argon2_cffi
        "$argon2i$m=8,t=1,p=1$"
        "bL/lLsegFKTuR+5vVyA8tA$VKz5CHavCtFOL1N5TIXWSA"
    )

    assert porridge.verify(password, encoded)


def test_verify_self(porridge, password):
    assert porridge.verify(password, porridge.boil(password))


def test_invalid_password(porridge):
    assert porridge.verify('pass1', porridge.boil('pass2')) == False


def test_attacker_cant_verify_without_secret(password):
    our_porridge = Porridge('id1:key1')
    attacker_porridge = Porridge('otherid:otherkey')
    encoded_password = our_porridge.boil(password)
    with pytest.raises(MissingKeyError):
        attacker_porridge.verify(password, encoded_password)


def test_verify_invalid_password_type(porridge):
    with pytest.raises(TypeError) as exception:
        porridge.verify(1, '')

    assert exception.value.args[0].startswith("'password' must be a str")


@pytest.mark.parametrize('encoded', (
    # these are all encoded versions of 'password'
    '$argon2i$v=19$m=512,t=2,p=2$Vr7zN80DmEZdRQcMGeV2lA$/fcYY5wcLE9YR4ttKuwshw',
    '$argon2i$v=16$m=8,t=1,p=1$bXlzYWx0eXNhbHQ$nz8csvIXGASHCkUia+K4Zg',
    '$argon2i$m=8,t=1,p=1$bXlzYWx0eXNhbHQ$nz8csvIXGASHCkUia+K4Zg',
))
def test_verify_legacy_passwords_without_secret(porridge, encoded):
    assert porridge.verify('password', encoded)


@pytest.mark.parametrize('encoded', (
    'definitely not a valid',
    '$argon2i$m=8,t=1,p=1$bXlzYWx0eXNhbHQ$nz8csvIXGASHCkUia+K4Zg' + 'a' * 207,
))
def test_verify_invalid_encode(porridge, encoded):
    with pytest.raises(EncodedPasswordError):
        porridge.verify('password', encoded)
