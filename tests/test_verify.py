import pytest
import six

from porridge import Porridge, MissingKeyError
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
