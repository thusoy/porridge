import pytest
import six

from porridge import Porridge, MissingKeyError
from porridge.utils import ensure_bytes


bytes_and_unicode_password = pytest.mark.parametrize("password", [
    u"pässword".encode("latin1"),
    u"pässword",
])


@bytes_and_unicode_password
def test_verify(password):
    """
    Verification works with unicode and bytes.
    """
    porridge = Porridge(encoding='latin1')
    encoded = (  # handrolled test vector lifted from argon2_cffi
        "$argon2i$m=8,t=1,p=1$"
        "bL/lLsegFKTuR+5vVyA8tA$VKz5CHavCtFOL1N5TIXWSA"
    )

    assert porridge.verify(password, encoded)


def test_verify_self(porridge):
    password = 'password'
    assert porridge.verify(password, porridge.boil(password))


@bytes_and_unicode_password
def test_attacker_cant_verify_without_secret(password):
    our_porridge = Porridge(secrets=[('id1', 'key1')])
    attacker_porridge = Porridge()
    encoded_password = our_porridge.boil(password)
    with pytest.raises(MissingKeyError):
        attacker_porridge.verify(password, encoded_password)
