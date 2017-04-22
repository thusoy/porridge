# coding: utf-8

from __future__ import unicode_literals

import pytest
from hypothesis import given, assume
from hypothesis.strategies import integers, text

from porridge import Porridge, MissingKeyError, EncodedPasswordError
from porridge.utils import ensure_bytes


@pytest.mark.parametrize('test_password', (
    "pässword".encode("latin-1"),
    "pässword",
))
def test_verify(test_password):
    """
    Verification works with unicode and bytes.
    """
    porridge = Porridge('keyid1:key1', encoding='latin1')
    encoded = (  # handrolled test vector lifted from argon2_cffi
        "$argon2i$m=8,t=1,p=1$"
        "bL/lLsegFKTuR+5vVyA8tA$VKz5CHavCtFOL1N5TIXWSA"
    )

    assert porridge.verify(test_password, encoded)


@given(text())
def test_verify_self(porridge, given_password):
    assert porridge.verify(given_password, porridge.boil(given_password))


@given(
    time_cost=integers(1, 5),
    memory_cost=integers(0, 513),
    parallelism=integers(1, 5),
)
def test_verify_custom_parameters(password, time_cost, memory_cost, parallelism):
    assume(parallelism * 8 <= memory_cost)
    porridge = Porridge('key:secret', time_cost=time_cost, memory_cost=memory_cost,
        parallelism=parallelism)
    assert porridge.verify(password, porridge.boil(password))


def test_verify_self_default_parameters(password):
    porridge = Porridge('key:secret')
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
def test_verify_legacy_passwords_without_secret(encoded):
    # Set high enough parameters to avoid triggering the safety check
    porridge = Porridge('key1:secret1', memory_cost=256, time_cost=1, parallelism=2)
    assert porridge.verify('password', encoded)


@pytest.mark.parametrize('encoded', (
    'definitely not a valid',
    '$argon2i$m=8,t=1,p=1$bXlzYWx0eXNhbHQ$nz8csvIXGASHCkUia+K4Zg' + 'a' * 207,
))
def test_verify_invalid_encode(porridge, encoded):
    with pytest.raises(EncodedPasswordError):
        porridge.verify('password', encoded)


@pytest.mark.parametrize('parameter', ('time_cost', 'memory_cost', 'parallelism'))
def test_verify_bails_on_values_higher_than_configured(porridge, parameter):
    parameters = {
        'time_cost': porridge.time_cost,
        'memory_cost': porridge.memory_cost,
        'parallelism': porridge.parallelism,
    }
    parameters[parameter] *= porridge.parameter_threshold + 1
    encoded = get_encoded_password_with_parameters(parameters)
    with pytest.raises(EncodedPasswordError):
        porridge.verify('password', encoded)


@pytest.mark.parametrize('parameter', ('time_cost', 'memory_cost', 'parallelism'))
@given(threshold=integers(1, 8))
def test_verify_doesnt_bail_on_values_equal_to_threshold(parameter, threshold):
    # Create an instance where memory_cost is at least the highest parallelism*8
    porridge = Porridge('key1:secret1', memory_cost=64, time_cost=1, parallelism=1,
        parameter_threshold=threshold)
    parameters = {
        'time_cost': porridge.time_cost,
        'memory_cost': porridge.memory_cost,
        'parallelism': porridge.parallelism,
    }
    parameters[parameter] *= porridge.parameter_threshold
    encoded = get_encoded_password_with_parameters(parameters)
    # Since the parameters are wrong the password should not be valid
    assert porridge.verify('password', encoded) == False


def get_encoded_password_with_parameters(parameters):
    template = '$argon2i$v=19$m={memory_cost},t={time_cost},p={parallelism}{tail}'
    tail = ',keyid=key1$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'
    return template.format(tail=tail, **parameters)
