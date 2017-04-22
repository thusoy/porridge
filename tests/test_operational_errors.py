import contextlib
import os
import sys
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False
try:
    from unittest import mock
except ImportError:
    import mock

import pytest

from porridge import Porridge, PorridgeError

SKIP_THREADING_TESTS = not HAS_RESOURCE or os.environ.get('WITH_THREADING_TESTS', '0') == '0'
SKIP_MEMORY_ALLOC_TESTS = sys.maxsize <= 2**32 or sys.platform == 'darwin'


def test_operational_error_memory_allocation_error_boil_mock(porridge):
    lib_mock = mock.Mock()
    # Ref. https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h#L131
    lib_mock.return_value = -22
    with mock.patch('porridge.porridge.compute_hash', lib_mock):
        with pytest.raises(PorridgeError) as exception:
            porridge.boil('password')
        assert 'Memory allocation' in exception.value.args[0]


def test_operational_error_memory_allocation_error_verify_mock():
    lib_mock = mock.Mock()
    # Ref. https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h#L131
    lib_mock.return_value = -22

    # 'password' encoded with key 'secret'
    encoded = (
        '$argon2i$v=19$m=512,t=2,p=4,keyid=key$Zs0La+XTLuJ9fpmXnUneCA$'
        '5dJXxTR/z/i7Bre6BM4RUEKeStSoVU8yzY+a+UxwnT8'
    )
    porridge = Porridge('key:secret')
    with mock.patch('porridge.porridge.verify_hash', lib_mock):
        with pytest.raises(PorridgeError) as exception:
            porridge.verify('password', encoded)
        assert 'Memory allocation' in exception.value.args[0]


@pytest.mark.skipif(SKIP_MEMORY_ALLOC_TESTS, reason='Skipping on 32bit platforms')
def test_operational_error_memory_allocation_error_on_boil():
    '''Tries to allocate 1TB for password hashing, which is hopefully more
    than what is available on any machine that tries to run the tests, or this
    test will take a long-ass time to finish.
    '''
    with pytest.raises(PorridgeError) as exception:
        porridge = Porridge('key:secret', memory_cost=1000000000)
    assert 'Memory allocation' in exception.value.args[0]


@pytest.mark.skipif(SKIP_MEMORY_ALLOC_TESTS, reason='Skipping on 32bit platforms')
def test_operational_error_memory_allocation_error_on_verify(porridge):
    '''Tries to allocate 1TB for password hashing, which is hopefully more
    than what is available on any machine that tries to run the tests, or this
    test will take a long-ass time to finish.
    '''
    # 'password' encoded with key 'secret', then just overwriting the m-value
    encoded = (
        '$argon2i$v=19$m=1000000000,t=1,p=1,keyid=key1$nZOoCCqcGHXS0w3JBFK1ng$'
        'eBNrzME/WOyM7N2Hk8Oz8sDGa8b/L3k0RD85JsN49zA'
    )
    # Remove the safety check to allow this test to go through
    with mock.patch.object(porridge, '_verify_parameters_within_threshold'):
        with pytest.raises(PorridgeError) as exception:
            porridge.verify('password', encoded)
    assert 'Memory allocation' in exception.value.args[0]


@pytest.mark.skipif(SKIP_THREADING_TESTS, reason='Skipping threading tests')
def test_operational_error_on_threading_error_on_boil():
    with nproc_soft_limit(100) as limits:
        parallelism = limits[0]*2
        memory_cost = 8*parallelism
        with pytest.raises(PorridgeError) as exception:
            Porridge('key:secret', parallelism=parallelism, memory_cost=memory_cost)
    assert exception.value.args[0] == 'Threading failure'


@pytest.mark.skipif(SKIP_THREADING_TESTS, reason='Skipping threading tests')
def test_operational_error_on_threading_error_on_verify(porridge):
    # 'password' encoded with key 'secret', then just overwriting the costs
    encoded_template = (
        '$argon2i$v=19$m={memory_cost},t=1,p={parallelism},keyid=key1$'
        'nZOoCCqcGHXS0w3JBFK1ng$eBNrzME/WOyM7N2Hk8Oz8sDGa8b/L3k0RD85JsN49zA'
    )
    with nproc_soft_limit(100) as limits:
        parallelism = limits[0]*2
        memory_cost = 8*parallelism
        encoded = encoded_template.format(
            memory_cost=memory_cost,
            parallelism=parallelism,
        )
        with pytest.raises(PorridgeError) as exception:
            porridge.verify('password', encoded)
    assert exception.value.args[0] == 'Threading failure'


@contextlib.contextmanager
def nproc_soft_limit(soft_limit):
    original_limits = resource.getrlimit(resource.RLIMIT_NPROC)
    new_limits = (soft_limit, original_limits[1])
    resource.setrlimit(resource.RLIMIT_NPROC, new_limits)

    try:
        yield new_limits
    finally:
        resource.setrlimit(resource.RLIMIT_NPROC, original_limits)
