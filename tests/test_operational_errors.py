import os
import resource
import contextlib

import pytest

from porridge import Porridge, PorridgeError

SKIP_THREADING_TESTS = os.environ.get('WITH_THREADING_TESTS', '0') == '0'


def test_operational_error_memory_allocation_error_on_boil():
    '''Tries to allocate 1TB for password hashing, which is hopefully more
    than what is available on any machine that tries to run the tests, or this
    test will take a long-ass time to finish.
    '''
    with pytest.raises(PorridgeError) as exception:
        porridge = Porridge('key:secret', memory_cost=1000000000)
    assert 'Memory allocation' in exception.value.args[0]


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
