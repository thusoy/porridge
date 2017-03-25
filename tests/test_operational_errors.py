import resource

import pytest

from porridge import Porridge, PorridgeError


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


def test_operational_error_on_threading_error_on_boil():
    original_limits = resource.getrlimit(resource.RLIMIT_NPROC)
    new_limits = (100, original_limits[1])
    resource.setrlimit(resource.RLIMIT_NPROC, new_limits)
    parallelism = new_limits[0] + 1
    memory_cost = 8*parallelism
    with pytest.raises(PorridgeError) as exception:
        Porridge('key:secret', parallelism=parallelism, memory_cost=memory_cost)
    assert exception.value.args[0] == 'Threading failure'
    resource.setrlimit(resource.RLIMIT_NPROC, original_limits)


def test_operational_error_on_threading_error_on_verify(porridge):
    # 'password' encoded with key 'secret', then just overwriting the costs
    encoded_template = (
        '$argon2i$v=19$m={memory_cost},t=1,p={parallelism},keyid=key1$nZOoCCqcGHXS0w3JBFK1ng$'
        'eBNrzME/WOyM7N2Hk8Oz8sDGa8b/L3k0RD85JsN49zA'
    )
    original_limits = resource.getrlimit(resource.RLIMIT_NPROC)
    new_limits = (100, original_limits[1])
    resource.setrlimit(resource.RLIMIT_NPROC, new_limits)
    parallelism = new_limits[0] + 1
    memory_cost = 8*parallelism
    encoded = encoded_template.format(
        memory_cost=memory_cost,
        parallelism=parallelism,
    )
    with pytest.raises(PorridgeError) as exception:
        porridge.verify('password', encoded)
    assert exception.value.args[0] == 'Threading failure'
    resource.setrlimit(resource.RLIMIT_NPROC, original_limits)
