import pytest

from porridge import Porridge, PorridgeError

def test_boil_unique(porridge):
    assert porridge.boil('password') != porridge.boil('password')


def test_good_exception_on_memory_allocation_error():
    '''Tries to allocate 1TB for password hashing, which is hopefully more
    than what is available on any machine that tries to run the tests, or this
    test will take a long-ass time to finish.
    '''
    porridge = Porridge('key:secret', memory_cost=1000000000)
    with pytest.raises(PorridgeError) as exception:
        porridge.boil('password')
    assert 'Memory allocation' in exception.value.args[0]
