import pytest

from porridge import Porridge


@pytest.fixture
def porridge():
    '''A Porridge-instance suitable for testing.

    Does no environment check and has very fast parameters.
    '''
    return Porridge(time_cost=1, memory_cost=8, parallelism=1)
