import pytest

from porridge import Porridge


PORRIDGES = (
    Porridge('key1:secret1',
        time_cost=1,
        memory_cost=8,
        parallelism=1,
    ),
    Porridge('key2:secret2,key1:secret1',
        time_cost=1,
        memory_cost=8,
        parallelism=1,
    )
)

@pytest.fixture(params=PORRIDGES)
def porridge(request):
    '''A Porridge-instance suitable for testing.

    Does no environment check and has very fast parameters.
    '''
    return request.param


PASSWORDS = (
    "pässword".encode("latin-1"), # bytes
    "pässword", # unicode
    "password", # plain ascii
)

@pytest.fixture(params=PASSWORDS)
def password(request):
    '''A valid password, both as unicode and bytes'''
    return request.param
