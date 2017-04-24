import pytest

from porridge import Porridge, ParameterError


def test_invalid_parameters():
    with pytest.raises(ParameterError) as exception:
        porridge = Porridge('key:secret', time_cost=1, memory_cost=1)

    assert 'Memory cost is too small' == exception.value.args[0]


def test_invalid_parameter_types():
    with pytest.raises(TypeError) as exception:
        Porridge(1)
    assert exception.value.args[0].startswith("'secrets' must be a str")


def test_invalid_parameter_types_int():
    with pytest.raises(TypeError) as exception:
        Porridge('key:secret', time_cost='hello')
    assert exception.value.args[0].startswith("'time_cost' must be a int")


def test_invalid_threshold():
    with pytest.raises(ValueError) as exception:
        Porridge('key:secret', parameter_threshold=0)
    assert exception.value.args[0] == 'parameter_threshold must be at least 1'


def test_str():
    porridge = Porridge('key:secret,oldkey:oldsecret', memory_cost=8, time_cost=1,
        parallelism=1)
    assert str(porridge) == "Porridge(key='key', memory_cost=8, time_cost=1, parallelism=1)"


def test_repr():
    porridge = Porridge('key:secret,oldkey:oldsecret', memory_cost=8, time_cost=1,
        parallelism=1, parameter_threshold=2, hash_len=7, salt_len=9, encoding='latin-1')
    assert repr(porridge) == ("Porridge(key='key', memory_cost=8, time_cost=1, parallelism=1, "
        "hash_len=7, salt_len=9, parameter_threshold=2, encoding='latin-1')")
