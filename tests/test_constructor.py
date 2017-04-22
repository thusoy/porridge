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
