import pytest


def test_boil_unique(porridge, password):
    assert porridge.boil(password) != porridge.boil(password)


def test_boil_invalid_password_type(porridge):
    with pytest.raises(TypeError) as exception:
        porridge.boil(1)

    assert exception.value.args[0].startswith("'password' must be a str")
