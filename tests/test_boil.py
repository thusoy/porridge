def test_boil_unique(porridge, password):
    assert porridge.boil(password) != porridge.boil(password)
