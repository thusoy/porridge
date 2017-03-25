def test_boil_unique(porridge):
    assert porridge.boil('password') != porridge.boil('password')
