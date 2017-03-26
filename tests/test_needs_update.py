import pytest

from porridge import Porridge

# All of these test cases are relative to the parameters of the Porridge
# instance created by `create_porridge()`

@pytest.mark.parametrize('reason,encoded', (
    ('old version, non-explicit', '$argon2i$m=16,t=2,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('old version, explicit', '$argon2i$v=16$m=16,t=2,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('lesser parallelism', '$argon2i$v=19$m=16,t=2,p=1,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('lesser memory cost', '$argon2i$v=19$m=8,t=2,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('lesser time cost', '$argon2i$v=19$m=16,t=1,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('shorter salt', '$argon2i$v=19$m=16,t=2,p=2,keyid=key$NuPQLVdIzpQ$vXvsYVvrrzRdOMpVLXgs4w'),
    ('shorter encode', '$argon2i$v=19$m=16,t=2,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$6tMIIoujQMCm25+NF34'),
    ('missing secret', '$argon2i$v=19$m=16,t=2,p=2$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('old secret', '$argon2i$v=19$m=16,t=2,p=2,keyid=oldkey$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
))
def test_needs_update_old_parameters(reason, encoded):
    porridge = create_porridge()

    assert porridge.needs_update(encoded), reason

    # old, explicit version
    assert porridge.needs_update('$argon2i$v=16$m=8,t=2,p=1$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w')


@pytest.mark.parametrize('reason,encoded', (
    ('identical', '$argon2i$v=19$m=16,t=2,p=2,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
    ('higher', '$argon2i$v=21$m=16,t=3,p=3,keyid=key$AhkxHIhp4o4KOuYBCbduUg$vXvsYVvrrzRdOMpVLXgs4w'),
))
def test_needs_update_up_to_date(reason, encoded):
    porridge = create_porridge()
    assert porridge.needs_update(encoded) == False, reason


def create_porridge():
    return Porridge('key:secret,oldkey:oldsecret',
        time_cost=2,
        memory_cost=16,
        parallelism=2,
        hash_len=16,
        salt_len=16,
    )
