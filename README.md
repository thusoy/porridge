# porridge [![Build Status](https://travis-ci.org/thusoy/porridge.svg?branch=master)](https://travis-ci.org/thusoy/porridge) [![Windows build status](https://ci.appveyor.com/api/projects/status/y51rewx877d522b5/branch/master?svg=true)](https://ci.appveyor.com/project/thusoy/porridge/branch/master)

Simple, strong and standardized keyed password storage.

Keyed password storage utilizes server-side secrets to ensure passwords cannot be brute-forced offline if the encoded passwords are leaked. A leak could happen through a SQL injection or a compromised database backup, or a host of other sadly quite common webapp vulnerabilities.

While many password storage schemes like PBKDF2, bcrypt, scrypt and the likes will make recovering the passwords offline slow, a resourceful and patient attacker will eventually be able to recover most of them. Porridge makes this entirely impossible unless your secret is also leaked, which is often not the case for many common vulnerabilities.

Note that utilizing porridge is not magical solution to passwords on the internet, a complete solution should still enforce at least a password policy, secure password resets, rate-limiting and U2F/2FA. Have experienced security engineers set up something for you, or use high-level libraries that care of it for you.


Usage
-----

```python
import os
from porridge import Porridge

porridge = Porridge(os.environ['PORRIDGE_SECRETS'])

encoded_password = porridge.boil('password')
if porridge.verify('password', encoded_password):
    print('Success!')
else:
    print('Fail!')
```

If the PORRIDGE_SECRETS is a comma separated list of `keyid:key` pairs, this setup will ensure that even if your database is leaked, your users' passwords are irrecoverable by an attacker.

This shell snippet is handy to create strong secrets:

```bash
$ echo "$(date +%Y%m%d):$(openssl rand -base64 30)"
```

This string will thus grow regularly. After some time, it'll look something like

    keyid3:key3,keyid2:key2,keyid1:key1

The first key in the list (in this case, keyid3) will be used to boil new passwords.

Old keys are necessary to verify the passwords of users who haven't logged in since the secret was rotated. Secrets can be dropped from the config when no users have passwords using that id anymore, which you can tell from the `keyid` field in the encoded password.


Local development
-----------------

    $ ./configure
    $ ./test

Continually running tests whenever source changes:

    $ ./tools/watch_and_run_tests.sh


Motivation
----------

I couldn't find any existing solutions that utilizes argon2's server-side secret feature, as most libraries only wrap the high-level interfaces, which sadly don't enable setting secrets.

Some guiding principles for this project:

- People should not have to configure cryptographic parameters
- UX is a security feature
- The database is not trusted, neither to keep things secret, nor to keep things sane
- Following nothing more than the quickstart should result in a very secure implementation
- Migrating from existing solutions should be easy


Maintenance
-----------

Keeping this running over an extended period requires two things:
    - Adding new secrets regularly (twice a year is probably fine), and whenever you suspect a breach
    - Using `needs_update()` to store new encodes where the password was stored with old parameters

The first is to ensure that if your servers at one point is compromised, future passwords are not impacted. 

The second point ensures that every time one of your users log in, the parameters their existing encoded password is stored under are still strong and the secret current, otherwise it'll be re-stored.

The only thing you need to do this is to check `needs_update()` after a password has been verified, and to store the updated one if that's the case:

```python
import os
from porridge import Porridge

porridge = Porridge(os.environ['PORRIDGE_SECRETS'])

password = ... # get this from the user
old_encoded_password = ... # Get this from your database

if porridge.verify(password, old_encoded_password):
    print('Success!')
    if porridge.needs_update(old_encoded_password):
        # update the password in the database
        new_encoded_password = porridge.boil(password)
        print('Storing new encoded password to database')
else:
    print('Fail!')
```

The default parameters will be bumped regularly with new releases of porridge, thus as long as you install updates this should keep everything fresh.


FAQ
---

*Q: I notice the word "hash" isn't used much by porridge, why?*
A: Because it's too easy to get stuff wrong when communicated to people who are not cryptographers, which include most of us. Experienced cryptographers do a mental translation of "hash" to "memory-hard key stretching" whenever they're in a password context, but the rest of us don't. Thus it's too easy for non-cryptographers to write password storage solutions that either store passwords in plaintext, or just use an actual "hash", leading to puppies dying left and right. Thus for porridge, passwords are stored in "encoded form", and to get a password in encoded form you "boil" it. If non-cryptographers hear that they're supposed to boil passwords, any decent search engine will ensure they end up with a very robust solution.

*Q: How do I migrate to porridge from pbkdf2/bcrypt/scrypt/plain argon2?*
A: Add a new column in your database to store the new encoded passwords, add porridge and boil passwords with it in addition to your existing scheme and store them to the new column. When verifying, verify with both your existing scheme and porridge if there's anything in the new column. When you deem that few enough users haven't gotten their passwords encoded by porridge yet, drop the old password column and stop using the old scheme. The users who hasn't gotten new encoded passwords will be forced through password reset, but otherwise no one will notice any difference. If you are already using argon2 but without server-side secrets, porridge can dropped in directly. Note that the max length of an encoded password is *265* characters, but that requires using the associated data feature that is not exposed through porridge, so you're probably fine if your existing columns only allows 255 characters.

*Q: Why "porridge"?*
A: Because good porridge requires more than just salt, takes a long time to boil, and you cannot separate its ingredients  after they've been boiled. And I was hungry when starting writing this. And we need better terminology for password storage, see the first question.


Alternatives
------------

If you can't apply server-side secrets, plain [argon2](https://github.com/hynek/argon2_cffi) is the recommended way to store your passwords as of best practices in 2017. To utilize server-side secrets with other schemes you can HMAC the password with your secret before passing it to your key stretching function, but it'll be very hard to rotate this secret without invalidating all your passwords.


Credits
-------

Many thanks to [argon2_cffi](https://github.com/hynek/argon2_cffi) for a great starting point for wrapping argon2.
