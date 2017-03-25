import contextlib
import os
import re

from argon2.low_level import (
    ARGON2_VERSION,
    Type,
    core,
    ffi,
    lib,
)

from .utils import check_types, ensure_bytes, b64_decode_raw, b64_encode_raw
from .exceptions import PorridgeError, MissingKeyError, ParameterError

# TODO: Compute these dynamically for the target environment. Prefer magic to people having to configure cryptographic parameters.
DEFAULT_RANDOM_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_PARALLELISM = 2
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET

# This regex validates the spec from
# https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
ENCODED_HASH_RE = re.compile(r''.join([
    # TODO: Validate max lengths of fields
        r'^\$argon2i\$',
        r'(?:v=(?P<version>[0-9]+)\$)?',
        r''.join([
            r'm=(?P<memory_cost>[0-9]{1,10})',
            r',t=(?P<time_cost>[0-9]{1,10})',
            r',p=(?P<parallelism>[0-9]{1,3})',
            r'(?:,keyid=(?P<keyid>[a-zA-Z0-9+/]+))?', # optional
            r'(?:,data=(?P<data>[a-zA-Z0-9+/]+))?', # optional, unused
        ]),
        r'\$(?P<salt>[a-zA-Z0-9+/]+)\$',
        r'(?P<hash>[a-zA-Z0-9+/]+)',
    ]) + r'$'
)


class Porridge(object):
    r"""
    High level class to hash passwords with sensible defaults.

    Uses *always* Argon2\ **i** and a random salt_.

    The reason for this being a class is both for convenience to carry
    parameters and to verify the parameters only *once*. Any unnecessary
    slowdown when hashing is a tangible advantage for a brute force attacker.

    :param str secrets: A comma-separated string of keyid:key pairs that will be used for
        keyed hashing. The first element in the list will be used to boil new passwords,
        the others to verify old ones.
    :param int time_cost: Defines the amount of computation realized and
        therefore the execution time, given in number of iterations.
    :param int memory_cost: Defines the memory usage, given in kibibytes_.
    :param int parallelism: Defines the number of parallel threads (*changes*
        the resulting hash value).
    :param int hash_len: Length of the hash in bytes.
    :param int salt_len: Length of random salt to be generated for each
        password.
    :param str encoding: The Argon2 C library expects bytes.  So if
        :meth:`hash` or :meth:`verify` are passed an unicode string, it will be
        encoded using this encoding.

    .. versionadded:: 16.0.0

    .. _salt: https://en.wikipedia.org/wiki/Salt_(cryptography)
    .. _kibibytes: https://en.wikipedia.org/wiki/Binary_prefix#kibi
    """
    __slots__ = [
        "time_cost", "memory_cost", "parallelism", "hash_len", "salt_len",
        "encoding", "secret_map", "secret", "keyid"
    ]

    def __init__(
        self,
        secrets,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        hash_len=DEFAULT_HASH_LENGTH,
        salt_len=DEFAULT_RANDOM_SALT_LENGTH,
        encoding="utf-8",
    ):
        e = check_types(
            secrets=(secrets, str),
            time_cost=(time_cost, int),
            memory_cost=(memory_cost, int),
            parallelism=(parallelism, int),
            hash_len=(hash_len, int),
            salt_len=(salt_len, int),
            encoding=(encoding, str),
        )
        if e:
            raise TypeError(e)

        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.encoding = encoding

        self.secret_map = {}
        self.secret = None
        self.keyid = None
        for secret_pair in secrets.split(','):
            keyid, secret = secret_pair.split(':', 1)
            keyid = self._ensure_bytes(keyid)
            secret = self._ensure_bytes(secret)
            if self.secret is None:
                self.secret = secret
                self.keyid = keyid
            self.secret_map[keyid] = secret

        self._self_check()


    def _self_check(self):
        """
        Perform a single run of boiling to ensure we have a valid
        combination of parameters.
        """
        self.boil('dummy')


    def _ensure_bytes(self, s):
        return ensure_bytes(s, self.encoding)


    def boil(self, password):
        """
        Boil *password* and return and encoded password that can be stored in a
        database.

        :param password: Password to boil.
        :type password: ``bytes`` or ``unicode``

        :raises argon2.exceptions.HashingError: If hashing fails.

        :rtype: unicode
        """
        salt = os.urandom(self.salt_len)
        context_params = dict(
            salt=salt,
            password=ensure_bytes(password, self.encoding),
            secret=ensure_bytes(self.secret, self.encoding) if self.secret else None,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
        )
        with argon2_context(**context_params) as ctx:
            result = core(ctx, Type.I.value)

            if result != lib.ARGON2_OK:
                error_message = argon2_error_message(result)
                if is_operational_error(result):
                    raise PorridgeError(error_message)
                else:
                    raise ParameterError(error_message)

            raw_hash = bytes(ffi.buffer(ctx.out, ctx.outlen))
        return self._encode(raw_hash, salt)


    def verify(self, password, encoded):
        """
        Verify that *password* matches *encoded*.

        :param unicode hash: An encoded hash as returned from
            :meth:`PasswordHasher.hash`.
        :param password: The password to verify.
        :type password: ``bytes`` or ``unicode``

        :raises argon2.exceptions.VerifyMismatchError: If verification fails
            because *hash* is not valid for *secret* of *type*.
        :raises argon2.exceptions.VerificationError: If verification fails for
            other reasons.

        :return: ``True`` on success, raise
            :exc:`~argon2.exceptions.VerificationError` otherwise.
        :rtype: bool

        .. versionchanged:: 16.1.0
            Raise :exc:`~argon2.exceptions.VerifyMismatchError` on mismatches
            instead of its more generic superclass.
        """
        assert len(encoded) < 1024 # Ensure we don't DDoS ourselves if the database holds corrupt values
        # TODO: Ensure hashed values are maximum double of what we're configured with
        # TODO: Test migrating parameters
        # encoded = ensure_bytes(encoded, self.encoding)
        match = ENCODED_HASH_RE.match(encoded)
        assert match, 'Encoded password is on unknown format: %s' % encoded
        version = match.group('version')
        if version:
            version = int(version)
        else:
            # Default to the old version as only ARGON2_VERSION_13 includes it in the encoded string
            version = lib.ARGON2_VERSION_10

        salt = b64_decode_raw(match.group('salt'))
        raw_hash = b64_decode_raw(match.group('hash'))
        time_cost = int(match.group('time_cost'))
        memory_cost = int(match.group('memory_cost'))
        parallelism = int(match.group('parallelism'))

        context_params = dict(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=len(raw_hash),
            salt=salt,
            password=self._ensure_bytes(password),
            version=version,
        )

        keyid = match.group('keyid')
        if keyid:
            binary_keyid = keyid.encode('utf-8')
            secret = self.secret_map.get(binary_keyid)
            if not secret:
                raise MissingKeyError(keyid)
            context_params['secret'] = secret

        with argon2_context(**context_params) as ctx:
            result = lib.argon2i_verify_ctx(ctx, raw_hash)

        if result == lib.ARGON2_OK:
            return True
        elif result == lib.ARGON2_VERIFY_MISMATCH:
            return False
        else:
            error_message = argon2_error_message(result)
            raise PorridgeError(error_message)


    def _encode(self, raw_hash, salt):
        template = (
            '${algo}$v={version}$m={m_cost},t={t_cost},p={parallelism}'
            ',keyid={keyid}${salt}${hash}'
        )
        return template.format(
                algo='argon2i',
                t_cost=self.time_cost,
                m_cost=self.memory_cost,
                parallelism=self.parallelism,
                salt=b64_encode_raw(salt),
                hash=b64_encode_raw(raw_hash),
                version=ARGON2_VERSION,
                keyid=self.keyid.decode(self.encoding),
            )


def argon2_error_message(error_code):
    return ffi.string(lib.argon2_error_message(error_code)).decode('utf-8')


def is_operational_error(error_code):
    return error_code in set([
        lib.ARGON2_THREAD_FAIL,
        lib.ARGON2_MEMORY_ALLOCATION_ERROR,
    ])


@contextlib.contextmanager
def argon2_context(
        password=None, # bytes
        salt=None,
        secret=None,
        hash_len=DEFAULT_HASH_LENGTH,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        flags=DEFAULT_FLAGS,
        version=ARGON2_VERSION,
        ):
    csalt = ffi.new("uint8_t[]", salt)
    cout = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password)

    if secret:
        csecret = ffi.new("uint8_t[]", secret)
        secret_len = len(secret)
    else:
        csecret = ffi.NULL
        secret_len = 0

    ctx = ffi.new("argon2_context *", dict(
            version=version,
            out=cout, outlen=hash_len,
            pwd=cpwd, pwdlen=len(password),
            salt=csalt, saltlen=len(salt),
            secret=csecret, secretlen=secret_len,
            ad=ffi.NULL, adlen=0,
            t_cost=time_cost,
            m_cost=memory_cost,
            lanes=parallelism, threads=parallelism,
            allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
            flags=DEFAULT_FLAGS,
        )
    )
    yield ctx
