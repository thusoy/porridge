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
from .exceptions import MissingKeyError

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
    parameters and to verify the parameters only *once*.   Any unnecessary
    slowdown when hashing is a tangible advantage for a brute force attacker.

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
    :param list secrets: A list of (keyid, key) tuples that will be used for
        keyed hashing. The first element in the list will be used for new
        hashes, the others to verify old ones.

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
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        hash_len=DEFAULT_HASH_LENGTH,
        salt_len=DEFAULT_RANDOM_SALT_LENGTH,
        encoding="utf-8",
        secrets=None,
    ):
        e = check_types(
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

        if secrets:
            self.secret_map = dict(secrets)
            self.secret = secrets[0][1]
            self.keyid = secrets[0][0]
        else:
            self.secret_map = {}
            self.secret = None
            self.keyid = None


    def boil(self, password):
        """
        Hash *password* and return an encoded hash.

        :param password: Password to hash.
        :type password: ``bytes`` or ``unicode``

        :raises argon2.exceptions.HashingError: If hashing fails.

        :rtype: unicode
        """
        salt = os.urandom(self.salt_len)
        context_params = dict(
            salt=salt,
            password=ensure_bytes(password, self.encoding),
            secret=ensure_bytes(self.secret, self.encoding) if self.secret else None,
            data=self.keyid,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
        )
        with argon2_context(**context_params) as ctx:
            result = core(ctx, Type.I.value)
            assert result == lib.ARGON2_OK, 'Result was %d' % result

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
            password=ensure_bytes(password, self.encoding),
            version=version,
        )

        keyid = match.group('keyid')
        if keyid:
            binary_keyid = keyid.encode('utf-8')
            secret = self.secret_map.get(binary_keyid)
            if not secret:
                raise MissingKeyError(keyid)
            assert secret, 'No key for keyid %s' % keyid
            context_params['secret'] = secret
            context_params['data'] = keyid

        # print('verifying with parameters %s' % context_params)
        with argon2_context(**context_params) as ctx:
            result = lib.argon2i_verify_ctx(ctx, raw_hash)

        return result == lib.ARGON2_OK


    def _encode(self, raw_hash, salt):
        format_args = dict(
            algo='argon2i',
            t_cost=self.time_cost,
            m_cost=self.memory_cost,
            parallelism=self.parallelism,
            salt=b64_encode_raw(salt),
            hash=b64_encode_raw(raw_hash),
            version=ARGON2_VERSION,
            keyid='',
        )
        if self.keyid:
            format_args['keyid'] = ',keyid={}'.format(self.keyid)
        return ('${algo}$v={version}$m={m_cost},t={t_cost},p={parallelism}{keyid}'
            '${salt}${hash}').format(**format_args)


@contextlib.contextmanager
def argon2_context(
        password=None, # bytes
        salt=None,
        secret=None,
        data=None,
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
    if data:
        cdata = ffi.new("uint8_t[]", data)
        data_len = len(data)
    else:
        cdata = ffi.NULL
        data_len = 0
    ctx = ffi.new("argon2_context *", dict(
            version=version,
            out=cout, outlen=hash_len,
            pwd=cpwd, pwdlen=len(password),
            salt=csalt, saltlen=len(salt),
            secret=csecret, secretlen=secret_len,
            ad=cdata, adlen=data_len,
            t_cost=time_cost,
            m_cost=memory_cost,
            lanes=parallelism, threads=parallelism,
            allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
            flags=DEFAULT_FLAGS,
        )
    )
    yield ctx
