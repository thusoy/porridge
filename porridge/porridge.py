import contextlib
import os
import re

from ._ffi import ffi, lib
from .utils import (
    b64_decode_raw,
    b64_encode_raw,
    check_types,
    ensure_bytes,
    string_types,
)
from .exceptions import (
    EncodedPasswordError,
    MissingKeyError,
    ParameterError,
    PorridgeError,
)

# These parameters should be increased regularly to keep boiling slow
# on new hardware
DEFAULT_RANDOM_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_PARALLELISM = 4
DEFAULT_PARAMETER_THRESHOLD = 4
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET

# This regex validates the spec from
# https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
ENCODED_HASH_RE = re.compile(r''.join([
        r'^\$argon2i\$',
        r'(?:v=(?P<version>[0-9]{1,3})\$)?',
        r''.join([
            r'm=(?P<memory_cost>[0-9]{1,10})',
            r',t=(?P<time_cost>[0-9]{1,10})',
            r',p=(?P<parallelism>[0-9]{1,3})',
            r'(?:,keyid=(?P<keyid>[a-zA-Z0-9+/]{0,11}))?', # optional
            r'(?:,data=(?P<data>[a-zA-Z0-9+/]{0,43}))?', # optional, unused
        ]),
        r'\$(?P<salt>[a-zA-Z0-9+/]{11,64})\$',
        r'(?P<hash>[a-zA-Z0-9+/]{16,86})',
    ]) + r'$'
)


class Porridge(object):
    r"""
    Helper class to boil passwords with sensible defaults and server-side
    secrets.

    :param str secrets: A comma-separated string of *keyid:key* pairs that will
        be used as server-side secrets. The first element in the list will be
        used to boil new passwords, the others to verify old ones.
    :param int time_cost: Defines the amount of computation realized and
        therefore the execution time, given in number of iterations.
    :param int memory_cost: Defines the memory usage, given in kibibytes_.
    :param int parallelism: Defines the number of threads used
    :param int hash_len: Length of the raw hash in bytes.
    :param int salt_len: Length of random salt to be generated for each
        password.
    :param int parameter_threshold: A multiplier that sets the threshold for
        how much higher parameters in encoded passwords can be above our own
        parameters before we refuse the process them.
    :param str encoding: Boiling is always performed on bytes, thus if unicode
        strings are given to either :meth:`boil` of :meth:`verify` this encoding
        will be used to encode the password to bytes.

    .. _salt: https://en.wikipedia.org/wiki/Salt_(cryptography)
    .. _kibibytes: https://en.wikipedia.org/wiki/Binary_prefix#kibi
    """

    def __init__(
        self,
        secrets,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        hash_len=DEFAULT_HASH_LENGTH,
        salt_len=DEFAULT_RANDOM_SALT_LENGTH,
        parameter_threshold=DEFAULT_PARAMETER_THRESHOLD,
        encoding="utf-8",
    ):
        e = check_types(
            secrets=(secrets, string_types),
            time_cost=(time_cost, int),
            memory_cost=(memory_cost, int),
            parallelism=(parallelism, int),
            hash_len=(hash_len, int),
            salt_len=(salt_len, int),
            parameter_threshold=(parameter_threshold, int),
            encoding=(encoding, string_types),
        )
        if e:
            raise TypeError(e)

        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.encoding = encoding
        if parameter_threshold < 1:
            raise ValueError('parameter_threshold must be at least 1')
        self.parameter_threshold = parameter_threshold

        self.secret_map = {}
        self.secret = None
        self.keyid = None
        for secret_pair in secrets.split(','):
            keyid, secret = secret_pair.split(':', 1)
            keyid = keyid.encode('utf-8')
            secret = secret.encode('utf-8')
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


    def boil(self, password):
        """
        Boil *password* and return and encoded password that can be stored in a
        database.

        :param password: Password to boil.
        :type password: ``bytes`` or ``unicode``

        :raises porridge.PorridgeError: If verification fails to complete due
            to not being able to spawn enough threads or allocate enough memory.

        :rtype: unicode
        """
        e = check_types(password=(password, string_types + (bytes,)))
        if e:
            raise TypeError(e)

        salt = os.urandom(self.salt_len)
        context_params = dict(
            salt=salt,
            password=ensure_bytes(password, self.encoding),
            secret=self.secret,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
        )
        with argon2_context(**context_params) as ctx:
            result = compute_hash(ctx)

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

        :param password: The password to verify.
        :type password: ``bytes`` or ``unicode``
        :param unicode encoded: An encoded password as returned from
            :meth:`Porridge.boil`.

        :raises porridge.PorridgeError: If verification fails to complete due
            to not being able to spawn enough threads or allocate enough memory.

        :return: ``True`` if *password* is valid, otherwise ``False``.
        :rtype: bool
        """
        e = check_types(
            password=(password, string_types + (bytes,)),
            encoded=(encoded, string_types),
        )
        if e:
            raise TypeError(e)

        if len(encoded) > 265:
             # Ensure we don't DDoS ourselves if the database holds corrupt values
            raise EncodedPasswordError('Encoded password exceeds maximum length of '
                '265, was {length}'.format(length=len(encoded)))

        context_params = parse_encoded(encoded)
        self._verify_parameters_within_threshold(context_params)
        raw_hash = context_params.pop('raw_hash')

        context_params.update(dict(
            hash_len=len(raw_hash),
            password=self._ensure_bytes(password),
        ))

        keyid = context_params.get('keyid')
        if keyid:
            del context_params['keyid']
            secret = self.secret_map.get(keyid)
            if not secret:
                raise MissingKeyError(keyid.decode('utf-8'))
            context_params['secret'] = secret

        with argon2_context(**context_params) as ctx:
            result = verify_hash(ctx, raw_hash)

        if result == lib.ARGON2_OK:
            return True
        elif result == lib.ARGON2_VERIFY_MISMATCH:
            return False
        else:
            error_message = argon2_error_message(result)
            raise PorridgeError(error_message)


    def needs_update(self, encoded):
        """
        Check if the parameters in *encoded* are old and the password should be
        re-boiled.

        :param unicode encoded: An encoded password as returned from
            :meth:`Porridge.boil`.

        :rtype: bool
        """
        parsed = parse_encoded(encoded)
        if parsed['version'] < lib.ARGON2_VERSION_NUMBER:
            return True

        if parsed['parallelism'] < self.parallelism:
            return True

        if parsed['memory_cost'] < self.memory_cost:
            return True

        if parsed['time_cost'] < self.time_cost:
            return True

        if len(parsed['salt']) < self.salt_len:
            return True

        if len(parsed['raw_hash']) < self.hash_len:
            return True

        if parsed.get('keyid') != self.keyid:
            return True

        return False


    def _ensure_bytes(self, s):
        return ensure_bytes(s, self.encoding)


    def _verify_parameters_within_threshold(self, parameters):
        for parameter in ('time_cost', 'memory_cost', 'parallelism'):
            given_parameter = parameters[parameter]
            our_parameter = getattr(self, parameter)
            if given_parameter > our_parameter * self.parameter_threshold:
                raise EncodedPasswordError('%s exceeds threshold of what we will process' % parameter)


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
                version=lib.ARGON2_VERSION_NUMBER,
                keyid=self.keyid.decode('utf-8'),
            )


def parse_encoded(encoded):
    match = ENCODED_HASH_RE.match(encoded)
    if not match:
        raise EncodedPasswordError('Encoded password is on unknown format', encoded)
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

    parsed = dict(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        raw_hash=raw_hash,
        salt=salt,
        version=version,
    )

    keyid = match.group('keyid')
    if keyid:
        parsed['keyid'] = keyid.encode('utf-8')

    return parsed


def argon2_error_message(error_code):
    return ffi.string(lib.argon2_error_message(error_code)).decode('utf-8')


def is_operational_error(error_code):
    return error_code in set([
        lib.ARGON2_THREAD_FAIL,
        lib.ARGON2_MEMORY_ALLOCATION_ERROR,
    ])


def compute_hash(context):
    '''Minimal wrapper around argon2_ctx to enable mocking'''
    return lib.argon2_ctx(context, lib.Argon2_i)


def verify_hash(context, raw_hash):
    '''Minimal wrapper around argon2i_verify_ctx to enable mocking'''
    return lib.argon2i_verify_ctx(context, raw_hash)


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
        version=lib.ARGON2_VERSION_NUMBER,
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
            flags=flags,
        )
    )
    yield ctx
