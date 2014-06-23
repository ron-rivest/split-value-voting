# sv.py
# python3
# Prototype code implementing split-value voting method
# This code is meant to be pedagogic and illustrative of main concepts;
# many details would need adjustment or filling in for a final implementation.
# This code only considers a one race election.
# Ronald L. Rivest
# 2014-06-13

##############################################################################
# standard MIT open-source license
##############################################################################
"""
The MIT License

Copyright (c) 2014 Michael O. Rabin and Ronald L. Rivest

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
##############################################################################
# end of standard MIT open-source license
##############################################################################

import base64
import hmac
import hashlib

##############################################################################
# Security parameters (key lengths)
##############################################################################
# see http://www.keylength.com/en/3/  (level 7)

# define some security parameters

SECPARAM_SYMMETRIC = 256     # size of symmetric encryption key (bits)
                             # (this is also the commitment key length)
SECPARAM_ASYMMETRIC = 3248   # size of asymmetric encryption key (bits)
SECPARAM_HASH_OUTPUT = 256   # size of hash function output (bits)
SECPARAM_RAND_SEED = 256     # size of seed for pseudo-random-generator (bits)

# security parameters must be integral number of bytes
assert SECPARAM_SYMMETRIC % 8 == 0
assert SECPARAM_ASYMMETRIC % 8 == 0
assert SECPARAM_HASH_OUTPUT % 8 == 0
assert SECPARAM_RAND_SEED == SECPARAM_HASH_OUTPUT

##############################################################################
# HASH FUNCTION (SHA256)
##############################################################################

# define our hash function to be compatible with the above
def hash(x, tweak=0):
    """ Return SHA256 hash of (tweaked) x, as bytes value.
    x may be string or bytes.

    (Note that python already has a "hash" function, which is not
    cryptographic, but used for dictionaries.  We are overriding the
    use of the function name "hash" here to mean sha256.)

    The value "tweak" (which is in range 0 to 255), allows one to
    "tweak" the (non-empty) input x.

    Note: this is not the only place where dependency on choice
    of hash function is evidenced; also see commitment use of hmac.
    """
    if isinstance(x, str):
        x = x.encode()
    assert isinstance(x, (bytes, bytearray))
    assert isinstance(tweak, int) and 0 <= tweak < 256
    if tweak == 0:
        return hashlib.sha256(x).digest()
    else:
        x = bytearray(x)
        x[0] = (x[0] + tweak) % 256
        return hashlib.sha256(x).digest()

##############################################################################
# UTILITY FUNCTIONS
##############################################################################

def bytes2hex(x):
    """ Return hexadecimal representation of byte sequence x (as a string) 
    
    Could also use binascii.hexlify(x)
    """
    assert isinstance(x, (bytes, bytearray))
    ans = []
    hexdigits = "0123456789abcdef"
    for c in x:
        ans.append(hexdigits[c >> 4])
        ans.append(hexdigits[c & 0xf])
    return "".join(ans)

def hex2bytes(s):
    """ Return bytes representation of hex string s. """
    assert isinstance(s, str)
    assert len(s) % 2 == 0
    return bytes.fromhex(s)

def bytes2int(x):
    """ Return integer (bignum) representation of byte sequence x.

    First byte in sequence is least-significant byte.
    """
    assert isinstance(x, (bytes, bytearray))
    ans = 0
    for i in range(len(x)-1, -1, -1):
        ans = 256*ans + x[i]
    return ans

def int2bytes(x, desired_length=None):
    """ Return bytes representation of integer x >= 0 of desired length.

    If desired_length == None, then return minimum-length representation
    (but representing 0 takes 1 byte).
    """
    assert isinstance(x, int) and x >= 0
    assert not desired_length or \
        (isinstance(desired_length, int) and desired_length > 0)

    byte_list = []
    if not desired_length:
        if x == 0:
            return b"\x00"
        while x > 0:
            byte_list.append(x % 256)
            x = x // 256
    else:
        while len(byte_list) < desired_length:
            byte_list.append(x % 256)
            x = x // 256
    assert not desired_length or len(byte_list) == desired_length
    return bytes(byte_list)

def bytes2base64(x):
    """ Convert bytes value x to base64 representation as a string. """
    return base64.b64encode(x).decode()

def base64_2_bytes(x):
    """ Convert string base64 value x to bytes. """
    return base64.b64decode(x)

def test_conversions():
    """ Test the above data-type conversion routines. """
    assert bytes2hex(b"abc") == '616263'
    assert bytes2int(bytes([1, 2])) == 513
    assert bytes2int(int2bytes(134827781332)) == 134827781332
    x = b"012345abcde"
    assert base64_2_bytes(bytes2base64(x)) == x

test_conversions()

##############################################################################
# RANDOMNESS
##############################################################################

"""
Implement a collection of randomness "sources".
In practice, these must be independent and separately seeded.
In this protype implementation, they are pseudorandomly seeded.
** For a secure real implementation, seeds should come 
** from a truly random source. 
Each randomness source has a separate name (a string).
Each randomness source has a seed (a SECPARAM_RAND_SEED/8 bytes value)
"""
randomness_sources = dict()     # maps names to their current state

def init_randomness_source(rand_name, initial_seed=None):
    """ Initialize a randomness source with given name.

    Doesn't matter if already exists, but will reset seed then though.
    """
    assert isinstance(rand_name, str)
    num_sources = len(randomness_sources)
    if initial_seed == None:
        # initialize new seed to hash of source name
        # this is not secure!! this is only for prototype use!!
        new_seed = hash(rand_name)
    else:
        assert isinstance(initial_seed, (bytes, bytearray))
        assert len(initial_seed) == SECPARAM_HASH_OUTPUT / 8
        new_seed = initial_seed
    randomness_sources[rand_name] = new_seed

def get_random_from_source(rand_name, modulus=None):
    """ Return next random value for given randomness source.

    Returned value is of type bytes, of length SECPARAM_RAND_SEED/8 bytes,
    unless modulus is given, in which case an integer modulo the
    given modulus is returned.
    """
    assert rand_name in randomness_sources
    assert not modulus or (isinstance(modulus, int) and modulus > 0)
    new_seed = hash(randomness_sources[rand_name])
    randomness_sources[rand_name] = new_seed
    # use tweaked hash in the following line, so that
    # output-producing hash and next-new-seed hash are different
    random_output = hash(new_seed, 1)
    if modulus == None:
        return random_output
    return bytes2int(random_output) % modulus

def test_random():
    """ Test init_randomness_source and get_random_from source. """
    init_randomness_source("spam")
    init_randomness_source("eggs")
    ans = []
    for rand_name in ["spam", "spam", "eggs", "spam", "eggs"]:
        ans.append(rand_name)
        rand_bytes = get_random_from_source(rand_name)
        ans.append(bytes2hex(rand_bytes[:6]))
    # print(ans)
    assert ans == \
        ['spam', '1236c6cea5b6', 'spam', '25f602072d77',
         'eggs', '1d52f6c167a8', 'spam', 'e1bfc9553da5',
         'eggs', '90dd63f64db6']
    ans = get_random_from_source("spam", 100)
    # print(ans)
    assert ans == 21

test_random()

##############################################################################
# GENERATE A RANDOM PERMUTATION
##############################################################################

def random_permutation(elts, rand_name):
    """
    Generate and return a random permutation (as a dict) of given set of 
    elements using random source with name rand_name.  If elts is an integer,
    it is interpreted as range(elts)

    Use Fisher-Yates method.
    """
    if isinstance(elts, int):
        elts = range(elts)
    elts = list(elts)
    g = len(elts)
    pi = list(range(g))
    for i in range(1, g):
        j = get_random_from_source(rand_name, i+1)
        temp = pi[i]
        pi[i] = pi[j]
        pi[j] = temp
    perm = dict()
    for i in range(g):
        perm[elts[i]] = elts[pi[i]]
    return perm

def inverse_permutation(perm):
    """ Produce inverse of permutation perm (a permutation as a dict). """
    perm_inv = dict()
    for elt in perm:
        perm_inv[perm[elt]] = elt
    return perm_inv

def apply_permutation(perm, x):
    """ Apply permutation perm to input dict x.

    Here perm is a permutation of x.keys()
    The element starting in position pi[i] ends up in position i.
    The element starting in position elt ends up in position perm_inv[elt].
    """
    y = dict()
    for elt in x:
        y[elt] = x[perm[elt]]
    return y

def test_random_permutation():
    """ Test random_permutation. """
    init_randomness_source("test_random_permutation")
    for i in range(1, 5):
        n = 10
        perm = random_permutation(list(range(n)), "test_random_permutation")
        assert sorted(perm) == list(range(n))
        perm_inv = inverse_permutation(perm)
        x = dict()
        for i in range(n):
            x[i] = i
        y = apply_permutation(perm, x)
        z = apply_permutation(perm_inv, y)
        assert x == z
    perm1 = random_permutation(list(range(100)), "test_random_permutation")
    perm2 = random_permutation(list(range(100)), "test_random_permutation")
    assert perm1 != perm2     # could happen, but with negligible probability

test_random_permutation()

##############################################################################
# PRIMALITY TESTING
##############################################################################

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, \
                59, 61, 67, 71, 73, 79, 83, 89, 97, 101]

def is_prime(n):
    """ Return True if n is prime (probabilistic for large n) """
    assert isinstance(n, int)
    if n in small_primes:
        return True
    if n < max(small_primes):
        return False
    for p in small_primes:
        if n % p == 0:
            return False
    return miller_rabin(n, 20)

def miller_rabin(n, s):
    """ Miller_Rabin primality test (see CLRS 3e, page 970).

    Return True iff n is prime (w.h.p.), with s trials.
    """
    init_randomness_source("Miller_Rabin")
    for j in range(1, s+1):
        a = get_random_from_source("Miller_Rabin", n-1) + 1
        if witness(a, n):
            return False
    return True

def witness(a, n):
    """ Return True if a witnesses compositeness of n. """
    assert isinstance(a, int)
    assert isinstance(n, int)
    u = n - 1
    t = 0
    while u % 2 == 0:
        u = u // 2
        t = t + 1
    x = [pow(a, u, n)]
    for i in range(1, t+1):
        x.append((x[-1]*x[-1]) % n)
        if x[-1] == 1 and x[-2] != 1 and x[-2] != n-1:
            return True
    if x[-1] != 1:
        return True
    return False

def test_is_prime():
    """ Test is_prime on values up to 10^4 """
    prime_count = 0
    for n in range(1, 10**4+1):
        if is_prime(n):
            prime_count += 1
    assert 1229 == prime_count

test_is_prime()

def next_prime(n):
    """ Return the smallest integer greater than n that is prime. """
    assert isinstance(n, int)
    n = n + 1
    if n <= 2:
        return 2
    if n % 2 == 0:
        n = n + 1
    while not is_prime(n):
        n = n + 2
    return n

def test_next_prime():
    """ Test next_prime routine on a few examples. """
    assert 2 == next_prime(0)
    assert 3 == next_prime(2)
    assert 7 == next_prime(5)
    assert 17 == next_prime(15)
    assert 101 == next_prime(100)
    assert 257 == next_prime(256)
    assert 1009 == next_prime(1000)
    assert 10**6 + 3 == next_prime(10**6)
    assert 2**256 + 297 == next_prime(2**256)

test_next_prime()

def prev_prime(n):
    """ Return the largest integer less than n that is prime.

        Raise an error if n <= 2.
    """
    assert isinstance(n, int)
    assert n > 2
    if n == 3:
        return 2
    n = n - 1
    if n % 2 == 0:
        n = n - 1
    while not is_prime(n):
        n = n - 2
    return n

def test_prev_prime():
    """ Test prev_prime routine on a few examples. """
    assert 2 == prev_prime(3)
    assert 5 == prev_prime(7)
    assert 13 == prev_prime(15)
    assert 97 == prev_prime(100)
    assert 251 == prev_prime(256)
    assert 997 == prev_prime(1000)
    assert 10**6 - 17 == prev_prime(10**6)
    assert 2**256 - 189 == prev_prime(2**256)
    assert 256**48 - 317 == prev_prime(256**48)

test_prev_prime()

def make_prime(n):
    """ Return next prime greater than or equal to n. """
    if is_prime(n):
        return n
    else:
        return next_prime(n)

##############################################################################
# SPLIT-VALUE REPRESENTATIONS (modulo M)
##############################################################################

def get_sv_pair(x, rand_name, M):
    """
    Return random split-value representation of x. Use given randomness source.

    Value returned is a pair (u, v) of values mod M, s.t. x = u+v (mod M).
    """
    assert isinstance(M, int)
    assert M >= 2
    u = get_random_from_source(rand_name, M)
    v = (x-u) % M
    return (u, v)

def test_sv_pair():
    """ Test SV representation routines. """
    init_randomness_source("test_sv_pair_source")
    ans = []
    M = 101
    for x in [0, 1, 5, 23, 79, 88]:
        ans.append([x, get_sv_pair(x, "test_sv_pair_source", M)])
    # print(ans)
    assert ans == [[0, (29, 72)], [1, (1, 0)], [5, (34, 72)], [23, (93, 31)],
                   [79, (55, 24)], [88, (54, 34)]]

test_sv_pair()

##############################################################################
# POLYNOMIAL SECRET SHARING (modulo M)
##############################################################################

def share(secret, n, t, rand_name, M):
    """
    Split given secret into n shares, using given randomness, such that
    any t shares suffices to reconstruct secret, and fewer don't suffice.
    Work modulo M, which is assumed to be prime.

    Note that shares are random function (with secret as constant coef)
    evaluated at points x=1, 2, ..., n.  (This fact is used elsewhere,
    e.g. in sv_voter.cast_votes.)
    """
    assert isinstance(M, int) and M > 1
    assert isinstance(secret, int) and 0 <= secret < M, str(secret)
    assert isinstance(n, int) and 1 < n <= M - 1
    assert isinstance(t, int) and 1 <= t <= n
    coefs = [get_random_from_source(rand_name, M) for i in range(t)]
    coefs[0] = secret
    # print(coefs)
    share_list = []
    for x in range(1, n+1):
        y = 0
        for j in range(t-1, -1, -1):
            y = ((y * x) + coefs[j]) % M
        share_list.append((x, y))
    return share_list

def test_share():
    """ Test secret-sharing on a small example. """
    init_randomness_source("test_share")
    M = 11
    # print(share(3,5,3,"test_share",M))
    assert share(3, 5, 3, "test_share", M) == \
        [(1, 1), (2, 9), (3, 5), (4, 0), (5, 5)]

test_share()

def lagrange(share_list, n, t, M):
    """ return secret, given enough shares.

    Use LaGrange interpolation formula.
    Arithmetic is modulo M (a prime).
    share_list is a list of (x, y) pairs, with distinct x's.
    The original number of shares created was n.
    The threshold number of shares needed to reconstruct secret is t.
    The length of share_list is at least t (and at most n).
    """
    assert isinstance(n, int)
    assert isinstance(t, int)
    assert isinstance(M, int)
    assert 1 <= t <= n
    assert n <= M - 1
    assert len(share_list) >= t
    if len(share_list) > t:
        share_list = share_list[:t]
    x = [xy[0] for xy in share_list]
    y = [xy[1] for xy in share_list]
    secret = 0
    for i in range(t):
        numerator = 1
        denominator = 1
        for j in range(t):
            if j != i:
                numerator *= (-x[j]) % M
                denominator *= (x[i]-x[j]) % M
        assert denominator != 0
        denominator_inverse = pow(denominator, M-2, M)
        assert (denominator * denominator_inverse) % M == 1
        secret = (secret + y[i] * numerator * denominator_inverse) % M
    return secret

def test_lagrange():
    """ Test lagrange on a simple example. """
    n = 5
    t = 3
    secret = 3
    M = 11
    init_randomness_source("test_lagrange")
    share_list = share(secret, n, t, "test_lagrange", M)
    assert secret == lagrange(share_list, n, t, M)
    # now re-do, using *last* t shares instead of first t
    share_list.reverse()
    assert secret == lagrange(share_list, n, t, M)

test_lagrange()

##############################################################################
# SYMMETRIC ENCRYPTION
##############################################################################

def sym_keygen(rand_name):
    """ Generate and return a a symmetric encryption key. """
    sym_key = get_random_from_source(rand_name)
    assert len(sym_key) == SECPARAM_SYMMETRIC / 8
    return sym_key

def sym_enc(sym_key, msg):
    """ Encrypt message msg with given symmetric key sym_key.

        sym_key is key generated by sym_keygen
        msg is an arbitrary-length bytes value.

    UNUSED IN CURRENT VERSION. (TO BE ADDED WHEN SIMULATED
    TABLET TO SERVER COMMUNICATION ADDED.)
    THIS IS INSECURE "DUMMY" IMPLEMENTATION FOR NOW.
    UPDATE WITH AUTHENTICATED ENCRYPTION MODE LIKE EAX.
    """
    assert isinstance(sym_key, (bytes, bytearray))
    assert len(sym_key) == SECPARAM_SYMMETRIC / 8
    assert isinstance(msg, (bytes, bytearray))

    # In this dummy implementation encryption just concatenates
    # key and message!  Very insecure !!!
    ct = sym_key + msg
    return ct

def sym_dec(sym_key, ct):
    """ Decrypt ciphertext ct with the given symmetric key sym_key.

        sym_key is key generated by sym_keygen, same as was used to encrypt.
        ct is the ciphertext that was produced by sym_enc

    THIS IS INSECURE "DUMMY" IMPLEMENTATION FOR NOW.
    UPDATE WITH AUTHENTICATED ENCRYPTION MODE LIKE EAX.
    """
    assert isinstance(sym_key, (bytes, bytearray))
    assert len(sym_key) == SECPARAM_SYMMETRIC / 8
    assert isinstance(ct, (bytes, bytearray))
 
    # in this dummy implementation, just key that ct starts with
    # sym_key, then if OK, strip it off and return msg. Very insecure !!!
    assert sym_key == ct[:len(sym_key)]
    msg = ct[len(sym_key):]
    return msg

def test_sym_enc():
    """ Test symmetric keygen, enc, and dec. """
    init_randomness_source("test_sym_enc")
    sym_key = sym_keygen("test_sym_enc")
    msg = "Hello, world.".encode()
    ct = sym_enc(sym_key, msg)
    msg2 = sym_dec(sym_key, ct)
    assert msg == msg2

test_sym_enc()

##############################################################################
# PUBLIC-KEY ENCRYPTION
##############################################################################

def pk_keygen(rand_name):
    """ Generate public-key encryption parameters; return (pk,sk). """
    # INSECURE DUMMY IMPLEMENTATION FOR NOW
    r = get_random_from_source(rand_name)
    pk = b"pk" + r                  # proxy for public-key
    sk = b"sk" + r                  # proxy for secret-key
    return (pk, sk)

def pk_enc(pk, msg):
    """ Encrypt message msg with given public key pk. """
    # just concatenate public key and messge.  Very insecure !!!
    ct = pk + msg
    return pk + msg

def pk_dec(pk, sk, ct):
    """ Decrypt ciphertext ct with given secret key sk. """
    # just check prefix is pk for now, then return rest.
    # Very insecure !!!
    assert pk == ct[:len(pk)]
    msg = ct[len(pk):]
    return msg

def test_pk_enc():
    """ Test public-key keygen, enc, and dec. """
    init_randomness_source("test_pk_enc")
    (pk, sk) = pk_keygen("test_pk_enc")
    msg = "Hello, world.".encode()
    ct = pk_enc(pk, msg)
    msg2 = pk_dec(pk, sk, ct)
    assert msg == msg2

test_pk_enc()

##############################################################################
# BASIC COMMITMENT FUNCTION com
##############################################################################

def com(v, r_b64):
    """ Produce a commitment to v using randomness r.

    Here v  = an arbitrary-length string or bytes or bytearray or int
              (the value being committed to)
         r_b64  = a randomness parameter (or key)
                  which is of type string (base64)
                  of length SECPARAM_SYMMETRIC // 6 + 2 base64 digits

    The output produced is of type string giving the commitment in
    base64 (for ease of output) of length
    SECPARAM_HASH_OUTPUT // 6 + 2 (bytes) (approximately).
    """
    # make sure v has type bytes (by converting from string to bytes if nec.)
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, int):
        v = int2bytes(v)
    assert isinstance(v, (bytes, bytearray)),\
        "com error: value v must be of type str, int, bytes, or bytearray."
    # check that r_b64 is of right type (str) and length
    assert isinstance(r_b64, str)
    assert len(r_b64) == (SECPARAM_SYMMETRIC // 6) + 2,\
       "com error: value r_b64 must be SECPARAM_SYMMETRIC//6+2 b64 digits."
    # return commitment (of length SECPARAM_HASH_OUTPUT bits)
    # note that if you change SECPARAM_HASH_OUTPUT to something other
    # than 256, then the choice of hash function has to be changed here.
    # (We can't just use "hash" here, as it isn't compatible with hmac.)
    assert SECPARAM_HASH_OUTPUT == 256
    h = hashlib.sha256
    r_bytes = base64_2_bytes(r_b64)
    return bytes2base64(hmac.HMAC(r_bytes, v, h).digest())

def test_com():
    """ Test commitment function com. """
    r = 'aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk'
    # print(com("abc",r))
    assert com("abc", r) == \
        "jolywuOC0afkCY/rmY3YITd08E+79sB+ZFXFpRUYuFU="

test_com()

##############################################################################
# COMMITMENT TO A SPLIT-VALUE PAIR -- comsv
##############################################################################

def comsv(svpair, ru, rv):
    """ Return commitment to svpair (u, v) with randomness ru and rv. """
    u, v = svpair
    return (com(u, ru), com(v, rv))

##############################################################################
# MAKE P-LIST OF INDEX NAMES FOR VOTERS
##############################################################################

def p_list(n_voters):
    """ Return list of length n_voters: p0, p1, .... 

    (Widths of integers adjusted to be uniform.)
    Note that this list is in increasing order.
    """
    width = len("%d"%n_voters)
    x_format = "%0" + str(width) + "d"
    ps = ["p"+ x_format%x for x in range(n_voters)]
    return ps

##############################################################################
# MAKE ROW-LIST OF INDEX NAMES FOR ROWS
##############################################################################

def row_list(rows):
    """ Return list of length rows: 'a', 'b', 'c', ...

    Note that this list is in increasing order.
    """
    i_list = "abcdefghijklmnopqrstuvwxyz"[:rows]
    return i_list

##############################################################################
# MAKE K-LIST OF INDEX NAMES FOR PASSES (COPIES)
##############################################################################

def k_list(n_reps):
    """ Return list of length n_reps: 'A', 'B', 'C', ...

    Note that this list is in increasing order.
    """
    ks = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:n_reps]
    return ks
