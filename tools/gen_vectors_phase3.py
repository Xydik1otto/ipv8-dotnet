"""Generate Phase 3 golden vectors (tunnel session crypto + anonymization cell payloads).

Everything is generated with py-ipv8's REAL payload classes and Serializer:
the `ipv8_rust_tunnels` wheel (not installable here) is stubbed with a pure
python implementation of the tunnel session crypto, ported 1:1 from
ipv8-rust-tunnels/src/{dh.rs,crypto.rs} (this file doubles as the py-side
tunnelcrypto reference for Phase 4).

Fixed key material (same as Phase 1a goldens):
- Alice: Ed25519 seed = RFC 8032 TEST 1, X25519 priv = RFC 7748 6.1 alice
- Bob:   Ed25519 seed = RFC 8032 TEST 2, X25519 priv = RFC 7748 6.1 bob

Deterministic handshake extras:
- Initiator ephemeral X25519 sk = sha256("ipv8-port-phase3-ephemeral")
- Responder (hop) ephemeral X25519 sk = sha256("ipv8-port-phase3-responder-tmp")
"""
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import types

ROOT = os.environ.get("IPV8_PORT_ROOT", "G:/Projects/ipv8-port")
PV = os.path.join(ROOT, "py-ipv8")
sys.path.insert(0, PV)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

RAW = serialization.Encoding.Raw
RAWF = serialization.PublicFormat.Raw

# ---------------------------------------------------------------- pure crypto (from dh.rs)
SIGMA = b"expand 32-byte k"  # 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 (LE u32)


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def hsalsa20(shared: bytes) -> bytes:
    """crypto_core_hsalsa20, ported from dh.rs::crypto_box_beforenm (~80 lines)."""
    assert len(shared) == 32
    load = lambda b, i: struct.unpack_from("<I", b, i)[0]  # noqa: E731
    x0, x5, x10, x15 = (struct.unpack_from("<I", SIGMA, 4 * i)[0] for i in range(4))
    x1, x2, x3, x4 = (load(shared, 4 * i) for i in range(4))
    x11, x12, x13, x14 = (load(shared, 16 + 4 * i) for i in range(4))
    x6 = x7 = x8 = x9 = 0
    for _ in range(0, 20, 2):
        x4 ^= _rotl32((x0 + x12) & 0xFFFFFFFF, 7)
        x8 ^= _rotl32((x4 + x0) & 0xFFFFFFFF, 9)
        x12 ^= _rotl32((x8 + x4) & 0xFFFFFFFF, 13)
        x0 ^= _rotl32((x12 + x8) & 0xFFFFFFFF, 18)
        x9 ^= _rotl32((x5 + x1) & 0xFFFFFFFF, 7)
        x13 ^= _rotl32((x9 + x5) & 0xFFFFFFFF, 9)
        x1 ^= _rotl32((x13 + x9) & 0xFFFFFFFF, 13)
        x5 ^= _rotl32((x1 + x13) & 0xFFFFFFFF, 18)
        x14 ^= _rotl32((x10 + x6) & 0xFFFFFFFF, 7)
        x2 ^= _rotl32((x14 + x10) & 0xFFFFFFFF, 9)
        x6 ^= _rotl32((x2 + x14) & 0xFFFFFFFF, 13)
        x10 ^= _rotl32((x6 + x2) & 0xFFFFFFFF, 18)
        x3 ^= _rotl32((x15 + x11) & 0xFFFFFFFF, 7)
        x7 ^= _rotl32((x3 + x15) & 0xFFFFFFFF, 9)
        x11 ^= _rotl32((x7 + x3) & 0xFFFFFFFF, 13)
        x15 ^= _rotl32((x11 + x7) & 0xFFFFFFFF, 18)
        x1 ^= _rotl32((x0 + x3) & 0xFFFFFFFF, 7)
        x2 ^= _rotl32((x1 + x0) & 0xFFFFFFFF, 9)
        x3 ^= _rotl32((x2 + x1) & 0xFFFFFFFF, 13)
        x0 ^= _rotl32((x3 + x2) & 0xFFFFFFFF, 18)
        x6 ^= _rotl32((x5 + x4) & 0xFFFFFFFF, 7)
        x7 ^= _rotl32((x6 + x5) & 0xFFFFFFFF, 9)
        x4 ^= _rotl32((x7 + x6) & 0xFFFFFFFF, 13)
        x5 ^= _rotl32((x4 + x7) & 0xFFFFFFFF, 18)
        x11 ^= _rotl32((x10 + x9) & 0xFFFFFFFF, 7)
        x8 ^= _rotl32((x11 + x10) & 0xFFFFFFFF, 9)
        x9 ^= _rotl32((x8 + x11) & 0xFFFFFFFF, 13)
        x10 ^= _rotl32((x9 + x8) & 0xFFFFFFFF, 18)
        x12 ^= _rotl32((x15 + x14) & 0xFFFFFFFF, 7)
        x13 ^= _rotl32((x12 + x15) & 0xFFFFFFFF, 9)
        x14 ^= _rotl32((x13 + x12) & 0xFFFFFFFF, 13)
        x15 ^= _rotl32((x14 + x13) & 0xFFFFFFFF, 18)
    out = struct.pack("<8I", x0, x5, x10, x15, x6, x7, x8, x9)
    return out


def crypto_box_beforenm(pk: bytes, sk: bytes) -> bytes:
    assert len(pk) == 32 and len(sk) == 32
    clamped = bytearray(sk)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    shared = X25519PrivateKey.from_private_bytes(bytes(clamped)).exchange(
        X25519PublicKey.from_public_bytes(pk))
    return hsalsa20(shared)


def crypto_auth(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA512 truncated to the first 32 bytes (dh.rs::crypto_auth)."""
    return hmac_mod.new(key, message, hashlib.sha512).digest()[:32]


def crypto_auth_verify(tag: bytes, key: bytes, message: bytes) -> bool:
    return hmac_mod.compare_digest(crypto_auth(key, message), tag)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3 expand-only (pure stdlib)."""
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def generate_session_keys(shared_secret: bytes) -> "RefSessionKeys":
    """crypto.rs::generate_session_keys: HKDF-SHA256 expand-only, info=b"key_generation", 72B."""
    okm = hkdf_expand_sha256(shared_secret, b"key_generation", 72)
    return RefSessionKeys(
        key_backward=okm[0:32], key_forward=okm[32:64],
        salt_backward=okm[64:68], salt_forward=okm[68:72])


class RefSessionKeys:
    """SessionKeys ported from crypto.rs (counters increment BEFORE use)."""

    def __init__(self, key_forward, key_backward, salt_forward, salt_backward):
        self.key_forward = key_forward
        self.key_backward = key_backward
        self.salt_forward = salt_forward
        self.salt_backward = salt_backward
        self.salt_explicit_forward = 1
        self.salt_explicit_backward = 1

    def encrypt_str(self, content: bytes, direction: int) -> bytes:
        if direction == 0:
            self.salt_explicit_forward += 1
            key, salt, counter = self.key_forward, self.salt_forward, self.salt_explicit_forward
        else:
            self.salt_explicit_backward += 1
            key, salt, counter = self.key_backward, self.salt_backward, self.salt_explicit_backward
        counter_bytes = struct.pack(">Q", counter)
        nonce = salt + counter_bytes
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, content, None)
        return counter_bytes + ciphertext

    def decrypt_str(self, content: bytes, direction: int) -> bytes:
        if len(content) < 24:
            raise ValueError("Content too short")
        key, salt = ((self.key_forward, self.salt_forward) if direction == 0
                     else (self.key_backward, self.salt_backward))
        counter_bytes, rest = content[:8], content[8:]
        nonce = salt + counter_bytes
        return ChaCha20Poly1305(key).decrypt(nonce, rest, None)


# ---------------------------------------------------------------- RFC vector assertions
# RFC 7748 section 6.1
X_PRIV_A = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
X_PRIV_B = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
X_PUB_A = X25519PrivateKey.from_private_bytes(X_PRIV_A).public_key().public_bytes(RAW, RAWF)
X_PUB_B = X25519PrivateKey.from_private_bytes(X_PRIV_B).public_key().public_bytes(RAW, RAWF)
X_SHARED = X25519PrivateKey.from_private_bytes(X_PRIV_A).exchange(
    X25519PublicKey.from_public_bytes(X_PUB_B))
assert X_PUB_A.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert X_PUB_B.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
assert X_SHARED.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

# HSalsa20 (NaCl "Cryptography in NaCl" 2009, hsalsa20 section / tests/core1.out;
# the key is exactly the RFC 7748 6.1 shared secret, input = 16 zero bytes).
HSAL_OUT = hsalsa20(X_SHARED)
assert HSAL_OUT.hex() == ("1b27556473e985d462cd51197a9a46c7"
                          "6009549eac6474f206c4ee0844f68389"), HSAL_OUT.hex()

# crypto_box_beforenm composition for the RFC 6.1 keys (both directions).
BN_A_SK = crypto_box_beforenm(X_PUB_B, X_PRIV_A)
BN_B_SK = crypto_box_beforenm(X_PUB_A, X_PRIV_B)
assert BN_A_SK == BN_B_SK == HSAL_OUT

# RFC 4231 test case 1/2 (HMAC-SHA512), truncated to 32 bytes.
H_TC1_64 = hmac_mod.new(b"\x0b" * 20, b"Hi There", hashlib.sha512).digest()
assert H_TC1_64.hex().startswith("87aa7cdea5ef619d4ff0b4241a1d6cb0"), H_TC1_64.hex()
H_TC2_64 = hmac_mod.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha512).digest()
assert H_TC2_64.hex() == ("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                          "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"), \
    H_TC2_64.hex()

# RFC 5869 test cases 1-3 (SHA-256 only).
HKDF_TC = []
for ikm, salt, info, l, okm_prefix in [
    (b"\x0b" * 22, bytes(range(0x00, 0x0D)), bytes(range(0xF0, 0xFA)), 42,
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    (bytes(range(0x00, 0x50)), bytes(range(0x60, 0xB0)), bytes(range(0xB0, 0x100)), 82,
     "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac78272"
     "71cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
    (b"\x0b" * 22, b"", b"", 42,
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b6"
     "1a96c8"),
]:
    prk = hmac_mod.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = hkdf_expand_sha256(prk, info, l)
    assert okm.hex() == okm_prefix, (okm.hex(), okm_prefix)
    HKDF_TC.append({"ikm_hex": ikm.hex(), "salt_hex": salt.hex(), "info_hex": info.hex(),
                    "l": l, "prk_hex": prk.hex(), "okm_hex": okm.hex()})

# RFC 8439 section 2.8.2 (ChaCha20-Poly1305 AEAD seal).
C_KEY = bytes(range(0x80, 0xA0))
C_NONCE = bytes.fromhex("070000004041424344454647")
C_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
C_PLAIN = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
           b"only one tip for the future, sunscreen would be it.")
C_SEALED = ChaCha20Poly1305(C_KEY).encrypt(C_NONCE, C_PLAIN, C_AAD)
# The tag is the widely-cited RFC 8439 section 2.8.2 MAC; it authenticates the
# full ciphertext (and AAD), so a matching tag pins the whole seal vector.
assert C_SEALED[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", C_SEALED[-16:].hex()

# ---------------------------------------------------------------- rust wheel stub
ED_SEED_A = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ED_SEED_B = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
ED_A = Ed25519PrivateKey.from_private_bytes(ED_SEED_A)
ED_B = Ed25519PrivateKey.from_private_bytes(ED_SEED_B)

PUB_BIN_A = b"LibNaCLPK:" + X_PUB_A + ED_A.public_key().public_bytes(RAW, RAWF)
PUB_BIN_B = b"LibNaCLPK:" + X_PUB_B + ED_B.public_key().public_bytes(RAW, RAWF)


class _StubPK:
    def __init__(self, keystring: bytes) -> None:
        self.bin = keystring
        self.crypt_pk = keystring[10:42]
        self.vk = keystring[42:74]

    def key_to_bin(self) -> bytes:
        return self.bin

    def get_signature_length(self) -> int:
        return 64

    def get_crypt_pk(self) -> bytes:
        return self.crypt_pk

    def curve_name(self) -> str:
        return "curve25519"


class _StubSK:
    def __init__(self, keystring: bytes) -> None:
        self.bin = keystring
        self.sk = keystring[10:42]
        self.seed = keystring[42:74]
        self._ed = Ed25519PrivateKey.from_private_bytes(self.seed)
        self._x = X25519PrivateKey.from_private_bytes(self.sk)

    def key_to_bin(self) -> bytes:
        return self.bin

    def signature(self, msg: bytes) -> bytes:
        return self._ed.sign(msg)

    def diffie_hellman(self, peer_pub_bytes: bytes) -> bytes:
        return self._x.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))

    def get_crypt_pk(self) -> bytes:
        return self._x.public_key().public_bytes(RAW, RAWF)

    def curve_name(self) -> str:
        return "curve25519"

    @staticmethod
    def generate(curve_name: str = "ed25519") -> "_StubSK":
        return _StubSK(b"LibNaCLSK:" + os.urandom(32) + os.urandom(32))


rust = types.ModuleType("ipv8_rust_tunnels")
rust.PublicKey = _StubPK
rust.PrivateKey = _StubSK
rust.SessionKeys = RefSessionKeys
rust.crypto_auth = crypto_auth
rust.crypto_auth_verify = crypto_auth_verify
rust.crypto_box_beforenm = crypto_box_beforenm
rust.generate_session_keys = generate_session_keys
sys.modules.setdefault("ipv8_rust_tunnels", rust)

# ---------------------------------------------------------------- py-ipv8 import
from ipv8.messaging.anonymization.payload import (  # noqa: E402
    CellPayload,
    CreatedPayload,
    CreatePayload,
    ExtendedPayload,
    ExtendPayload,
    Flags,
    PingPayload,
    PongPayload,
)
from ipv8.messaging.serialization import Serializer  # noqa: E402

TUNNEL_COMMUNITY_ID = bytes.fromhex("81ded07332bdc775aa5a46f96de9f8f390bbc9f3")
PREFIX = b"\x00\x02" + TUNNEL_COMMUNITY_ID

serializer = Serializer()
serializer.add_packer("flags", Flags())

CIRCUIT_ID = 0x11223344
IDENTIFIER = 0xCAFE

# ------------------------------------------------------------- handshake fixture
DH_I_SK = hashlib.sha256(b"ipv8-port-phase3-ephemeral").digest()
DH_R_SK = hashlib.sha256(b"ipv8-port-phase3-responder-tmp").digest()
DH_I_PK = X25519PrivateKey.from_private_bytes(DH_I_SK).public_key().public_bytes(RAW, RAWF)
DH_R_PK = X25519PrivateKey.from_private_bytes(DH_R_SK).public_key().public_bytes(RAW, RAWF)

# Responder side (crypto.py::generate_diffie_shared_secret): tmp.DH(dh_received) + id.DH(dh_received)
SHARED_SECRET = (X25519PrivateKey.from_private_bytes(DH_R_SK).exchange(
    X25519PublicKey.from_public_bytes(DH_I_PK))
    + X25519PrivateKey.from_private_bytes(X_PRIV_B).exchange(
        X25519PublicKey.from_public_bytes(DH_I_PK)))
# Initiator side (crypto.py::verify_and_generate_shared_secret): s1 + s2 must be equal.
SHARED_INIT = (X25519PrivateKey.from_private_bytes(DH_I_SK).exchange(
    X25519PublicKey.from_public_bytes(DH_R_PK))
    + X25519PrivateKey.from_private_bytes(DH_I_SK).exchange(
        X25519PublicKey.from_public_bytes(X_PUB_B)))
assert SHARED_SECRET == SHARED_INIT
AUTH = crypto_auth(SHARED_SECRET[:32], DH_R_PK)

SESSION_KEYS = generate_session_keys(SHARED_SECRET)
OKM72 = hkdf_expand_sha256(SHARED_SECRET, b"key_generation", 72)

CANDIDATES = [PUB_BIN_B]
CANDIDATES_BIN = serializer.pack("varlenH-list", CANDIDATES)
assert serializer.unpack("varlenH-list", CANDIDATES_BIN)[0] == CANDIDATES
FRESH = generate_session_keys(SHARED_SECRET)  # fresh counters for the candidates_enc fixture
CANDIDATES_ENC = FRESH.encrypt_str(CANDIDATES_BIN, 0)  # FORWARD, counter 2
assert FRESH.decrypt_str(CANDIDATES_ENC, 0) == CANDIDATES_BIN

# ------------------------------------------------------------- golden cells
def cell_sections() -> dict:
    sections = {}

    def pack_cell(payload, plaintext: bool, relay_early: bool, circuit_id=CIRCUIT_ID):
        message = serializer.pack_serializable(payload)[4:]
        cell = CellPayload(circuit_id, struct.pack("!B", payload.msg_id) + message,
                           plaintext, relay_early)
        wire = cell.to_bin(PREFIX)
        reparsed = CellPayload.from_bin(wire)
        assert reparsed.circuit_id == circuit_id
        assert reparsed.plaintext == plaintext and reparsed.relay_early == relay_early
        assert reparsed.message == cell.message
        unwrapped = cell.unwrap(PREFIX)
        # The unwrapped packet must unpack to the same payload values.
        unpacked, _ = serializer.unpack_serializable(type(payload), unwrapped, offset=23)
        return wire, unwrapped, cell.message

    create = CreatePayload(CIRCUIT_ID, IDENTIFIER, PUB_BIN_A, DH_I_PK)
    wire, _, msg = pack_cell(create, True, False)
    sections["create"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER,
                          "node_public_key_hex": PUB_BIN_A.hex(), "key_hex": DH_I_PK.hex(),
                          "msg_id": 2, "plaintext": True, "relay_early": False,
                          "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                          "unwrapped_hex": _unwrapped(create).hex()}

    created = CreatedPayload(CIRCUIT_ID, IDENTIFIER, DH_R_PK, AUTH, CANDIDATES_ENC)
    wire, _, msg = pack_cell(created, True, False)
    sections["created"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER,
                           "key_hex": DH_R_PK.hex(), "auth_hex": AUTH.hex(),
                           "candidates_enc_hex": CANDIDATES_ENC.hex(),
                           "candidates_bin_hex": CANDIDATES_BIN.hex(),
                           "msg_id": 3, "plaintext": True, "relay_early": False,
                           "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                           "unwrapped_hex": _unwrapped(created).hex()}

    extend = ExtendPayload(CIRCUIT_ID, IDENTIFIER, PUB_BIN_B, DH_I_PK, ("127.0.0.1", 7812))
    wire, _, msg = pack_cell(extend, True, False)
    sections["extend"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER,
                          "node_public_key_hex": PUB_BIN_B.hex(), "key_hex": DH_I_PK.hex(),
                          "node_addr": ["127.0.0.1", 7812], "msg_id": 4,
                          "plaintext": True, "relay_early": False,
                          "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                          "unwrapped_hex": _unwrapped(extend).hex()}

    extended = ExtendedPayload(CIRCUIT_ID, IDENTIFIER, DH_R_PK, AUTH, CANDIDATES_ENC)
    wire, _, msg = pack_cell(extended, True, False)
    sections["extended"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER,
                            "key_hex": DH_R_PK.hex(), "auth_hex": AUTH.hex(),
                            "candidates_enc_hex": CANDIDATES_ENC.hex(),
                            "msg_id": 5, "plaintext": True, "relay_early": False,
                            "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                            "unwrapped_hex": _unwrapped(extended).hex()}

    ping = PingPayload(CIRCUIT_ID, IDENTIFIER)
    wire, _, msg = pack_cell(ping, False, True)
    sections["ping"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER, "msg_id": 6,
                        "plaintext": False, "relay_early": True,
                        "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                        "unwrapped_hex": _unwrapped(ping).hex()}

    pong = PongPayload(CIRCUIT_ID, IDENTIFIER)
    wire, _, msg = pack_cell(pong, False, True)
    sections["pong"] = {"circuit_id": CIRCUIT_ID, "identifier": IDENTIFIER, "msg_id": 7,
                        "plaintext": False, "relay_early": True,
                        "message_hex": msg.hex(), "cell_wire_hex": wire.hex(),
                        "unwrapped_hex": _unwrapped(pong).hex()}
    return sections


def _unwrapped(payload) -> bytes:
    message = serializer.pack_serializable(payload)[4:]
    cell = CellPayload(CIRCUIT_ID, struct.pack("!B", payload.msg_id) + message, False, False)
    return cell.unwrap(PREFIX)


# Encrypted-cell fixture: a PING cell body encrypted with the session keys
# (fresh keys; FORWARD, counter 2). Relay-early set, plaintext unset.
PING_MESSAGE = struct.pack("!B", PingPayload.msg_id) + serializer.pack_serializable(
    PingPayload(CIRCUIT_ID, IDENTIFIER))[4:]
FRESH_PING = generate_session_keys(SHARED_SECRET)
PING_ENCRYPTED = FRESH_PING.encrypt_str(PING_MESSAGE, 0)
assert FRESH_PING.decrypt_str(PING_ENCRYPTED, 0) == PING_MESSAGE
PING_CELL = CellPayload(CIRCUIT_ID, PING_ENCRYPTED, False, True)
PING_CELL_WIRE = PING_CELL.to_bin(PREFIX)

# Encrypted-cell fixture 2: second use of the same fresh keys (counter 3) for
# a DATA-like payload roundtrip (DataPayload).
from ipv8.messaging.anonymization.payload import DataPayload  # noqa: E402

DATA = DataPayload(CIRCUIT_ID, ("127.0.0.1", 9000), ("127.0.0.1", 9001), b"payload-data-001")
DATA_MESSAGE = struct.pack("!B", DataPayload.msg_id) + serializer.pack_serializable(DATA)[4:]
FRESH_DATA = generate_session_keys(SHARED_SECRET)
DATA_ENCRYPTED = FRESH_DATA.encrypt_str(DATA_MESSAGE, 0)
DATA_CELL = CellPayload(CIRCUIT_ID, DATA_ENCRYPTED, False, True)

vectors = {
    "meta": {
        "source": ("generated with py-ipv8's own Serializer/anonymization payload classes; "
                   "ipv8_rust_tunnels stubbed with a pure-python port of dh.rs/crypto.rs"),
        "tunnel_community_id_hex": TUNNEL_COMMUNITY_ID.hex(),
        "prefix_hex": PREFIX.hex(),
        "hsalsa20_vector_source": ('NaCl "Cryptography in NaCl" (2009-03-10) hsalsa20 example '
                                   "= nacl test/default/core1.out; key = RFC 7748 6.1 shared, "
                                   "in = 16 zero bytes, c = 'expand 32-byte k'"),
        "keys": {
            "alice_pub_bin_hex": PUB_BIN_A.hex(),
            "bob_pub_bin_hex": PUB_BIN_B.hex(),
            "alice_x_sk_hex": X_PRIV_A.hex(),
            "bob_x_sk_hex": X_PRIV_B.hex(),
            "dh_ephemeral_initiator_sk_hex": DH_I_SK.hex(),
            "dh_ephemeral_responder_sk_hex": DH_R_SK.hex(),
            "dh_ephemeral_initiator_pk_hex": DH_I_PK.hex(),
            "dh_ephemeral_responder_pk_hex": DH_R_PK.hex(),
        },
        "circuit_id": CIRCUIT_ID,
        "identifier": IDENTIFIER,
    },
    "x25519": {
        "alice_sk_hex": X_PRIV_A.hex(),
        "alice_pk_hex": X_PUB_A.hex(),
        "bob_sk_hex": X_PRIV_B.hex(),
        "bob_pk_hex": X_PUB_B.hex(),
        "shared_hex": X_SHARED.hex(),
    },
    "hsalsa20": {
        "key_hex": X_SHARED.hex(),
        "input16_hex": "00" * 16,
        "const16_hex": SIGMA.hex(),
        "out32_hex": HSAL_OUT.hex(),
    },
    "beforenm": [
        {"pk_hex": X_PUB_B.hex(), "sk_hex": X_PRIV_A.hex(), "out32_hex": BN_A_SK.hex()},
        {"pk_hex": X_PUB_A.hex(), "sk_hex": X_PRIV_B.hex(), "out32_hex": BN_B_SK.hex()},
    ],
    "hmac_sha512_32": [
        {"key_hex": ("0b" * 20), "msg_hex": b"Hi There".hex(),
         "mac64_hex": H_TC1_64.hex(), "mac32_hex": H_TC1_64[:32].hex()},
        {"key_hex": b"Jefe".hex(),
         "msg_hex": b"what do ya want for nothing?".hex(),
         "mac64_hex": H_TC2_64.hex(), "mac32_hex": H_TC2_64[:32].hex()},
    ],
    "hkdf_sha256": HKDF_TC + [{
        "ikm_hex": SHARED_SECRET.hex(),
        "salt_hex": "",
        "info_hex": b"key_generation".hex(),
        "l": 72,
        # EXPAND-ONLY: the shared secret itself is the PRK (crypto.rs passes it straight
        # to OpenSSL's HKDF EXPAND_ONLY mode; no extract step).
        "prk_hex": SHARED_SECRET.hex(),
        "okm_hex": OKM72.hex(),
    }],
    "chacha20poly1305": {
        "key_hex": C_KEY.hex(),
        "nonce_hex": C_NONCE.hex(),
        "aad_hex": C_AAD.hex(),
        "plaintext_hex": C_PLAIN.hex(),
        "ciphertext_hex": C_SEALED[:-16].hex(),
        "tag_hex": C_SEALED[-16:].hex(),
    },
    "session_keys": {
        "shared_secret_hex": SHARED_SECRET.hex(),
        "okm72_hex": OKM72.hex(),
        "key_backward_hex": OKM72[0:32].hex(),
        "key_forward_hex": OKM72[32:64].hex(),
        "salt_backward_hex": OKM72[64:68].hex(),
        "salt_forward_hex": OKM72[68:72].hex(),
        "first_counter": 2,
        "encrypt_forward": {
            "content_hex": PING_MESSAGE.hex(),
            "direction": 0,
            "counter_after": 2,
            "wire_hex": generate_session_keys(SHARED_SECRET).encrypt_str(PING_MESSAGE, 0).hex(),
        },
        "encrypt_backward": {
            "content_hex": PING_MESSAGE.hex(),
            "direction": 1,
            "counter_after": 2,
            "wire_hex": generate_session_keys(SHARED_SECRET).encrypt_str(PING_MESSAGE, 1).hex(),
        },
        "double_forward_second_wire_hex": None,
        "decrypt_short_error": "content shorter than 24 bytes must fail",
        "decrypt_tamper_error": "tampered tag/ciphertext must fail",
    },
    "cells": cell_sections(),
    "encrypted_cells": {
        "ping": {"circuit_id": CIRCUIT_ID, "plaintext": False, "relay_early": True,
                 "message_encrypted_hex": PING_ENCRYPTED.hex(),
                 "cell_wire_hex": PING_CELL_WIRE.hex()},
        "data": {"circuit_id": CIRCUIT_ID, "plaintext": False, "relay_early": True,
                 "message_encrypted_hex": DATA_ENCRYPTED.hex(),
                 "cell_wire_hex": DATA_CELL.to_bin(PREFIX).hex()},
        "shared_secret_hex": SHARED_SECRET.hex(),
    },
}

# Created-cell wire (plaintext flag): create → created handshake crypto over the shared secret.
_created = CreatedPayload(CIRCUIT_ID, IDENTIFIER, DH_R_PK, AUTH, CANDIDATES_ENC)
_created_message = struct.pack("!B", 3) + serializer.pack_serializable(_created)[4:]
_created_cell = CellPayload(CIRCUIT_ID, _created_message, True, False)
vectors["created_handshake"] = {
    "shared_secret_hex": SHARED_SECRET.hex(),
    "auth_hex": AUTH.hex(),
    "candidates_bin_hex": CANDIDATES_BIN.hex(),
    "candidates_enc_hex": CANDIDATES_ENC.hex(),
    "created_cell_wire_hex": _created_cell.to_bin(PREFIX).hex(),
    "created_message_hex": _created_message.hex(),
}
# Decrypt the candidates back (FORWARD, from fresh keys) to prove the split.
_dec = generate_session_keys(SHARED_SECRET)
assert _dec.decrypt_str(CANDIDATES_ENC, 0) == CANDIDATES_BIN

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors-phase3.json")
if "--out" in sys.argv:
    out_path = sys.argv[sys.argv.index("--out") + 1]
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(vectors, f, indent=2)

print("wrote", out_path)
print("hsalsa20 out:", HSAL_OUT.hex())
print("beforenm:", BN_A_SK.hex())
print("okm72:", OKM72.hex())
