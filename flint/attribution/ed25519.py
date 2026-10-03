"""Ed25519 signers and verifiers for ``flint.attribution`` (the ``[attribution]`` extra).

These are reference implementations of the ``Signer`` and ``Verifier`` protocols,
backed by ``cryptography``. A deployment that keeps its keys in a hardware or OS
keystore implements the same two-method protocols instead; nothing else in FLINT
touches key material.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Ed25519Signer:
    """Signs with one Ed25519 private key, identified to verifiers as ``kid``."""

    def __init__(self, private_key: Ed25519PrivateKey, kid: str) -> None:
        self._key = private_key
        self._kid = kid

    @classmethod
    def generate(cls, kid: str) -> Ed25519Signer:
        """A fresh random key; for tests and examples, not for key custody."""
        return cls(Ed25519PrivateKey.generate(), kid)

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class Ed25519Verifier:
    """Verifies against a key ring ``{kid: public key}``; revoked kids never verify.

    Revocation fails safe: a revoked key's labels read as untrusted and its
    capabilities admit nothing, so revoking can only add alerts, never hide one.
    """

    def __init__(
        self,
        keys: Mapping[str, Ed25519PublicKey | bytes],
        revoked: Collection[str] = (),
    ) -> None:
        self._keys = {
            kid: Ed25519PublicKey.from_public_bytes(k) if isinstance(k, bytes) else k
            for kid, k in keys.items()
        }
        self._revoked = frozenset(revoked)

    @classmethod
    def of(cls, *signers: Ed25519Signer, revoked: Collection[str] = ()) -> Ed25519Verifier:
        """A verifier for the public halves of ``signers``."""
        return cls({s.kid: s.public_key for s in signers}, revoked)

    def verify(self, kid: str, message: bytes, signature: bytes) -> bool:
        if kid in self._revoked:
            return False
        key = self._keys.get(kid)
        if key is None:
            return False
        try:
            key.verify(signature, message)
        except InvalidSignature:
            return False
        return True
