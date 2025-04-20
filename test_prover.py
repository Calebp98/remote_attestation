import os
import pytest
from prover.prover_core import Prover  # You can change this to match your file structure


def test_keypair_generation():
    prover = Prover()
    assert prover.private_key is not None
    assert prover.public_key is not None

def test_pcr_hashing_consistency():
    state = "bootloader=v1 kernel=v5 app=trusted"
    prover = Prover()
    hash1 = prover.compute_pcr(state)
    hash2 = prover.compute_pcr(state)
    assert hash1 == hash2  # Deterministic hash

def test_pcr_hashing_changes_with_state():
    prover = Prover()
    hash1 = prover.compute_pcr("kernel=v1")
    hash2 = prover.compute_pcr("kernel=v2")
    assert hash1 != hash2

def test_quote_generation_is_deterministic_given_same_inputs():
    prover = Prover()
    nonce = b"random_nonce"
    state = "kernel=v1"
    quote1, sig1 = prover.generate_quote(nonce, state)
    quote2, sig2 = prover.generate_quote(nonce, state)
    
    # Quotes should be identical
    assert quote1 == quote2

    # Both signatures should be valid, even if different
    prover.public_key.verify(sig1, quote1, prover.padding_scheme(), prover.hash_algorithm())
    prover.public_key.verify(sig2, quote2, prover.padding_scheme(), prover.hash_algorithm())


def test_signature_verifies_with_public_key():
    prover = Prover()
    nonce = b"secure_nonce"
    state = "bootloader=ok"
    quote, signature = prover.generate_quote(nonce, state)

    # Signature verification should succeed
    prover.public_key.verify(
        signature,
        quote,
        prover.padding_scheme(),
        prover.hash_algorithm()
    )

def test_prover_key_persistence(tmp_path):
    prover1 = Prover(key_dir=tmp_path)
    prover2 = Prover(key_dir=tmp_path)
    assert prover1.get_public_pem() == prover2.get_public_pem()


