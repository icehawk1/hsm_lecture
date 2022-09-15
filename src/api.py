#!/usr/bin/env python3
# encoding: utf-8
"""Demonstrates how to implement an API for an HSM"""

from mtls import *
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, jsonify, request
from flask_json import FlaskJSON, as_json

app = Flask(__name__)
json = FlaskJSON(app)
next_key_id = 0

chosen_hash = hashes.SHA256()
mypad = padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH)

users = dict()

# After we entered an HSM cluster, we store corresponding info here
cluster_info = None

class User:
    def __init__(self, uid, sym_key, asym_key):
        self.uid = uid
        self.sym_key = sym_key
        self.asym_key = asym_key


@app.route('/')
def index():
    return "This is an API with following Endpoints: \n- /create_user\n- /encrypt/USER_ID\n/decrypt/USER_ID\n- /sign/USER_ID\n-/verify/USER_ID"


@as_json
@app.route("/create_user", methods=['POST', 'GET'])
def create_user():
    return dict(key_id=_create_user())


@as_json
@app.route("/encrypt/<int:user_id>", methods=['POST', 'GET'])
def encrypt(user_id):
    """Encrypts given plaintext and returns ciphertext, with 16 byte tag appended, and nonce"""
    pt = str(request.get_json(force=True)["plaintext"]).encode("utf-8")

    gcm = AESGCM(users[user_id].sym_key)
    nonce = os.urandom(12)

    ct = gcm.encrypt(nonce, pt, b"")
    ret = dict(ciphertext=ct.hex(), nonce=nonce.hex())
    print("yo")
    return ret


@as_json
@app.route("/decrypt/<int:user_id>", methods=['POST', 'GET'])
def decrypt(user_id):
    """Decrypts given ciphertext with given nonce"""
    gcm = AESGCM(users[user_id].sym_key)

    ct = bytes.fromhex(request.get_json(force=True)["plaintext"])
    nonce = bytes.fromhex(request.get_json(force=True)["nonce"])

    pt = gcm.decrypt(nonce, ct, b"")
    return dict(plaintext=pt)


@as_json
@app.route("/sign/<int:user_id>", methods=['POST', 'GET'])
def sign(user_id):
    """Signs given data with users master key"""
    hasher = hashes.Hash(chosen_hash)
    hasher.update(bytes.fromhex(request.get_json(force=True)["plaintext"]))
    digest = hasher.finalize()

    sig = users[user_id].asym_key.sign(digest, mypad, chosen_hash)
    return dict(sig=sig.hex())


@as_json
@app.route("/verify/<int:user_id>", methods=['POST', 'GET'])
def verify(user_id):
    """Verifies given signature with users master key"""
    pt = bytes.fromhex(request.get_json(force=True)["plaintext"])
    sig = bytes.fromhex(request.get_json(force=True)["signature"])
    pubkey = users[user_id].asym_key.public_key()
    pubkey.verify(sig, pt, mypad, chosen_hash) # verify() raises Exception when sig is invalid
    return dict(result=True)


def create_hsm_cluster(peer_ip):
    """Asks the given HSM to join this HSM in clustering mode"""
    # Generate some parameters. These can be reused.
    cluster_info = dict()

    parameters = dh.generate_parameters(generator=2, key_size=1024)
    private_key = parameters.generate_private_key()

    # We remember Peer pubkey, so we can detect MitM-Attacks later on
    cluster_info['peer_public_key'] = _request_cluster_public_key(ip)
    shared_key = private_key.exchange(peer_public_key)

    # Perform key derivation.
    cluster_info['derived_key'] = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

def _create_user():
    global next_key_id

    sym_key = AESGCM.generate_key(bit_length=128)
    asym_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    users[next_key_id] = User(next_key_id, sym_key, asym_key)
    next_key_id += 1
    return next_key_id - 1


_create_user()
app.run(debug=True, port=5001, ssl_context='adhoc')
