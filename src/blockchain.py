#!/usr/bin/env python3
"""Demonstrates an extremely minimalistic Bitcoin Wallet"""
from time import sleep

import bitcoin
from bitcoinlib.keys import Address,HDKey
from bitcoinlib.wallets import Wallet
from flask_json import as_json, FlaskJSON
from flask import Flask, jsonify, request
from mtls import *
from pathlib import Path

app = Flask(__name__)
json = FlaskJSON(app)

@as_json
@app.route("/keygen/path", methods=['POST', 'GET'])
def generate_child_key(path):
    """(Re)-Generates the key at given path"""
    ret = master_key.subkey_for_path(path).wif_private()
    return ret.address()


@as_json
@app.route("/keygen/classic", methods=['POST', 'GET'])
def sign_transaction(path,tx):
    """Signs transaction with key at given path"""
    key = master_key.subkey_for_path(path)
    wallet.sign(keys=[key])
    return None


master_key = HDKey()
master_addr = Address(master_key.public_hex)

# Create new Wallet, even if one exists
dbfile = Path("~/.bitcoinlib/database/bitcoinlib.sqlite")
if dbfile.exists(): dbfile.unlink()
wallet = Wallet.create("master",keys=[master_key])

input("Please send some testnet coins to this address: %s"%(wallet.addresslist()))

sleep(5)
print("Thanks, your balance is now: %d"%wallet.balance())

app.run(ssl_context=ssl_context, request_handler=PeerCertWSGIRequestHandler)
