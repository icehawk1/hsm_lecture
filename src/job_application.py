#!/usr/bin/env python3
"""Shows a web page where you can apply for a job"""
import json

from flask import Flask, request
import sqlite3, requests
import os.path

app = Flask(__name__)


@app.route("/")
@app.route("/index.html")
def hello():
    with open('resources/job_application.html', 'r') as fp:
        data = fp.read()
    return data


@app.route("/apply_for_job", methods=["POST"])
def apply():
    vorname = encrypt_data(request.form["vorname"])
    print("type vorname: ",type(vorname))
    nachname = encrypt_data(request.form["nachname"])
    email = encrypt_data(request.form["email"])
    anschreiben = encrypt_data(request.form["anschreiben"])
    gehalt = encrypt_data(request.form["gehalt"])

    execute_db_query("INSERT INTO bewerbungen VALUES (?,?,?,?,?, ?,?,?,?,?)",
        (vorname["ciphertext"],nachname["ciphertext"],email["ciphertext"], anschreiben["ciphertext"], gehalt["ciphertext"],
         vorname["nonce"],nachname["nonce"],email["nonce"], anschreiben["nonce"], gehalt["nonce"]))

    with open('resources/accepted.html', 'r') as fp:
        data = fp.read()
    return data


def execute_db_query(query, params=None):
    assert query is not None
    dbcon = sqlite3.connect(dbfile)

    cur = dbcon.cursor()
    if params is not None:
        cur.execute(query,params)
    else:
        cur.execute(query)

    dbcon.commit()
    dbcon.close()


def encrypt_data(data):
    resp = requests.post(api_url+"/encrypt/%d"%userid, json={"plaintext": data}, verify=False)
    assert 200 <= resp.status_code <= 299
    ct = json.loads(resp.text)
    return ct


cert_file_path = "./resources/client.cert.pem"
key_file_path = "./resources/client.key.pem"
api_url = "https://localhost:5001"

resp = requests.post(api_url+"/create_user", cert=(cert_file_path, key_file_path), verify=False)
assert 200 <= resp.status_code <= 299 , "Could not create user"
userid = int(json.loads(resp.text)["key_id"])
dbfile = "/tmp/bewerbungen.db"

if not os.path.exists(dbfile):
    execute_db_query('''CREATE TABLE bewerbungen (vorname TEXT, nachname TEXT, email text, anschreiben TEXT, gehaltsvorstellung TEXT, 
    vorname_nonce TEXT, nachname_nonce TEXT, email_nonce text, anschreiben_nonce TEXT, gehaltsvorstellung_nonce TEXT)''', None)

app.run(ssl_context='adhoc', host="0.0.0.0", port=443 , debug=False)

