from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
from calendar import timegm
import sqlite3

# import uuid
import json
import jwt

# Cody Quinn Hogan |    cqh0003                   |    11342946
# CSCE 3550.001    |    Project 1: JWKS Server    |    server.py
# codyhogan2@my.unt.edu


class RequestHandler(BaseHTTPRequestHandler):
    JWKS = {"keys": []}  # sets up storage for JWKs

    def do_PUT(self):  # handles any PUT request by sending back Method Not Allowed
        self.send_response(405)
        self.end_headers()

    def do_DELETE(
        self,
    ):  # handles any DELETE request by sending back Method Not Allowed
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):  # handles any PATCH request by sending back Method Not Allowed
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):  # handles any HEAD request by sending back Method Not Allowed
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.end_headers()
            curs = db.cursor()

            select = "SELECT * FROM keys WHERE exp > ?;"
            curs.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
            rows = curs.fetchall()

            for row in rows:
                expiry = row[2]
                priv_key_bytes = row[1]
                keyID = str(row[0])
                priv_key = load_pem_private_key(priv_key_bytes, None)
                pub_key = priv_key.public_key()

                JWK = {
                    "kid": keyID,
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": base64url_encode(
                        bytes_from_int(pub_key.public_numbers().n)
                    ).decode(
                        "UTF-8"
                    ),  # base64 encoded Modulus
                    "e": base64url_encode(
                        bytes_from_int(pub_key.public_numbers().e)
                    ).decode(
                        "UTF-8"
                    ),  # base64 encoded Exponent
                }
                if not expiry <= timegm(
                    datetime.now(tz=timezone.utc).timetuple()
                ):  # adds JWK to the list if it is not expired
                    self.JWKS["keys"].append(JWK)

            self.wfile.write(json.dumps(self.JWKS, indent=1).encode("UTF-8"))
            return
        else:  # handles any GET request not targeted to /.well-known/jwks.json by sending back Method Not Allowed
            self.send_response(405)
            self.end_headers()
            return

    def do_POST(self):
        if (
            self.path == "/auth"
            or self.path == "/auth?expired=true"
            or self.path == "/auth?expired=false"
        ):
            expired = False
            if self.path == "/auth?expired=true":  # will generate and expired KID
                expired = True
            self.send_response(200)
            self.end_headers()
            curs = db.cursor()

            if expired:
                select = "SELECT kid, key, exp FROM keys WHERE exp <= ?;"
            else:
                select = "SELECT * FROM keys WHERE exp > ?;"
            curs.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
            key_row = curs.fetchone()

            expiry = key_row[2]
            priv_key_bytes = key_row[1]
            keyID = str(key_row[0])
            jwt_token = jwt.encode(
                {"exp": expiry},
                priv_key_bytes,
                algorithm="RS256",
                headers={"kid": keyID},
            )  # creates the JWT token with specified expiry and KID
            self.wfile.write(
                bytes(jwt_token, "UTF-8")
            )  # provides the requester with the JWT token
            return
        else:  # handles any POST request not targeted to /auth by sending back Method Not Allowed
            self.send_response(405)
            self.end_headers()
            return


http_server = HTTPServer(
    ("", 8080), RequestHandler
)  # create server on http://localhost:8080

db = sqlite3.connect("totally_not_my_privateKeys.db")
db.execute(
    "CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);"
)

print("Generating key pairs... Please wait...")
for i in range(5):
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_key_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )  # converts private key into its bytes object
    if i % 2 == 0:  # provides expired time
        expiry = datetime.now(tz=timezone.utc) + timedelta(0, -3600, 0)
    else:  # provides expiry in one hour
        expiry = datetime.now(tz=timezone.utc) + timedelta(0, 3600, 0)

    insert = "INSERT INTO keys (key, exp) VALUES(?, ?);"
    db.execute(insert, (priv_key_bytes, timegm(expiry.timetuple())))
db.commit()
print("HTTP Server running on Localhost port 8080...")
try:
    http_server.serve_forever()  # run forever
except KeyboardInterrupt:  # stop running on KeyboardInterrupt
    db.close()
    pass
http_server.server_close()  # close server
