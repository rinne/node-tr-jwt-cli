In a Nutshell
=============

This is a command line tool for creating and validating JSON Web
Tokens (JWT).

Public keys (RSA and EC) and shared secrets are supported.

Key generation tool blindly trusts node.js capability to generate
secure keys. Your mileage may vary.


Example
=======

```
$ jwt-keygen --jwt-algorithm=ES256 --output=es256key

$ cat es256key
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEII6APc8+PB13Jr6KNl1jNCPER14yV2V7GUopEJA2DlR8oAcGBSuBBAAK
oUQDQgAEd7QH6h68PVjh6SNLKQW6bMfCuFjnzGJJIE2BBtjAk5jUJOxQTtyPqhP9
gGZC3uU4vlIODHLc4FVIc5PctG0MVQ==
-----END EC PRIVATE KEY-----

$ cat es256key.pub
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEd7QH6h68PVjh6SNLKQW6bMfCuFjnzGJJ
IE2BBtjAk5jUJOxQTtyPqhP9gGZC3uU4vlIODHLc4FVIc5PctG0MVQ==
-----END PUBLIC KEY-----

$ jwt-create --secret-key-file=es256key --hash-length=256
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhbm9ueW1vdXMiLCJzdWIiOiJhbm9ueW1vdXMiLCJpYXQiOjE2NDEzNjYzMTUsImV4cCI6MTY0MTM2OTk3NSwianRpIjoiYzA0NmVkYzEtYTRlYy00YzcyLWI3ZGQtNTYwNjVkYWI3NjBmIiwia2lkIjoiZ3lrd3N1Y2dkanJ3In0.MLZS-UNPC3KAE4k97j-axeV93y_yr1nwinG4opcWHf5R9HEtgQiCoSpB3_z8m3RHJg7kdvgKQ6pKKZ4nuk439A

$ jwt-validate --public-key-file=es256key.pub --token='eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhbm9ueW1vdXMiLCJzdWIiOiJhbm9ueW1vdXMiLCJpYXQiOjE2NDEzNjYzMTUsImV4cCI6MTY0MTM2OTk3NSwianRpIjoiYzA0NmVkYzEtYTRlYy00YzcyLWI3ZGQtNTYwNjVkYWI3NjBmIiwia2lkIjoiZ3lrd3N1Y2dkanJ3In0.MLZS-UNPC3KAE4k97j-axeV93y_yr1nwinG4opcWHf5R9HEtgQiCoSpB3_z8m3RHJg7kdvgKQ6pKKZ4nuk439A'
Token successfully verified

$ jwt-validate --public-key-file=es256key.pub --token='eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhbm9ueW1vdXMiLCJzdWIiOiJhbm9ueW1vdXMiLCJpYXQiOjE2NDEzNjYzMTUsImV4cCI6MTY0MTM2OTk3NSwianRpIjoiYzA0NmVkYzEtYTRlYy00YzcyLWI3ZGQtNTYwNjVkYWI3NjBmIiwia2lkIjoiZ3lrd3N1Y2dkanJ3In0.MLZS-UNPC3KAE4k97j-axeV93y_yr1nwinG4opcWHf5R9HEtgQiCoSpB3_z8m3RHJg7kdvgKQ6pKKZ4nuk439A' -v
Token successfully verified
Issued at 2022-01-05 07:05:15 UTC
Expires at 2022-01-05 08:06:15 UTC
token header: {
  "alg": "ES256",
  "typ": "JWT"
}
token payload: {
  "iss": "anonymous",
  "sub": "anonymous",
  "iat": 1641366315,
  "exp": 1641369975,
  "jti": "c046edc1-a4ec-4c72-b7dd-56065dab760f",
  "kid": "gykwsucgdjrw"
}
```

Author
======

Timo J. Rinne <tri@iki.fi>


License
=======

GPL-2.0

