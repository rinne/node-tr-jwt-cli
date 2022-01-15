In a Nutshell
=============

This is a command line tool for creating and validating JSON Web
Tokens (JWT).

Public keys (RSA and EC) and shared secrets are supported.

Supported JWT algorithms are: HS256, HS384, HS512, RS256, RS384,
RS512, PS256, PS384, PS512, ES256, ES384, and ES512.

Reference
=========

jwt-keygen \[\<opt\> ...\]
--------------------------

Generate a key pair to be used with JWT tokens. Keys generated with
other tools, such as `openssl`, can be used with these tools. A tool
to generate suitable keys for various JWT algorithms is provided
anyways. Key generation tool blindly trusts node.js capability to
generate secure keys. Your mileage may vary and you may want to
generate your production keys with some other method. However, With a
reasonably fresh node.js version, you'll most likely be fine.

This tool does not provide ways to tweak key parameter details, but
instead it just generates a key that is for all intents and purposes
suitable to be used with a given JWT algorithm. Also, `jwt-create` is
able to select the intended JWT algorithm from the generated key, so
the algorithm does not have to be explicitly passed to `jwt-create`
later if the key is generated using `jwt-keygen`.

The tool creates two files.  The file with a name given witn
`--output` option, is the filename for the private key. The public key
is written to the file with `.pub` suffix.

### Options

```
-a <arg>  --jwt-algorithm=<arg>  JWT algorithm for the key pair.
          --output=<arg>         Filename for the secret key.
-v        --verbose              Enable verbose output.
-h        --help                 Show help and exit
```


jwt-create  \[\<opt\> ...\]
---------------------------

Create a JWT token either using a private key or a shared secret to
sign the token.  In most cases, the JWT algorithm to be used, is
automatically derived from the key.

Token property-value pairs passed with option `--token-property` can
be separated either with an equals sign `=` or a semicolon `:`. Values
of the properties with a semicolon sign are handled as strings whereas
values with an equals sign are integers and are also included into the
token as a numeric type.

Removing properties from the token payload using
`--exclude-token-property`, may result a token that does not validate
properly. Option `--exclude-token-property=*` removes all payload
properties from the created token effectively creating a token with
empty object `{}` as payload.  This may be useful for testing in some
cases, but should never be used in production use. Option
`--exclude-token-property` is applied just before token signing, so it
will potentially exclude also properties explicitly added using
`--token-property` or other options adjusting the token payload, such
as `--token-issuer` or `--token-ttl`.

### Options

```
-a <arg>  --jwt-algorithm=<arg>           Force JWT algorithm to be used.
          --token-ttl=<arg>               Default validity time for tokens in seconds.
          --token-issuer=<arg>            Issuer name to be included into tokens.
          --token-subject=<arg>           Subject name to be included into tokens.
          --token-property=<arg>          Extra name:value pair to be included into tokens.
          --exclude-token-property=<arg>  Exclude property from the token before signing.
          --token-key-id=<arg>            Override key-id in token.
          --skip-validation               Do not validate the created token.
          --private-key-file=<arg>        Read token signing key from file.
          --secret=<arg>                  Symmetric secret for token signing.
          --secret-hex=<arg>              Symmetric secret for token signing in hexadecimal.
-v        --verbose                       Enable verbose output.
-h        --help                          Show help and exit
```

jwt-validate  \[\<opt\> ...\]
-----------------------------

Validate a JWT token. If no token is passed as a command line
parameter, the program reads it from the standard input. With verbose
output, the contents of the token may be examined even if the token
does not validate.


### Options

```
          --public-key-file=<arg>  Read token signature public key from file.
          --secret=<arg>           Symmetric token signing secret.
          --secret-hex=<arg>       Symmetric secret for token signing in hexadecimal.
-a <arg>  --jwt-algorithm=<arg>    Accept only a given JWT algorithm.
          --strict                 Be strict!
-v        --verbose                Enable verbose output.
          --token=<arg>            Token to be verified.
-h        --help                   Show help and exit
```

jwt-parse  \[\<opt\> ...\]
--------------------------

Parse a JWT token. If no token is passed as a command line
parameter, the program reads it from the standard input.

### Caution!

This command only parses and prints the token contents. It does not
check the token signature nor does it do any contextual validation at
all. It is strictly a debugging tool.

### Options

```
-v  --verbose        Enable verbose output.
    --token=<arg>    Token to be parsed.
-h  --help           Show help and exit
```

Examples
========

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

$ jwt-create --private-key-file=es256key
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

$ jwt-create --secret-hex='666f6f' | jwt-validate --secret='foo'
Token successfully verified

$ jwt-create --secret-hex='666f6f' | jwt-parse
token header: {
  "alg": "HS256",
  "typ": "JWT"
}
token payload: {
  "iss": "anonymous",
  "sub": "anonymous",
  "iat": 1642241823,
  "exp": 1642245483,
  "jti": "10750195-9c67-4ffa-8add-8528ba064c57"
}
token signature blob length: 32 bytes
```

Author
======

Timo J. Rinne <tri@iki.fi>


License
=======

GPL-2.0

