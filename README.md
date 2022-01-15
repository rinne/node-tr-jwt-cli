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
MHQCAQEEIGapL6ERXjSMjp9WQUEN884hDoDAlgiAW6jlSSVxt1qxoAcGBSuBBAAK
oUQDQgAEj1v74/50oeF3MUMstBCDVwPu6mwLQvTKLdn3aO6BrFPfF4tzDvpAvHJD
lomWoy5nkgPbvfJhghuHw90yBDR6sQ==
-----END EC PRIVATE KEY-----

$ cat es256key.pub
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEj1v74/50oeF3MUMstBCDVwPu6mwLQvTK
Ldn3aO6BrFPfF4tzDvpAvHJDlomWoy5nkgPbvfJhghuHw90yBDR6sQ==
-----END PUBLIC KEY-----

$ jwt-create --private-key-file=es256key
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDIyNDQ3NzYsImV4cCI6MTY0MjI0ODQzNiwianRpIjoiMzFkNTk2YjYtNjNkYy00NmY5LWI4NTktNmMxNWJkOGE5NWUxIiwia2lkIjoiZ2xkZG90dmlhcWZ3In0.8yofRLYLubbuMzdsBUaG_g7jYts9DfzbL_KMhDv3b8HnQ-BlPdqFYP7yLKARq-B6v_Yqb55TB6iynGulpcma5w

$ jwt-validate --public-key-file=es256key.pub --token='eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDIyNDQ3NzYsImV4cCI6MTY0MjI0ODQzNiwianRpIjoiMzFkNTk2YjYtNjNkYy00NmY5LWI4NTktNmMxNWJkOGE5NWUxIiwia2lkIjoiZ2xkZG90dmlhcWZ3In0.8yofRLYLubbuMzdsBUaG_g7jYts9DfzbL_KMhDv3b8HnQ-BlPdqFYP7yLKARq-B6v_Yqb55TB6iynGulpcma5w'
Token successfully verified

$ jwt-validate --public-key-file=es256key.pub --token='eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDIyNDQ3NzYsImV4cCI6MTY0MjI0ODQzNiwianRpIjoiMzFkNTk2YjYtNjNkYy00NmY5LWI4NTktNmMxNWJkOGE5NWUxIiwia2lkIjoiZ2xkZG90dmlhcWZ3In0.8yofRLYLubbuMzdsBUaG_g7jYts9DfzbL_KMhDv3b8HnQ-BlPdqFYP7yLKARq-B6v_Yqb55TB6iynGulpcma5w' -v
Token successfully verified
Issued at 2022-01-15 11:06:16 UTC
Expires at 2022-01-15 12:07:16 UTC
token header: {
  "alg": "ES256",
  "typ": "JWT"
}
token payload: {
  "iat": 1642244776,
  "exp": 1642248436,
  "jti": "31d596b6-63dc-46f9-b859-6c15bd8a95e1",
  "kid": "glddotviaqfw"
}

$ jwt-create --secret-hex='666f6f' | jwt-validate --secret='foo'
Token successfully verified

$ jwt-create --secret-hex='666f6f' --token-issuer='abc' --token-subject='xyz' | jwt-parse
token header: {
  "alg": "HS256",
  "typ": "JWT"
}
token payload: {
  "iss": "abc",
  "sub": "xyz",
  "iat": 1642244881,
  "exp": 1642248541,
  "jti": "f7ee169d-c7d7-4c4b-ad93-1fe3e9994b81"
}
token signature blob length: 32 bytes

$ jwt-parse --token='e30.e30.LQ'
token header: {}
token payload: {}
token signature blob length: 1 bytes
```

Author
======

Timo J. Rinne <tri@iki.fi>


License
=======

GPL-2.0

