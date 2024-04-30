# Gemcert

A simple tool for creating self-signed certs for use in Geminispace.

Gemcert is designed to be a less overwhelming alternative to the `openssl`
command line tool, especially for people who don't like blindly copying and
pasting long, opaque commands without understanding them but also feel like they
shouldn't need to wade through multiple long man pages just to make a
self-signed certificate.  It does just what is needed for typical Gemini server
or client certificates with sensible defaults and a handful of straightforward
options for extra control.

## Usage

### Server certificates

Use the following command to generate a self-signed certificate to use with a
Gemini server:

```sh
gemcert --server --domain example.com
```

This will generate a certificate with a CommonName of example.com, but will
include both `example.com` and `*.example.com` in the Subject Alternate Names
field.  In other words, gemcert generates wildcard certificates by default.
Because many Gemini clients use the TOFU model, frequent certificate changes
should be avoided wherever possible, so it's better to remain flexible at the
outset - you might have no plans to use subdomains right now, but are you sure
you won't change your mind next year?  Oh, you are?  Then you can use:

```sh
gemcert --server --nowild --domain example.com
```

To get a certificate valid only for `example.com`.

### Client certificates

Use the following command to generate a self-signed certificate to use as a
client certificate:

```sh
gemcert --client
```

The x.509 standard allows a certificate's Subject to be empty, but not its
Issuer.  Gemcert produces client certificates with an Issuer whose CN is
"gemini", and where all other fields of the Issuer DN are empty.  Even though
empty Subjects are valid in principle, the Go standard library tools force
the Issuer and Subject of self-signed certificates to be identical, so your
client certs will end up with a Subject CN of "gemini" as well.

Some applications (e.g. astrobotany) use your client cert's Subject CN as a
username in the application.  You can use the `-cn` option to specify your
own Subject CN in certs destined for use with such an application:

```sh
gemcert --client --cn username
gemcert --client --cn "Gus Grissom"
```

### Certificate lifetimes

The validity period of a certificate always begins at the time it was generated.
By default, server certificates are valid for 5 years beyond that time, and
client certificates for 1 day.  No matter which certificate type you are
creating, you can easily specify the validity lifetime you would like using any
combination of the `--years`, `--months`, `--days` and `--hours` options:

```
gemcert --server --domain example.com --years 3 --months 6 --days 12 --hours 4
```

### Key types

By default, gemcert produces keys for the ECDSA signature scheme, using the P256
NIST curve.  The resulting certificates are much smaller than the RSA
certificates commonly used on the web, and will work with just about any TLS
implementation, even if you are stuck with a relatively old version.  This kind
of cert seems to represent the best current trade-off between small certificate
size and broad compatibility.

As a single alternative, gemcert can also produce keys for the ED25519
signature scheme, via the `--ed25519` option:

```sh
gemcert --server --ed25519 --domain example.com
```

The resulting certificates will be even smaller, and many consider them more
secure than ECDSA (or, more precisely, ECDSA using the NIST standard curves,
which are the only ones widely supported).  These are ideal certificates for
use with Gemini, but unfortunately they are not yet as widely supported as
ECDSA.  If you use one of these certs for your server, be aware that some
clients (including most mobile clients) will be unable to access them.
Hopefully this situation will change in the near future.  For the time being,
these certs are still useful for use as client certificates if your own client
and a particular application server you want to use both support ED25519.

### Output files

Server certificate and key files will be written to files with names derived
from the domain, e.g. `example.com.crt` and `example.com.key`.  Client
certificates are written instead to `key.pem` and `cert.pem`, or `key.der` and
`cert.der` (an ugly inconsistency which is not long for this world).  Either
way, the files will be written to the current working directory, will be in PEM
(plain text) or DER (binary) format, and gemcert will not ask before overwriting
existing files, so use with caution!

DER certificates are smaller than PEMs and can be created with the `--der`
option:

```sh
gemcert --server --ed25519 --der --domain example.com
```
