# SHA1 Digest and HMAC for Common Lisp

A very simple implementation of [SHA1](http://en.wikipedia.org/wiki/SHA-1) and [HMAC-SHA1](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code) for Common Lisp. The code is intended to be easy to follow and is therefore a little slower than it could be.

## Quickstart

There are 6 functions exposed in the `sha1` package:

    (sha1-digest message)                   ;=> digest
    (sha1-hex message)                      ;=> string
    (sha1-base64 message &optional encoder) ;=> string

    (hmac-sha1-digest key message)                   ;=> digest
    (hmac-sha1-hex key message)                      ;=> string
    (hmac-sha1-base64 key message &optional encoder) ;=> string

A *digest* is a list of 20 bytes. The *-hex* functions will return a hexadecimal string that is equal to the digest. The *-base64* functions will return a base64-encoded string of the digest.

They *key* and *message* arguments can either be a sequence of bytes or a string (ASCII or UTF-8).

Some examples (from the Wikipedia pages):

    CL-USER > (sha1-digest "")
    (218 57 163 238 94 107 75 13 50 85 191 239 149 96 24 144 175 216 7 9)

    CL-USER > (sha1-hex "The quick brown fox jumps over the lazy dog")
    "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"

    CL-USER > (require :base64) ;; From massung/base64
    CL-USER > (sha1-base64 "The quick brown fox jumps over the lazy dog"
                           #'base64:base64-encode)
    "L9ThxnotKPzthJ7hu3bnORuT6xI="

    CL-USER > (hmac-sha1-hex "key" "The quick brown fox jumps over the lazy dog")
    "DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9"

That's it!
