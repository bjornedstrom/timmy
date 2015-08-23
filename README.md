# timmy - Use some TLS servers for trusted timestamping
0.0.0-DEVEL

"Trusted timestamping" is using a trusted party to sign a timestamp together with a piece of data (normally a hash of a document). This can for example be used to prove that a document was authored at, or before, a certain date.

`timmy` is a command line tool that uses a pecularity in the TLS protocol to let almost any TLS server act as a trusted timestamping server. That is, you can let the TLS server, such as www.google.com, sign your hash with a *timestamp provided by the server*.

This program is a proof of concept. Use this program at your own risk. See the About section for more details.

## Usage

    $ timmy -f document > output.json
	www.google.com signed SHA-256 bf921b493168a... at
	  2015-08-22T20:04:24Z (Unix Timestamp: 1440273864)
	
	$ sha256sum document
	bf921b493168a...  document
    
    $ timmy -v output.json
    Signature verification SUCCESS.
    Warning! Signature only verified against first X509 certificate.
    Please verify yourself that the certificate chain is valid.
    
    C=US/ST=California/L=Mountain View/O=Google Inc/CN=google.com/ Signed
	  SHA-256 bf921b493168a050884f723dc13fa4b1fc0afe95d06ce8cd4d66b4087204cbd0
	  at 2015-08-22T20:04:24Z (Unix Timestamp: 1440273864)

### Gotchas

By default the program will use www.google.com:443 for signing, which as of writing (August 2015) work correctly. Some TLS servers may use implementations that do not include a valid timestamp. RFC compliant implementations should include a timestamp but it's not required to be valid. See chapter 7.4.1.2 of RFC 5426 or RFC 2246 for details. Here's a short list of servers that work:

* www.google.com:443
* www.nsa.gov:443
* letsencrypt.org:443
* www.symantec.com:443
* www.godaddy.com:443

timmy will detect these invalid servers and refuse to sign (TODO: implement similar for verification):

    $ timmy -f document -s facebook.com
	ERROR! Server responded with invalid time! Aborting.

A further gotcha is that many of the *valid* servers are configured with short lived certificates nowadays. For example Googles certificates are routinely only valid for a few months at most. On signature verification timmy will check that the timestamp signed falls within the valid dates. You may see this after a while:

    $ timmy -v output.json
    ERROR! Signature verification FAILURE: Certificate has expired.

### Attacks

As mentioned above, not all TLS servers supply valid timestamps. This is true for many big websites, such as facebook.com or amazon.com. An attacker can abuse this by repeatedly sending requests to any of these servers until a desired (within some range) timestamp is returned. You should only accept signatures from servers you know are trustworthy in this regard.

### Input, Output, Signature and Certificates

When you sign a document with timmy, you sign a SHA-256 hash. For convenience timmy will calculate this hash for you for your input file. Lets call this hash `H`. `H` is sent to the server in a special way and you will get some data back.

The output when you sign is a JSON blob that contains three Base64 coded fields:

* `"certificates"` is a list of certificates: the certificate chain returned by the TLS server. The first certificate in the list is the one that signs your data.
* `"blob"` is the data signed. The first 32 bytes is the hash `H` and the following 4 bytes is the timestamp. The rest of the data in the blob are internal to the TLS handshake and can be ignored for our purpose.
* `"signature"` is the server's signature of the blob. It is signed by the private key corresponding to the public key in `certificates[0]`.

## Building

    $ cargo build

## Appendix A: Signature Details

To avoid confusion I'd only recommend you to read this section if you are comfortable with cryptography and the TLS protocol. Otherwise this may be confusing.

The "signature" returned by the TLS server is a PKCS 1.5 padded hash of the "blob". The hash in this case is the unusual TLS 1 construction TLSHash(h) = MD5(h) || SHA1(h).

## About

The author (Björn) discovered this curiosity of the TLS protocol back in 2012, and wrote a blog post about it here: [blog.bjrn.se](http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html). Now three years later he wanted to learn the Rust programming language and resumed the project.

See LICENSE for licensing information. Copyright (C) Björn Edström <be@bjrn.se> 2012, 2015.
