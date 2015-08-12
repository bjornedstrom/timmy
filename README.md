# timmy - Use some TLS servers for trusted timestamping
0.0.0-DEVEL

"Trusted timestamping" is using a trusted party to sign a timestamp together with a piece of data (normally a hash of a document). This can for example be used to prove that a document was authored at, or before, a certain date.

`timmy` is a command line tool that uses a pecularity in the TLS protocol to let almost any TLS server act as a timestamping server. That is, you can let the TLS server, such as www.google.com, sign your hash with a timestamp provided by the server.

This program is a proof of concept. Use this program at your own risk. See the About section for more details.

## Usage

    $ timmy -f document
	www.google.com signed SHA-256 bf921b493168a... at
	  2015-08-10T22:27:07Z (Unix Timestamp: 1439245627)
	$ sha256sum document
	bf921b493168a...  document

### Gotchas

By default the program will use www.google.com:443 for signing, which as of writing (August 2015) work correctly. Some TLS servers may use implementations that do not include a valid timestamp. RFC compliant implementations should include a timestamp but it's not required to be valid. See chapter 7.4.1.2 of RFC 5426 or RFC 2246 for details. Here's a short list of servers that work:

* www.google.com:443
* www.nsa.gov:443
* letsencrypt.org:443
* www.symantec.com:443
* www.godaddy.com:443

### Attacks

As mentioned above, not all TLS servers supply valid timestamps. This is true for many big websites, such as facebook.com or amazon.com. An attacker can abuse this by repeatedly sending requests to any of these servers until a desired (within some range) timestamp is returned. You should only accept signatures from servers you know are trustworthy in this regard.

## About

The author (Björn) discovered this curiosity of the TLS protocol back in 2012, and wrote a blog post about it here: [blog.bjrn.se](http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html). Now three years later he wanted to learn the Rust programming language and resumed the project.

See LICENSE for licensing information. Copyright (C) Björn Edström <be@bjrn.se> 2012, 2015.
