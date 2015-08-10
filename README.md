# timmy - Use (almost) any TLS server for trusted timestamping
0.0.0-DEVEL

"Trusted timestamping" is using a trusted party to sign a timestamp together with a piece of data (normally a hash of a document). This can for example be used to prove that a document was authored at, or before, a certain date.

`timmy` is a command line tool that uses a pecularity in the TLS protocol to let almost any TLS server act as a timestamping server. That is, you can let the TLS server, such as www.google.com, sign your hash with a timestamp provided by the server.

## Usage

    $ timmy -f document
	www.google.com signed SHA-256 bf921b493168a050884f723dc13fa4b1fc0afe95d06ce8cd4d66b4087204cbd0 at 2015-08-10T22:27:07Z (Unix Timestamp: 1439245627)
	$ sha256sum document
	bf921b493168a050884f723dc13fa4b1fc0afe95d06ce8cd4d66b4087204cbd0  document

## About

The author (Björn) discovered this curiosity of the TLS protocol back in 2012, and wrote a blog post about it here: [blog.bjrn.se](http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html). Now three years later he wanted to learn the Rust programming language and resumed the project.

See LICENSE for licensing information. Copyright (C) Björn Edström <be@bjrn.se> 2012, 2015.
