# timmy - Use (almost) any TLS server for trusted timestamping
0.0.0-DEVEL

"Trusted timestamping" is using a trusted party to sign a timestamp together with a piece of data (normally a hash of a document). This can for example be used to prove that a document was authored at, or before, a certain date.

`timmy` is a command line tool that uses a pecularity in the TLS protocol to let almost any TLS server act as a timestamping server. That is, you can let the TLS server, such as www.google.com, sign your hash with a timestamp provided by the server.

## About

The author (Björn) discovered this curiosity of the TLS protocol back in 2012, and wrote a blog post about it here: [blog.bjrn.se](http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html). Now three years later he wanted to learn the Rust programming language and resumed the project.
