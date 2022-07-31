# Pure Golang implementation of Yara 

The purpose of this project is primarily for backends written in
Golang requiring Yara. Statically compiling Yara is doable but is a
pain, and it muddies up the Golang build pipeline.

I also created this project for fun :) Writing parsers and
interpreters are fun, and I enjoy Golang development, even for
parsers.

<strong>This project is a working in progress</strong>

# Differences with C Yara

The goal is to be feature compatible in all ways, there are areas
where there is some divergence.

1. All go-yara Yara files are UTF8 encoded, and as such Unicode is
   supported by default in a string pattern. All String patterns are
   matched on their exact bytes. So if your UTF8 contains code points
   that are multi-byte, they will be matched correctly. As a result of
   this, the "wide" keyword now converts the UTF8 string into
   UTF16LE.

# Currently supported functionality

What is not supported right now?

1. No byte patterns. E.g. `$b1 = { FF FF FF ?? ... }`
2. No regex. E.g. `$r1 = /.../`

What is supported?

1. Most of regular strings and the operations/conditions for matching
   on them do work. 
2. Full UTF8 strings, so unicode is supported by default. "wide"
   keyword converts UTF8 to UTF16Le



