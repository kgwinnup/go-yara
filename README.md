# Pure Golang implementation of Yara 

The purpose of this project is primarily for backends written in
Golang requiring Yara. Statically compiling Yara is doable but is a
pain, and it muddies up the Golang build pipeline.

I also created this project for fun :) Writing parsers and
interpreters are fun, and I enjoy Golang development, even for
parsers.

<strong>This project is a work in progress</strong>

- [x] lexer and parser
- [x] operations/condition evaluation (pre Yara 4.2)
- [x] standard string pattern types
- [ ] regex pattern types
- [ ] bytes pattern types
- [ ] Yara 4.2+ evaluation support

# Differences with C Yara

The goal is to be feature compatible in all ways, there are areas
where there is some divergence.

1. All go-yara Yara files are UTF8 encoded, and as such Unicode is
   supported by default in a string pattern. All String patterns are
   matched on their exact bytes. So if your UTF8 contains code points
   that are multi-byte, they will be matched correctly. As a result of
   this, the "wide" keyword now converts the UTF8 string into
   UTF16LE.

