# Pure Golang implementation of Yara 

[![PkgGoDev](https://pkg.go.dev/badge/github.com/kgwinnup/go-yara/yara)](https://pkg.go.dev/github.com/kgwinnup/go-yara/yara)

The purpose of this project is primarily for backends written in
Golang requiring Yara. Linking Yara in Golang is kind of annoying,
both statically and dynamically. Additionally, when linking a C
library in Golang there is a little overhead in calling the C library
code. 

My primary use case is matching against text files so the focus is on
getting that feature compatible first, and of course the condition
evaluation.

I also created this project for fun :) Writing parsers and
interpreters are fun, and I enjoy Golang development, even for
parsers.

<strong>This project is a work in progress</strong>

- [x] lexer and parser
- [x] virtual machine for evaluation 
- [x] standard string pattern types
- [x] bytes pattern types
- [ ] optimize Aho-Corasick algorithm, make into table
- [ ] regex pattern types
- [ ] modules 

# Differences with C Yara

The goal is to be feature compatible in all ways, there are areas
where there is some divergence.

## UTF8 encoding by default for Yara files.

Note, I have not read the original Yara C source that closely. Go-yara
is UTF8 encoded by default; this includes all patterns (standard
strings and regex). The matching algorithm uses the raw bytes for
these patterns, including any UTF8 multibyte code points. The `ascii`
modifier leaves the pattern unchanged and in its UTF8 form; the user
is responsible for removing non-ASCII chars if they are present. The
larger change is with the `wide` modifier. In the C Yara `wide` will
add null bytes after each ASCII char (1 byte) and transform into
UTF16LE. Go-yara will transform the UTF8 pattern into UTF16 and fully
support any Unicode characters.

## Byte patterns and wildcards

In C Yara, you can specify wildcard byte matches with the ? char and
th ? can be on either side of the defined byte. In Go-yara, the ?
char, regardless of its position, will treat the entire byte as a wild
card byte.

# Example

see the `cmd/main.go` for a full example

```bash
go get github.com/kgwinnup/go-yara
```

Now in a go file

```
yara, err := yara.New(rule)
if err != nil {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}

contents, err := ioutil.ReadFile(arg)
if err != nil {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	continue
}

output, err := yara.Scan(contents, 3, true)
if err != nil {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	continue
}

for _, obj := range output {
	fmt.Println("Rule:", obj.Name, strings.Join(obj.Tags, ","))
	for _, str := range obj.Strings {
		fmt.Println("   ", str)
	}
}
```
