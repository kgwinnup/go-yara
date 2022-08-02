# Pure Golang implementation of Yara 

The purpose of this project is primarily for backends written in
Golang requiring Yara. Statically compiling Yara is doable but is a
pain, and it muddies up the Golang build pipeline.

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
- [ ] regex pattern types
- [ ] bytes pattern types
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

output, err := yara.Scan(contents, true)
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
