package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/kgwinnup/go-yara/internal/exec"
)

func main() {

	debug := flag.Bool("debug", false, "debug rules")
	flag.Parse()

	rule := ""

	if len(flag.Args()) > 0 {
		bs, err := ioutil.ReadFile(flag.Args()[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		rule = string(bs)
	} else {
		bs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		rule = string(bs)
	}

	compiled, err := exec.Compile(rule)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if *debug {
		compiled.Debug()
	}

	for i, arg := range flag.Args() {

		if i == 0 {
			continue
		}

		contents, err := ioutil.ReadFile(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		output, err := compiled.Scan(contents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		for _, obj := range output {
			fmt.Println(obj.Name, strings.Join(obj.Tags, ","))
		}
	}

}
