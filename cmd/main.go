package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/kgwinnup/go-yara/yara"
)

func main() {

	debug := flag.Bool("debug", false, "debug rules")
	showString := flag.Bool("s", false, "show string matches and offsets")
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

	yara, err := yara.New(rule)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if *debug {
		yara.Debug()
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

		output, err := yara.Scan(contents, 3, *showString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		for _, obj := range output {
			fmt.Println("Rule:", obj.Name, strings.Join(obj.Tags, ","))
		}
	}

}
