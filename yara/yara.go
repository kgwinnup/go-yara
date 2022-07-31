package yara

import "github.com/kgwinnup/go-yara/internal/exec"

type Yara struct {
	compiled *exec.CompiledRules
}

type Output struct {
	Name string
	Tags []string
}

func New(rule string) (*Yara, error) {
	compiled, err := exec.Compile(rule)
	if err != nil {
		return nil, err
	}

	return &Yara{compiled: compiled}, nil
}

func (y *Yara) Scan(input []byte) ([]*exec.ScanOutput, error) {
	output, err := y.compiled.Scan([]byte(input))
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (y *Yara) Debug() {
	y.compiled.Debug()
}
