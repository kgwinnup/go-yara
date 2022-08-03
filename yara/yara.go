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

func (y *Yara) Scan(input []byte, timeout int, s bool) ([]*exec.ScanOutput, error) {
	if timeout <= 0 {
		timeout = 3
	}

	output, err := y.compiled.Scan([]byte(input), s, timeout)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (y *Yara) Debug() {
	y.compiled.Debug()
}
