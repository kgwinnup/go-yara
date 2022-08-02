package exec

import "fmt"

type Pattern interface {
	// Pattern returns the byte pattern to be used in the
	// automata. The bool return value is whether this pattern should
	// be treated as no case. This only works for ascii.
	Pattern() []byte

	// Rule returns the name of the rule this pattern is associated with.
	Rule() string

	// returns the name of the pattern, $s1 = "foobar", $s1 in this case
	Name() string
}

type ConstantPattern struct {
	name string
	size int
}

func NewConstantPattern(name string, size int) *ConstantPattern {
	return &ConstantPattern{
		name: name,
		size: size,
	}
}

func (c *ConstantPattern) Pattern() []byte {
	return []byte{}
}

func (c *ConstantPattern) Rule() string {
	return ""
}

func (c *ConstantPattern) Name() string {
	return ""
}

type StringPattern struct {
	name string
	// pattern to be used in the automta
	pattern []byte
	// what rule this pattern is tied to.
	rule   string
	nocase bool
}

func NewStringPattern(varName, ruleName string, nocase bool, pattern []byte) *StringPattern {
	return &StringPattern{
		name:    fmt.Sprintf("%v_%v", ruleName, varName),
		pattern: pattern,
		rule:    ruleName,
		nocase:  nocase,
	}
}

func (s *StringPattern) Pattern() []byte {
	return s.pattern
}

func (s *StringPattern) Rule() string {
	return s.rule
}

func (s *StringPattern) Name() string {
	return s.name
}
