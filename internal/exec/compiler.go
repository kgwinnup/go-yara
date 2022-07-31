package exec

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/kgwinnup/go-yara/internal/ast"
	"github.com/kgwinnup/go-yara/internal/lexer"
	"github.com/kgwinnup/go-yara/internal/parser"
)

type Rule struct {
	instr    []Op
	deps     []string
	finished bool
	result   int
	tags     []string
	name     string
}

type CompiledRules struct {
	rules map[string]*Rule
	// stores a Pattern object by its RuleName_Var key
	// this is used when evaluating the condition. Each pattern
	// contains information about the indexes within the input bytes
	mappings       map[string]Pattern
	automata       []*Node
	automataNocase []*Node
}

func (c *CompiledRules) Debug() {
	fmt.Println("instructions stack")
	for _, rule := range c.rules {
		fmt.Printf("    rule %v\n", rule.name)
		size := len(rule.instr)
		for i := size - 1; i >= 0; i-- {
			fmt.Printf("        %v: %v\n", i, rule.instr[i])
		}
	}

	fmt.Println("patterns")
	for _, pattern := range c.mappings {
		bs := pattern.Pattern()
		bs2 := ""
		for _, b := range bs {
			bs2 += fmt.Sprintf("%x ", b)
		}
		fmt.Printf("    %v = %v\n", pattern.Name(), bs2)
	}
}

type ScanOutput struct {
	Name string
	Tags []string
}

func (c *CompiledRules) Scan(input []byte) ([]*ScanOutput, error) {

	nodeId := 0
	nodeIdNocase := 0

	output := make([]*ScanOutput, 0)

	c.mappings["filesize"] = &ConstantPattern{
		name: "filesize",
		size: len(input),
	}

	for i, b := range input {
		// get the next node in the automata and return a list of
		// matches indexed the same as the patterns slice
		nodeId = next(c.automata, nodeId, b, i)
		nodeIdNocase = next(c.automataNocase, nodeIdNocase, toLower(b), i)
	}

	for name, rule := range c.rules {
		out, err := eval(rule, c.mappings)
		if err != nil {
			return nil, err
		}

		if out > 0 {
			output = append(output, &ScanOutput{
				Name: name,
				Tags: rule.tags,
			})
		}
	}

	return output, nil
}

// Compile an input Yara rule(s) and create the machine to scan input files
func Compile(input string) (*CompiledRules, error) {
	parser, err := parser.New(input)
	if err != nil {
		return nil, err
	}

	rules := make([]*ast.Rule, 0)

	for _, node := range parser.Nodes {
		if rule, ok := node.(*ast.Rule); ok {
			rules = append(rules, rule)
		}
	}

	compiled, err := compile(rules)
	if err != nil {
		return nil, err
	}

	return compiled, nil

}

func toLower(b byte) byte {
	if b >= 0x41 && b <= 0x5a {
		return b | 0x20
	}

	return b
}

// compile is the internal compile function for iterating over all the
// parsed rules and creating the automaton and other structures
func compile(rules []*ast.Rule) (*CompiledRules, error) {

	compiled := &CompiledRules{
		rules:    make(map[string]*Rule),
		mappings: make(map[string]Pattern),
	}

	patterns := make([]Pattern, 0)
	patternsNocase := make([]Pattern, 0)
	dups := make(map[string]Pattern)

	for _, rule := range rules {
		compiledRule := &Rule{
			instr:    make([]Op, 0),
			deps:     make([]string, 0),
			finished: false,
			result:   0,
			tags:     rule.Tags,
			name:     rule.Name,
		}

		// add string patterns to the ahocor pattern list
		for _, node := range rule.Strings {
			if assign, ok := node.(*ast.Assignment); ok {

				patternSlice, nocase, err := assign.BytePattern()
				if err != nil {
					return nil, err
				}

				for _, p := range patternSlice {
					hash := fmt.Sprintf("%x", sha256.Sum256([]byte(assign.Right.String())))

					temp := &StringPattern{
						name:    fmt.Sprintf("%v_%v", rule.Name, assign.Left),
						nocase:  nocase,
						pattern: p,
						rule:    rule.Name,
					}

					// check if the pattern is identical to another existing pattern. If
					// so add a pointer with this patterns name to point to the existing
					// identical pattern. This prevents duplicate items being added to the
					// automaton.
					pattern, ok := dups[hash]
					if ok {
						compiled.mappings[temp.name] = pattern
					} else {
						dups[hash] = temp

						if temp.nocase {
							for i := 0; i < len(temp.pattern); i++ {
								temp.pattern[i] = toLower(temp.pattern[i])
							}

							patternsNocase = append(patternsNocase, temp)
						} else {
							patterns = append(patterns, temp)
						}

						compiled.mappings[temp.name] = temp
					}
				}
			}
		}

		compiled.rules[rule.Name] = compiledRule

		instr := make([]Op, 0)
		err := compileCondition(rule.Name, rule.Condition, &instr)
		if err != nil {
			return nil, err
		}

		compiledRule.instr = instr

	}

	// build the automta
	compiled.automata = build(patterns)
	compiled.automataNocase = build(patternsNocase)

	return compiled, nil
}

func compileCondition(ruleName string, node ast.Node, accum *[]Op) error {

	if infix, ok := node.(*ast.Infix); ok {

		// some infix operations do not require pushing the variable as a single instruction
		switch infix.Token.Type {
		case lexer.IN:
			compileCondition(ruleName, infix.Right, accum)
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				*accum = append(*accum, Op{OpCode: IN, VarParam: name})
			} else {
				return errors.New(fmt.Sprintf("invalid IN operation, left value must be a variable"))
			}

			return nil
		}

		compileCondition(ruleName, infix.Left, accum)
		compileCondition(ruleName, infix.Right, accum)

		switch infix.Token.Type {
		case lexer.PLUS:
			*accum = append(*accum, Op{OpCode: ADD})
		case lexer.MINUS:
			*accum = append(*accum, Op{OpCode: MINUS})
		case lexer.AND:
			*accum = append(*accum, Op{OpCode: AND})
		case lexer.OR:
			*accum = append(*accum, Op{OpCode: OR})
		case lexer.GT:
			*accum = append(*accum, Op{OpCode: GT})
		case lexer.GTE:
			*accum = append(*accum, Op{OpCode: GTE})
		case lexer.LT:
			*accum = append(*accum, Op{OpCode: LT})
		case lexer.LTE:
			*accum = append(*accum, Op{OpCode: LTE})
		case lexer.EQUAL:
			*accum = append(*accum, Op{OpCode: EQUAL})
		case lexer.NOTEQUAL:
			*accum = append(*accum, Op{OpCode: NOTEQUAL})
		case lexer.RANGE:
			// NOP for now, the two values should be pushed on the stack
		case lexer.AT:
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				*accum = append(*accum, Op{OpCode: AT, VarParam: name})
			} else {
				return errors.New(fmt.Sprintf("invalid AT operation, left value must be a variable"))
			}

		default:
			return errors.New(fmt.Sprintf("invalid infix operation: %v", infix.Type()))
		}

		return nil
	}

	if prefix, ok := node.(*ast.Prefix); ok {
		compileCondition(ruleName, prefix.Right, accum)

		switch prefix.Token.Type {
		case lexer.MINUS:
			*accum = append(*accum, Op{OpCode: MINUSU})
		default:
			return errors.New(fmt.Sprintf("invalid prefix operation: %v", prefix.Type()))
		}
	}

	if v, ok := node.(*ast.Variable); ok {
		// counts are the default value pushed onto the instruction
		// stack. Replace the # sign so the variable can be looked up
		// in the mappings correctly
		if strings.HasPrefix(v.Value, "#") {
			v.Value = strings.Replace(v.Value, "#", "$", 1)
		}

		name := fmt.Sprintf("%v_%v", ruleName, v.Value)
		*accum = append(*accum, []Op{{OpCode: LOAD, VarParam: name}}...)
	}

	if keyword, ok := node.(*ast.Keyword); ok {
		switch keyword.Token.Type {
		case lexer.FILESIZE:
			*accum = append(*accum, []Op{{OpCode: LOAD, VarParam: keyword.Value}}...)
		default:
			return errors.New(fmt.Sprintf("invalid keyword: %v", keyword.Value))
		}
	}

	if n, ok := node.(*ast.Integer); ok {
		*accum = append(*accum, []Op{{OpCode: PUSH, IntParam: n.Value}}...)
	}

	return nil
}
