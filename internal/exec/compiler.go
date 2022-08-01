package exec

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kgwinnup/go-yara/internal/ast"
	"github.com/kgwinnup/go-yara/internal/lexer"
	"github.com/kgwinnup/go-yara/internal/parser"
)

type CompiledRule struct {
	instr    []Op
	deps     []string
	finished bool
	tags     []string
	name     string
}

type ScanOutput struct {
	Name string
	Tags []string
}

type CompiledRules struct {
	rules []*CompiledRule
	// stores a Pattern object by its RuleName_Var key
	// this is used when evaluating the condition. Each pattern
	// contains information about the indexes within the input bytes
	mappings       map[string]Pattern
	automata       []*ACNode
	automataNocase []*ACNode

	// this is to hold variable names to register value. Hacky, i
	// know.
	tempVars map[string]int64
	tempVar  string
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

func (c *CompiledRules) Scan(input []byte) ([]*ScanOutput, error) {

	nodeId := 0
	nodeIdNocase := 0

	output := make([]*ScanOutput, 0)

	c.mappings["filesize"] = NewConstantPattern("filesize", len(input))

	for i, b := range input {
		// get the next node in the automata and return a list of
		// matches indexed the same as the patterns slice
		nodeId = ACNext(c.automata, nodeId, b, i)
		nodeIdNocase = ACNext(c.automataNocase, nodeIdNocase, toLower(b), i)
	}

	for _, rule := range c.rules {
		out, err := Eval(rule, c.mappings)
		if err != nil {
			return nil, err
		}

		if out > 0 {
			output = append(output, &ScanOutput{
				Name: rule.name,
				Tags: rule.tags,
			})

			// add this rule to the global state for other rules to
			// reference
			c.mappings[rule.name] = NewConstantPattern(rule.name, int(out))
		}
	}

	return output, nil
}

// Compile an input Yara rule(s) and create both the pattern objects
// that will be matched on, add the patterns to the aho-corasick
// automatons, and create the instructions to evaluate each rule
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

	compiled := &CompiledRules{
		rules:    make([]*CompiledRule, 0),
		mappings: make(map[string]Pattern),
		tempVars: make(map[string]int64),
	}

	patterns := make([]Pattern, 0)
	patternsNocase := make([]Pattern, 0)
	dups := make(map[string]Pattern)

	for _, rule := range rules {
		compiledRule := &CompiledRule{
			instr:    make([]Op, 0),
			deps:     make([]string, 0),
			finished: false,
			tags:     rule.Tags,
			name:     rule.Name,
		}

		// add string patterns to the ahocor pattern list
		for _, node := range rule.Strings {
			if assign, ok := node.(*ast.Assignment); ok {

				bytePattern, err := assign.BytePattern()
				if err != nil {
					return nil, err
				}

				hash := fmt.Sprintf("%x", sha256.Sum256([]byte(assign.Right.String())))

				if _, ok := assign.Right.(*ast.String); ok {
					if bytePattern.Nocase {
						for i := 0; i < len(bytePattern.Patterns[0]); i++ {
							bytePattern.Patterns[0][i] = toLower(bytePattern.Patterns[0][i])
						}
					}
					temp := NewStringPattern(assign.Left, rule.Name, bytePattern.Nocase, bytePattern.Patterns[0])

					// check if the pattern is identical to another existing pattern. If
					// so add a pointer with this patterns name to point to the existing
					// identical pattern. This prevents duplicate items being added to the
					// automaton.
					pattern, ok := dups[hash]
					if ok {
						compiled.mappings[temp.Name()] = pattern
					} else {
						dups[hash] = temp

						if bytePattern.Nocase {
							patternsNocase = append(patternsNocase, temp)
						} else {
							patterns = append(patterns, temp)
						}

						compiled.mappings[temp.Name()] = temp
					}

				} else {
					return nil, errors.New("compiler: invalid strings type")
				}

			}
		}

		compiled.rules = append(compiled.rules, compiledRule)

		instr := make([]Op, 0)
		err := compiled.compileNode(rule.Name, rule.Condition, &instr)
		if err != nil {
			return nil, err
		}

		compiledRule.instr = instr

	}

	// build the automta
	compiled.automata = ACBuild(patterns)
	compiled.automataNocase = ACBuild(patternsNocase)

	return compiled, nil
}

func toLower(b byte) byte {
	if b >= 0x41 && b <= 0x5a {
		return b | 0x20
	}

	return b
}

func (c *CompiledRules) patternsInRule(ruleName string) []string {
	patterns := make([]string, 0)

	for key := range c.mappings {
		if strings.HasPrefix(key, ruleName) {
			patterns = append(patterns, key)
		}
	}

	return patterns
}

func (c *CompiledRules) setToStringSlice(ruleName string, set *ast.Set) []string {

	out := make([]string, 0)

	for _, node := range set.Nodes {
		if v, ok := node.(*ast.Variable); ok {
			if strings.HasSuffix(v.Value, "*") {
				temp := strings.TrimSuffix(v.Value, "*")
				for _, name := range c.patternsInRule(ruleName) {
					if strings.HasPrefix(name, temp) {
						out = append(out, name)
					}
				}
			} else {
				out = append(out, fmt.Sprintf("%v_%v", ruleName, v.Value))
			}
		}
	}

	return out
}

// compileNode is the function responsible for building the
// instruction sequence for evaluation.
func (c *CompiledRules) compileNode(ruleName string, node ast.Node, accum *[]Op) error {

	push := func(op Op) {
		*accum = append(*accum, op)
	}

	if infix, ok := node.(*ast.Infix); ok {

		// some infix operations do not require pushing the left value
		// as a single instruction. Intercept here and process accordingly.
		switch infix.Token.Type {
		case lexer.IN:
			c.compileNode(ruleName, infix.Right, accum)
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				push(Op{OpCode: IN, VarParam: name})
			} else {
				return errors.New(fmt.Sprintf("invalid IN operation, left value must be a variable"))
			}

			return nil

		case lexer.OF:

			if keyword, ok := infix.Right.(*ast.Keyword); ok && keyword.Token.Type == lexer.THEM {
				names := c.patternsInRule(ruleName)
				for _, name := range names {
					push(Op{OpCode: LOADCOUNT, VarParam: name})
				}
			} else {
				c.compileNode(ruleName, infix.Right, accum)
			}

			if integer, ok := infix.Left.(*ast.Integer); ok {
				push(Op{OpCode: OF, IntParam: integer.Value})
			} else if keyword, ok := infix.Left.(*ast.Keyword); ok {
				switch keyword.Token.Type {
				case lexer.ALL:
					*accum = append(*accum, Op{OpCode: OF, IntParam: int64(len(c.patternsInRule(ruleName)))})
				case lexer.ANY:
					*accum = append(*accum, Op{OpCode: OF, IntParam: 1})
				case lexer.NONE:
					*accum = append(*accum, Op{OpCode: OF, IntParam: 0})
				default:
					return errors.New(fmt.Sprintf("invalid OF operation, left value must be a integer, 'all', or 'any'"))
				}
			} else {
				return errors.New(fmt.Sprintf("invalid OF operation, left value must be a integer"))
			}

			return nil

		case lexer.LBRACKET:
			if v, ok := infix.Left.(*ast.Variable); ok {
				c.compileNode(ruleName, infix.Right, accum)

				name := fmt.Sprintf("%v_%v", ruleName, strings.Replace(v.Value, "@", "$", 1))
				push(Op{OpCode: LOADOFFSET, VarParam: name})

				return nil

			} else {
				return errors.New(fmt.Sprintf("invalid index operation, left value must be a variable"))
			}

		}

		// recurse the left and right branches and push those instructions onto the sequence.
		c.compileNode(ruleName, infix.Left, accum)
		c.compileNode(ruleName, infix.Right, accum)

		// handle the infix operation now that the left and right values are processed.
		switch infix.Token.Type {
		case lexer.PLUS:
			push(Op{OpCode: ADD})
		case lexer.MINUS:
			push(Op{OpCode: MINUS})
		case lexer.AND:
			push(Op{OpCode: AND})
		case lexer.OR:
			push(Op{OpCode: OR})
		case lexer.GT:
			push(Op{OpCode: GT})
		case lexer.GTE:
			push(Op{OpCode: GTE})
		case lexer.LT:
			push(Op{OpCode: LT})
		case lexer.LTE:
			push(Op{OpCode: LTE})
		case lexer.EQUAL:
			push(Op{OpCode: EQUAL})
		case lexer.NOTEQUAL:
			push(Op{OpCode: NOTEQUAL})
		case lexer.RANGE:
			// NOP for now, the two values should be pushed on the stack
		case lexer.AT:
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				push(Op{OpCode: AT, VarParam: name})
			} else {
				return errors.New(fmt.Sprintf("invalid AT operation, left value must be a variable"))
			}

		default:
			return errors.New(fmt.Sprintf("invalid infix operation: %v", infix.Type()))
		}

		return nil
	}

	if set, ok := node.(*ast.Set); ok {
		for _, node := range set.Nodes {
			c.compileNode(ruleName, node, accum)
		}

		// finally push the number of nodes pushed onto the stack
		push(Op{OpCode: PUSH, IntParam: int64(len(set.Nodes))})
	}

	if prefix, ok := node.(*ast.Prefix); ok {
		c.compileNode(ruleName, prefix.Right, accum)

		switch prefix.Token.Type {
		case lexer.MINUS:
			push(Op{OpCode: MINUSU})
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

		// this needs to be expanded into a set of matching rule names
		if strings.HasSuffix(v.Value, "*") {
			prefix := fmt.Sprintf("%v_%v", ruleName, strings.TrimSuffix(v.Value, "*"))

			count := 0
			for _, name := range c.patternsInRule(ruleName) {
				if strings.HasPrefix(name, prefix) {
					count++
					push(Op{OpCode: LOADCOUNT, VarParam: name})
				}
			}

			// finally push the number of nodes pushed onto the stack
			push(Op{OpCode: PUSH, IntParam: int64(count)})

		} else if strings.HasPrefix(v.Value, "@") {
			if len(v.Value) > 1 {
				name := fmt.Sprintf("%v_%v", ruleName, strings.Replace(v.Value, "@", "$", 1))
				push(Op{OpCode: PUSH, IntParam: 0})
				push(Op{OpCode: LOADOFFSET, VarParam: name})
			} else {
				push(Op{OpCode: PUSH, IntParam: 0})
				push(Op{OpCode: LOADOFFSET, VarParam: c.tempVar})
			}
		} else {
			name := fmt.Sprintf("%v_%v", ruleName, v.Value)
			push(Op{OpCode: LOADCOUNT, VarParam: name})
		}
	}

	if keyword, ok := node.(*ast.Keyword); ok {
		switch keyword.Token.Type {
		case lexer.FILESIZE:
			push(Op{OpCode: LOADCOUNT, VarParam: keyword.Value})
		default:
			return errors.New(fmt.Sprintf("invalid keyword: %v", keyword.Value))
		}
	}

	if n, ok := node.(*ast.Integer); ok {
		push(Op{OpCode: PUSH, IntParam: n.Value})
	}

	if ident, ok := node.(*ast.Identity); ok {
		if n, ok := c.tempVars[ident.Value]; ok {
			push(Op{OpCode: PUSHR, IntParam: n})
		} else {
			return errors.New("invalid variable to create instruction")
		}
	}

	if loop, ok := node.(*ast.For); ok {
		push(Op{OpCode: CLEAR})

		var startAddress int64

		// for _ loop.Var in (X..Y) : _
		if infix, ok := loop.StringSet.(*ast.Infix); ok && infix.Token.Type == lexer.RANGE && loop.Var != "" {
			// set loop.Var
			c.compileNode(ruleName, infix.Left, accum)
			push(Op{OpCode: MOVR, IntParam: R1})

			// save a total size for the ALL matching posibility
			c.compileNode(ruleName, infix.Left, accum)
			push(Op{OpCode: MOVR, IntParam: R3})
			c.tempVars[loop.Var] = R1

			// get the accumulator counter, loop checks this register
			c.compileNode(ruleName, infix.Right, accum)
			c.compileNode(ruleName, infix.Left, accum)
			push(Op{OpCode: MINUS})
			push(Op{OpCode: MOVR, IntParam: RC})

			startAddress = int64(len(*accum))

			// do body
			c.compileNode(ruleName, loop.Body, accum)

			// handle the loop
			push(Op{OpCode: INCR, IntParam: R1})
			push(Op{OpCode: ADDR, IntParam: R2})
			push(Op{OpCode: LOOP, IntParam: startAddress})
			push(Op{OpCode: PUSHR, IntParam: R2})

		} else if set, ok := loop.StringSet.(*ast.Set); ok {
			names := c.setToStringSlice(ruleName, set)

			for _, name := range names {
				c.tempVar = name
				c.compileNode(ruleName, loop.Body, accum)
				push(Op{OpCode: ADDR, IntParam: R2})
			}
			push(Op{OpCode: PUSHR, IntParam: R2})

		} else if keyword, ok := loop.StringSet.(*ast.Keyword); ok && keyword.Token.Type == lexer.THEM {
			for name := range c.mappings {
				c.tempVar = name
				c.compileNode(ruleName, loop.Body, accum)
				push(Op{OpCode: ADDR, IntParam: R2})
			}
			push(Op{OpCode: PUSHR, IntParam: R2})

		} else {
			return errors.New("loop structure not implemented")
		}

		// now wrap up and finish the condition
		if loop.Expr.Type == lexer.INTEGER {
			if n, err := strconv.ParseInt(loop.Expr.Raw, 10, 64); err == nil {
				push(Op{OpCode: PUSH, IntParam: n})
				push(Op{OpCode: EQUAL})
			} else {
				return err
			}
		} else if loop.Expr.Type == lexer.ALL {
			push(Op{OpCode: PUSHR, IntParam: R3})
			push(Op{OpCode: EQUAL})
		} else if loop.Expr.Type == lexer.ANY {
			push(Op{OpCode: PUSH, IntParam: 1})
			push(Op{OpCode: GTE})
		} else {
			return errors.New(fmt.Sprintf("invalid loop expression: '%v'", loop.Expr))
		}

	}

	return nil
}
