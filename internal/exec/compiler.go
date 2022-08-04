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

type Pattern struct {
	Name string
	// pattern to be used in the automta
	Pattern []byte
	// what rule this pattern is tied to.
	MatchIndex int
	// if Pattern is not the complete string, full match is the
	// complete string with 0x10000 as place holders for bytes with ??
	FullMatch []int
	IsPartial bool
}

type CompiledRule struct {
	instr []Op
	tags  []string
	name  string
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
	mappings            map[string]*Pattern
	automata            []*ACNode
	automataNocase      []*ACNode
	automataCount       int
	automataNocaseCount int
	patternCount        int
	// this is to hold variable names to register value. Hacky, i
	// know.
	tempVars map[string]int64
	tempVar  int64
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
		bs := pattern.Pattern
		bs2 := ""
		for _, b := range bs {
			bs2 += fmt.Sprintf("%x ", b)
		}
		fmt.Printf("    %v: %v = %v\n", pattern.MatchIndex, pattern.Name, bs2)
	}
}

func (c *CompiledRules) Scan(input []byte, s bool, timeout int) ([]*ScanOutput, error) {

	output := make([]*ScanOutput, 0)
	matches := make([]*[]int, c.patternCount)

	static := make([]int64, 0)
	static = append(static, int64(len(input)))

	// get the next node in the automata and return a list of
	// matches indexed the same as the patterns slice
	if c.automataCount > 0 {
		ACNext(matches, c.automata, input)
	}

	if c.automataNocaseCount > 0 {
		ACNextNocase(matches, c.automataNocase, input)
	}

	for _, rule := range c.rules {
		out, err := Eval(rule, matches, static)
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
			//static[rule.name] = int64(out)
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

	// get all the rule nodes
	for _, node := range parser.Nodes {
		if rule, ok := node.(*ast.Rule); ok {
			rules = append(rules, rule)
		}
	}

	compiled := &CompiledRules{
		rules:    make([]*CompiledRule, 0),
		mappings: make(map[string]*Pattern),
		tempVars: make(map[string]int64),
	}

	patterns := make([]*Pattern, 0)
	patternsNocase := make([]*Pattern, 0)
	dups := make(map[string]*Pattern)

	// index where each pattern will be in the match structure when
	// evaluated
	index := 0

	for _, rule := range rules {
		compiledRule := &CompiledRule{
			instr: make([]Op, 0),
			tags:  rule.Tags,
			name:  rule.Name,
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
							bytePattern.Patterns[0][i] = ToLower(bytePattern.Patterns[0][i])
						}
					}

					temp := &Pattern{
						Name:       fmt.Sprintf("%v_%v", rule.Name, assign.Left),
						Pattern:    bytePattern.Patterns[0],
						MatchIndex: index,
					}
					index++

					// check if the pattern is identical to another existing pattern. If
					// so add a pointer with this patterns name to point to the existing
					// identical pattern. This prevents duplicate items being added to the
					// automaton.
					pattern, ok := dups[hash]
					if ok {
						compiled.mappings[temp.Name] = pattern
					} else {
						dups[hash] = temp

						if bytePattern.Nocase {
							patternsNocase = append(patternsNocase, temp)
						} else {
							patterns = append(patterns, temp)
						}

						compiled.mappings[temp.Name] = temp
					}

				} else if _, ok := assign.Right.(*ast.Bytes); ok {

					mainPattern := &Pattern{
						Name:       fmt.Sprintf("%v_%v", rule.Name, assign.Left),
						Pattern:    bytePattern.Patterns[0],
						MatchIndex: index,
						IsPartial:  len(bytePattern.Patterns[0]) == len(bytePattern.PartialPatterns[0]),
						FullMatch:  bytePattern.PartialPatterns[0],
					}
					patterns = append(patterns, mainPattern)
					compiled.mappings[mainPattern.Name] = mainPattern

					index++

					for i, pattern := range bytePattern.Patterns {
						if i == 0 {
							continue
						}

						temp := &Pattern{
							Name:       fmt.Sprintf("%v_%v_%v", rule.Name, assign.Left, i),
							Pattern:    pattern,
							MatchIndex: mainPattern.MatchIndex,
							IsPartial:  len(bytePattern.Patterns[0]) == len(bytePattern.PartialPatterns[0]),
							FullMatch:  bytePattern.PartialPatterns[0],
						}

						patterns = append(patterns, temp)
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
	if len(patterns) > 0 {
		compiled.automata = ACBuild(patterns)
		compiled.automataCount = len(patterns)
	}

	if len(patternsNocase) > 0 {
		compiled.automataNocase = ACBuild(patternsNocase)
		compiled.automataNocaseCount = len(patternsNocase)
	}

	compiled.patternCount = index

	return compiled, nil
}

func ToLower(b byte) byte {
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
// in general, I am unhappy with this function, super messy, but the
// operation are simple and the code isn't that long so...
func (c *CompiledRules) compileNode(ruleName string, node ast.Node, instructions *[]Op) error {

	push := func(op int) {
		*instructions = append(*instructions, Op{OpCode: op})
	}
	push1 := func(op int, param int64) {
		*instructions = append(*instructions, Op{OpCode: op, IntParam: param})
	}

	if infix, ok := node.(*ast.Infix); ok {

		// some infix operations do not require pushing the left value
		// as a single instruction. Intercept here and process accordingly.
		switch infix.Token.Type {
		case lexer.IN:
			c.compileNode(ruleName, infix.Right, instructions)
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				push1(IN, int64(c.mappings[name].MatchIndex))
			} else {
				return errors.New(fmt.Sprintf("compiler: invalid IN operation, left value must be a variable"))
			}

			return nil

		case lexer.OF:
			if keyword, ok := infix.Right.(*ast.Keyword); ok && keyword.Token.Type == lexer.THEM {
				names := c.patternsInRule(ruleName)
				for _, name := range names {
					push1(LOADCOUNT, int64(c.mappings[name].MatchIndex))
				}
			} else {
				c.compileNode(ruleName, infix.Right, instructions)
			}

			if integer, ok := infix.Left.(*ast.Integer); ok {
				push1(OF, integer.Value)
			} else if keyword, ok := infix.Left.(*ast.Keyword); ok {
				switch keyword.Token.Type {
				case lexer.ALL:
					push1(OF, int64(len(c.patternsInRule(ruleName))))
				case lexer.ANY:
					push1(OF, 1)
				case lexer.NONE:
					push1(OF, 0)
				default:
					return errors.New(fmt.Sprintf("compiler: invalid OF operation, left value must be a integer, 'all', or 'any'"))
				}
			} else {
				return errors.New(fmt.Sprintf("compiler: invalid OF operation, left value must be a integer"))
			}

			return nil

		case lexer.LBRACKET:
			if v, ok := infix.Left.(*ast.Variable); ok {
				c.compileNode(ruleName, infix.Right, instructions)

				name := fmt.Sprintf("%v_%v", ruleName, strings.Replace(v.Value, "@", "$", 1))
				push1(LOADOFFSET, int64(c.mappings[name].MatchIndex))

				return nil

			} else {
				return errors.New(fmt.Sprintf("compiler: invalid index operation, left value must be a variable"))
			}

		}

		// recurse the left and right branches and push those instructions onto the sequence.
		c.compileNode(ruleName, infix.Left, instructions)
		c.compileNode(ruleName, infix.Right, instructions)

		// handle the infix operation now that the left and right values are processed.
		switch infix.Token.Type {
		case lexer.PLUS:
			push(ADD)
		case lexer.MINUS:
			push(MINUS)
		case lexer.AND:
			push(AND)
		case lexer.OR:
			push(OR)
		case lexer.GT:
			push(GT)
		case lexer.GTE:
			push(GTE)
		case lexer.LT:
			push(LT)
		case lexer.LTE:
			push(LTE)
		case lexer.EQUAL:
			push(EQUAL)
		case lexer.NOTEQUAL:
			push(NOTEQUAL)
		case lexer.RANGE:
			// NOP for now, the two values should be pushed on the stack
		case lexer.AT:
			if variable, ok := infix.Left.(*ast.Variable); ok {
				name := fmt.Sprintf("%v_%v", ruleName, variable.Value)
				push1(AT, int64(c.mappings[name].MatchIndex))
			} else {
				return errors.New(fmt.Sprintf("compiler: invalid AT operation, left value must be a variable"))
			}

		default:
			return errors.New(fmt.Sprintf("compiler: invalid infix operation: %v", infix.Type()))
		}

		return nil
	}

	if set, ok := node.(*ast.Set); ok {
		for _, node := range set.Nodes {
			c.compileNode(ruleName, node, instructions)
		}

		// finally push the number of nodes pushed onto the stack
		push1(PUSH, int64(len(set.Nodes)))
	}

	if prefix, ok := node.(*ast.Prefix); ok {
		c.compileNode(ruleName, prefix.Right, instructions)

		switch prefix.Token.Type {
		case lexer.MINUS:
			push(MINUSU)
		default:
			return errors.New(fmt.Sprintf("compiler: invalid prefix operation: %v", prefix.Type()))
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
					push1(LOADCOUNT, int64(c.mappings[name].MatchIndex))
				}
			}

			// finally push the number of nodes pushed onto the stack
			push1(PUSH, int64(count))

		} else if strings.HasPrefix(v.Value, "@") {
			if len(v.Value) > 1 {
				name := fmt.Sprintf("%v_%v", ruleName, strings.Replace(v.Value, "@", "$", 1))
				push1(PUSH, 0)
				push1(LOADOFFSET, int64(c.mappings[name].MatchIndex))
			} else {
				push1(PUSH, 0)
				push1(LOADOFFSET, c.tempVar)
			}
		} else {
			if len(v.Value) > 1 {
				name := fmt.Sprintf("%v_%v", ruleName, v.Value)
				push1(LOADCOUNT, int64(c.mappings[name].MatchIndex))
			} else {
				push1(PUSH, 0)
				push1(LOADCOUNT, c.tempVar)
			}
		}

		return nil
	}

	if keyword, ok := node.(*ast.Keyword); ok {
		switch keyword.Token.Type {
		case lexer.FILESIZE:
			push1(LOADSTATIC, 0)
		default:
			return errors.New(fmt.Sprintf("compiler: invalid keyword: %v", keyword.Value))
		}
	}

	if n, ok := node.(*ast.Integer); ok {
		push1(PUSH, n.Value)
		return nil
	}

	if ident, ok := node.(*ast.Identity); ok {
		if n, ok := c.tempVars[ident.Value]; ok {
			push1(PUSHR, n)
		} else {
			return errors.New("compiler: invalid variable to create instruction")
		}
	}

	if loop, ok := node.(*ast.For); ok {
		push(CLEAR)

		// for _ loop.Var in (X..Y) : _
		if infix, ok := loop.StringSet.(*ast.Infix); ok && infix.Token.Type == lexer.RANGE && loop.Var != "" {
			// set loop.Var
			c.compileNode(ruleName, infix.Left, instructions)
			push1(MOVR, REG1)

			// save a total size for the ALL matching posibility
			c.compileNode(ruleName, infix.Left, instructions)
			push1(MOVR, REG3)
			c.tempVars[loop.Var] = REG1

			// get the accumulator counter, loop checks this register
			c.compileNode(ruleName, infix.Right, instructions)
			c.compileNode(ruleName, infix.Left, instructions)
			push(MINUS)
			push1(MOVR, RC)

			startAddress := int64(len(*instructions))

			// do body
			c.compileNode(ruleName, loop.Body, instructions)

			// handle the loop
			push1(INCR, REG1)
			push1(ADDR, REG2)
			push1(LOOP, startAddress)
			push1(PUSHR, REG2)

		} else if set, ok := loop.StringSet.(*ast.Set); ok {
			names := c.setToStringSlice(ruleName, set)

			push1(PUSH, int64(len(names)))
			push1(MOVR, REG3)

			for _, name := range names {
				c.tempVar = int64(c.mappings[name].MatchIndex)
				c.compileNode(ruleName, loop.Body, instructions)
				push1(ADDR, REG2)
			}

			push1(PUSHR, REG2)

		} else if keyword, ok := loop.StringSet.(*ast.Keyword); ok && keyword.Token.Type == lexer.THEM {

			push1(PUSH, int64(len(c.patternsInRule(ruleName))))
			push1(MOVR, REG3)

			for _, name := range c.patternsInRule(ruleName) {

				c.tempVar = int64(c.mappings[name].MatchIndex)
				c.compileNode(ruleName, loop.Body, instructions)
				push1(ADDR, REG2)
			}

			push1(PUSHR, REG2)

		} else {
			return errors.New("compiler: loop structure not implemented")
		}

		// now wrap up and finish the condition
		if loop.Expr.Type == lexer.INTEGER {
			if n, err := strconv.ParseInt(loop.Expr.Raw, 10, 64); err == nil {
				push1(PUSH, n)
				push(EQUAL)
			} else {
				return err
			}
		} else if loop.Expr.Type == lexer.ALL {
			push1(PUSHR, REG3)
			push(EQUAL)
		} else if loop.Expr.Type == lexer.ANY {
			push1(PUSH, 1)
			push(GTE)
		} else {
			return errors.New(fmt.Sprintf("compiler: invalid loop expression: '%v'", loop.Expr))
		}

		return nil
	}

	return errors.New(fmt.Sprintf("compiler: unable to compile: '%v'", node))
}
