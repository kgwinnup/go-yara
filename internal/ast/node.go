package ast

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/kgwinnup/go-yara/internal/lexer"
)

const (
	RULE = iota
	PREFIX
	INFIX
	INTEGER
	STRING
	REGEX
	BOOL
	ASSIGNMENT
	IDENTITY
	VARIABLE
	KEYWORD
	BYTES
	IMPORT
	SET
	FOR
)

// IsPrimitive returns true if the node is a primitive value like an
// Integer, Float, String, Variable, or Bool
func IsPrimitive(node Node) bool {
	switch node.Type() {
	case INTEGER, STRING, BOOL, VARIABLE:
		return true
	default:
		return false
	}
}

// IsModuleCall returns true if the expression node is a module call, e.g. pe.entry_point
func IsModuleCall(node Node) bool {
	if infix, ok := node.(*Infix); ok {
		if _, ok := infix.Left.(*Identity); !ok {
			return false
		}

		if _, ok := infix.Right.(*Identity); !ok {
			return false
		}

		if infix.Token.Type != lexer.DOT {
			return false
		}

		return true
	}

	return false
}

type Node interface {
	Type() int
	String() string
}

type For struct {
	Expr      *lexer.Token
	StringSet Node
	Var       string
	Body      Node
}

func (f For) String() string {
	if f.Var == "" {
		return fmt.Sprintf("for %v of %v : (%v)", f.Expr.Raw, f.StringSet, f.Body)
	}
	return fmt.Sprintf("for %v %v in %v : (%v)", f.Expr.Raw, f.Var, f.StringSet, f.Body)
}

func (f For) Type() int {
	return FOR
}

type Set struct {
	Nodes []Node
}

func (s Set) String() string {
	var builder strings.Builder

	builder.WriteRune('(')
	for i, node := range s.Nodes {
		builder.WriteString(node.String())
		if i < len(s.Nodes)-1 {
			builder.WriteRune(',')
		}
	}
	builder.WriteRune(')')

	return builder.String()
}

func (s *Set) Type() int {
	return SET
}

type Keyword struct {
	Token     *lexer.Token
	Value     string
	Attribute Node
}

func (k Keyword) String() string {
	if k.Attribute != nil {
		return fmt.Sprintf("%v(%v)", k.Value, k.Attribute)
	}

	return k.Value
}

func (k *Keyword) Type() int {
	return KEYWORD
}

type Bytes struct {
	Token *lexer.Token
	Items []string
}

func (b Bytes) String() string {
	var builder strings.Builder
	builder.WriteRune('{')
	builder.WriteRune(' ')

	for _, item := range b.Items {
		builder.WriteString(item)
		builder.WriteRune(' ')
	}

	builder.WriteRune('}')
	return builder.String()
}

func (b *Bytes) Type() int {
	return BYTES
}

func makeBytePatternInt(s string) (int, error) {

	if strings.Contains(s, "?") {
		return 0x1000, nil
	}

	if n, err := strconv.ParseInt(s, 16, 16); err != nil {
		return 0, err
	} else {
		return int(n), nil
	}
}

func (b *Bytes) BytePattern() ([][]int, error) {

	patterns := make([][]int, 0)
	patterns = append(patterns, []int{})

	for i := 0; i < len(b.Items); i++ {
		cur := b.Items[i]

		if cur == "[" {
			if i+3 >= len(b.Items) {
				return nil, errors.New("syntax error in byte pattern bracket")
			}

			first, err := strconv.ParseInt(b.Items[i+1], 10, 64)
			if err != nil {
				return nil, err
			}

			second, err := strconv.ParseInt(b.Items[i+3], 10, 64)
			if err != nil {
				return nil, err
			}

			if first > second {
				return nil, errors.New("invalid range in byte pattern")
			}

			opts := second - first + 1

			// clone patterns len(opts) times
			newpatterns := make([][]int, 0)

			for i := 0; i < int(opts); i++ {
				for _, pattern := range patterns {
					dst := make([]int, len(pattern))
					copy(dst, pattern)

					for j := 0; j < i+1; j++ {
						dst = append(dst, 0x1000)
					}

					newpatterns = append(newpatterns, dst)
				}
			}

			patterns = newpatterns

			i += 4
			continue
		}

		if cur == "(" {
			parts := make([][]int, 0)
			temp := make([]int, 0)

			for j := i + 1; j < len(b.Items); j++ {

				if b.Items[j] == ")" {
					i = j
					break
				}

				if b.Items[j] == "|" {
					parts = append(parts, temp)
					temp = make([]int, 0)
					continue
				}

				n, err := makeBytePatternInt(b.Items[j])
				if err != nil {
					return nil, err
				}

				temp = append(temp, n)
			}

			parts = append(parts, temp)

			// clone patterns len(parts) times
			newpatterns := make([][]int, 0)
			for _, part := range parts {
				for _, pattern := range patterns {
					dst := make([]int, len(pattern))
					copy(dst, pattern)

					dst = append(dst, part...)
					newpatterns = append(newpatterns, dst)
				}
			}

			patterns = newpatterns
			continue
		}

		for k := 0; k < len(patterns); k++ {
			n, err := makeBytePatternInt(cur)
			if err != nil {
				return nil, err
			}

			patterns[k] = append(patterns[k], n)
		}
	}

	return patterns, nil
}

type Identity struct {
	Token *lexer.Token
	Value string
}

func (i Identity) String() string {
	return i.Value
}

func (i *Identity) Type() int {
	return IDENTITY
}

type Variable struct {
	Token *lexer.Token
	Value string
}

func (v Variable) String() string {
	return v.Value
}

func (v *Variable) Type() int {
	return VARIABLE
}

type Rule struct {
	Private   bool
	Global    bool
	Name      string
	Tags      []string
	Condition Node
	Strings   []Node
	Meta      []Node
}

func (r Rule) String() string {
	var builder strings.Builder

	if r.Private {
		builder.WriteString("private rule ")
	} else if r.Global {
		builder.WriteString("global rule ")
	} else {
		builder.WriteString("rule ")
	}

	builder.WriteString(r.Name)
	builder.WriteRune(' ')

	if len(r.Tags) > 0 {
		builder.WriteString(" :")

		for _, tag := range r.Tags {
			builder.WriteRune(' ')
			builder.WriteString(tag)
		}
	}

	builder.WriteRune('{')
	builder.WriteRune('\n')

	if len(r.Meta) > 0 {
		builder.WriteString("    meta:\n")
		for _, node := range r.Meta {
			builder.WriteString("        ")
			builder.WriteString(node.String())
			builder.WriteRune('\n')

		}
		builder.WriteRune('\n')
	}

	if len(r.Strings) > 0 {
		builder.WriteString("    strings:\n")
		for _, node := range r.Strings {
			builder.WriteString("        ")
			builder.WriteString(node.String())
			builder.WriteRune('\n')
		}
		builder.WriteRune('\n')
	}

	builder.WriteString("    condition:\n")
	builder.WriteString("        ")
	builder.WriteString(r.Condition.String())

	builder.WriteRune('\n')
	builder.WriteRune('}')
	builder.WriteRune('\n')
	return builder.String()
}

func (r *Rule) Type() int {
	return RULE
}

type Prefix struct {
	Token *lexer.Token
	Right Node
}

func (p Prefix) String() string {
	if p.Token.Type == lexer.LPAREN {
		return fmt.Sprintf("(%v)", p.Right)
	}

	if p.Token.Type == lexer.LBRACKET {
		return fmt.Sprintf("[%v]", p.Right)
	}

	return fmt.Sprintf("%v%v", p.Token.Raw, p.Right)
}

func (p *Prefix) Type() int {
	return PREFIX
}

type Infix struct {
	Token *lexer.Token
	Left  Node
	Right Node
}

func (i Infix) String() string {

	if i.Token.Type == lexer.LBRACKET {
		return fmt.Sprintf("%v[%v]", i.Left, i.Right)
	}

	return fmt.Sprintf("%v %v %v", i.Left, i.Token.Raw, i.Right)
}

func (i *Infix) Type() int {
	return INFIX
}

type String struct {
	Token *lexer.Token
	Value string
}

func (s String) String() string {
	return fmt.Sprintf("\"%v\"", s.Value)
}

func (s *String) Type() int {
	return STRING
}

type Bool struct {
	Token *lexer.Token
	Value bool
}

func (b Bool) String() string {
	return fmt.Sprintf("%v", b.Value)
}

func (b *Bool) Type() int {
	return BOOL
}

type Integer struct {
	Token *lexer.Token
	Value int64
}

func (i Integer) String() string {
	return fmt.Sprintf("%v", i.Token.Raw)
}

func (i *Integer) Type() int {
	return INTEGER
}

type Import struct {
	Token *lexer.Token
	Value string
}

func (i Import) String() string {
	return fmt.Sprintf("import \"%v\"", i.Value)
}

func (i *Import) Type() int {
	return IMPORT
}

type Assignment struct {
	Left       string
	Right      Node
	Attributes map[int]Node
}

func (a Assignment) String() string {
	attrs := ""
	for _, attr := range a.Attributes {
		attrs += fmt.Sprintf("%v ", attr)
	}

	return fmt.Sprintf("%v = %v %v", a.Left, a.Right, attrs)
}

func (a *Assignment) Type() int {
	return ASSIGNMENT
}

type BytePattern struct {
	Patterns        [][]byte
	Offsets         []int
	Nocase          bool
	IsPartial       bool
	PartialPatterns [][]int
	Re              *regexp.Regexp
}

type Regex struct {
	Token *lexer.Token
	Value string
}

func (r Regex) String() string {
	return fmt.Sprintf("/%v/", r.Value)
}

func (r *Regex) Type() int {
	return REGEX
}

func (r *Regex) BytePattern() ([]byte, error) {
	re, err := regexp.Compile(r.Value)
	if err != nil {
		return nil, err
	}

	min := 6

	prefix, _ := re.LiteralPrefix()
	if len(prefix) < min {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("warning %v:%v: slow regex, regex prefix should be greater than %v, '%v'\n", r.Token.Row, r.Token.Col, min, prefix))
	}

	if len(prefix) == 0 {
		return nil, errors.New(fmt.Sprintf("error %v:%v: bad regex pattern, no valid prefix to match on", r.Token.Row, r.Token.Col))
	}

	return []byte(prefix), nil
}

// BytePattern returns a byte slice which represents the pattern to
// search for, an offset for use if the pattern is partial and located
// somewhere in the full pattern, a bool to say if this is case
// insensitive or not, and an error.
func (a *Assignment) BytePattern() (*BytePattern, error) {

	ret := &BytePattern{
		Patterns:        make([][]byte, 0),
		Offsets:         make([]int, 0),
		Nocase:          false,
		IsPartial:       false,
		PartialPatterns: make([][]int, 0),
	}

	if str, ok := a.Right.(*String); ok {

		if _, ok := a.Attributes[lexer.NOCASE]; ok {
			ret.Nocase = true
		}

		if _, ok := a.Attributes[lexer.ASCII]; ok {
			if _, ok := a.Attributes[lexer.BASE64]; ok {
				encoded := base64.StdEncoding.EncodeToString([]byte(str.Value))
				ret.Patterns = append(ret.Patterns, []byte(encoded))
				return ret, nil
			} else {
				ret.Patterns = append(ret.Patterns, []byte(str.Value))
				return ret, nil
			}
		}

		if _, ok := a.Attributes[lexer.WIDE]; ok {
			uint16Slice := utf16.Encode([]rune(str.Value))
			byteSlice := make([]byte, 0, len(uint16Slice)*2)

			temp := make([]byte, 2)
			for _, u16 := range uint16Slice {
				binary.LittleEndian.PutUint16(temp, u16)
				byteSlice = append(byteSlice, temp...)
			}

			if _, ok := a.Attributes[lexer.BASE64]; ok {
				encoded := base64.StdEncoding.EncodeToString(byteSlice)
				ret.Patterns = append(ret.Patterns, []byte(encoded))
				return ret, nil
			} else {
				ret.Patterns = append(ret.Patterns, byteSlice)
				return ret, nil
			}
		}

		// default is ascii/utf8
		ret.Patterns = append(ret.Patterns, []byte(str.Value))
		return ret, nil
	}

	if r, ok := a.Right.(*Regex); ok {
		pattern, err := r.BytePattern()
		if err != nil {
			return nil, err
		}

		ret.Patterns = append(ret.Patterns, pattern)
		return ret, nil
	}

	if bs, ok := a.Right.(*Bytes); ok {
		patterns, err := bs.BytePattern()
		if err != nil {
			return nil, err
		}

		bytePatterns := make([][]byte, 0)

		for _, pattern := range patterns {
			temp := make([]byte, 0)

			for _, b := range pattern {
				if b&0x1000 == 0x1000 {
					ret.IsPartial = true
					break
				}

				temp = append(temp, byte(b))
			}

			bytePatterns = append(bytePatterns, temp)
		}

		ret.PartialPatterns = patterns
		ret.Patterns = bytePatterns

		return ret, nil
	}

	if _, ok := a.Right.(*Regex); ok {
		return nil, errors.New("Regex patterns are not supported at this time")
	}

	return nil, errors.New("Unsupported pattern type")
}
