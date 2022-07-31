package ast

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
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

type Keyword struct {
	Token     *lexer.Token
	Value     string
	Attribute Node
}

func (k *Keyword) String() string {
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

func (b *Bytes) String() string {
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

type Identity struct {
	Token *lexer.Token
	Value string
}

func (i *Identity) String() string {
	return i.Value
}

func (i *Identity) Type() int {
	return IDENTITY
}

type Variable struct {
	Token *lexer.Token
	Value string
}

func (v *Variable) String() string {
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

func (r *Rule) String() string {
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

func (p *Prefix) String() string {
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

func (i *Infix) String() string {

	if i.Token.Type == lexer.LBRACKET {
		return fmt.Sprintf("%v[%v]", i.Left, i.Right)
	}

	return fmt.Sprintf("%v %v %v", i.Left, i.Token.Raw, i.Right)
}

func (i *Infix) Type() int {
	return INFIX
}

type BytePattern struct {
	Token *lexer.Token
}

type String struct {
	Token *lexer.Token
	Value string
}

func (s *String) String() string {
	return fmt.Sprintf("\"%v\"", s.Value)
}

func (s *String) Type() int {
	return STRING
}

type Regex struct {
	Token *lexer.Token
	Value string
}

func (r *Regex) String() string {
	return fmt.Sprintf("/%v/", r.Value)
}

func (r *Regex) Type() int {
	return REGEX
}

type Bool struct {
	Token *lexer.Token
	Value bool
}

func (b *Bool) String() string {
	return fmt.Sprintf("%v", b.Value)
}

func (b *Bool) Type() int {
	return BOOL
}

type Integer struct {
	Token *lexer.Token
	Value int64
}

func (i *Integer) String() string {
	return fmt.Sprintf("%v", i.Token.Raw)
}

func (i *Integer) Type() int {
	return INTEGER
}

type Import struct {
	Token *lexer.Token
	Value string
}

func (i *Import) String() string {
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

func (a *Assignment) String() string {
	attrs := ""
	for _, attr := range a.Attributes {
		attrs += fmt.Sprintf("%v ", attr)
	}

	return fmt.Sprintf("%v = %v %v", a.Left, a.Right, attrs)
}

func (a *Assignment) Type() int {
	return ASSIGNMENT
}

func (a *Assignment) BytePattern() ([][]byte, bool, error) {

	ret := make([][]byte, 0)
	nocase := false

	if str, ok := a.Right.(*String); ok {

		if _, ok := a.Attributes[lexer.NOCASE]; ok {
			nocase = true
		}

		if _, ok := a.Attributes[lexer.ASCII]; ok {
			if _, ok := a.Attributes[lexer.BASE64]; ok {
				encoded := base64.StdEncoding.EncodeToString([]byte(str.Value))
				ret = append(ret, []byte(encoded))
			} else {
				ret = append(ret, []byte(str.Value))
			}
		} else if _, ok := a.Attributes[lexer.WIDE]; ok {
			uint16Slice := utf16.Encode([]rune(str.Value))
			byteSlice := make([]byte, 0, len(uint16Slice)*2)

			temp := make([]byte, 2)
			for _, u16 := range uint16Slice {
				binary.LittleEndian.PutUint16(temp, u16)
				byteSlice = append(byteSlice, temp...)
			}

			if _, ok := a.Attributes[lexer.BASE64]; ok {
				encoded := base64.StdEncoding.EncodeToString(byteSlice)
				ret = append(ret, []byte(encoded))
			} else {
				ret = append(ret, byteSlice)
			}
		} else {
			// default is ascii/utf8
			ret = append(ret, []byte(str.Value))
		}
	}

	if _, ok := a.Right.(*Bytes); ok {
		return nil, false, errors.New("byte patterns are not supported at this time")
	}

	if _, ok := a.Right.(*Regex); ok {
		return nil, false, errors.New("Regex patterns are not supported at this time")
	}

	return ret, nocase, nil
}
