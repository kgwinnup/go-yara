package parser

import (
	"testing"

	"github.com/kgwinnup/go-yara/internal/ast"
	"github.com/kgwinnup/go-yara/internal/lexer"
)

func TestParseRuleTags(t *testing.T) {
	input := `rule Foobar : foo bar {

}`
	parser, err := New(input)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := parser.Nodes[0].(*ast.Rule)
	if !ok {
		t.Fatal("expecting rule")
	}
}

func TestParseRuleBody(t *testing.T) {
	input := `rule Test
{
    meta:
        hello = "world"
        foobar = 10

    strings:
        $a = "some string"
        $b = "foobaz" wide ascii xor(0x01-0x3)

    condition:
        $a and ($b or $a) and #a == 10 and #a in filesize
}`
	parser, err := New(input)
	if err != nil {
		t.Fatal(err)
	}

	rule, ok := parser.Nodes[0].(*ast.Rule)
	if !ok {
		t.Fatal("expecting rule")
	}

	if len(rule.Strings) != 2 {
		t.Fatal("expecting two 'strings:'")
	}

	assign, ok := rule.Strings[0].(*ast.Assignment)
	if !ok {
		t.Fatal("expecting assignment node")
	}

	if assign.Left != "$a" {
		t.Fatal("expecting $a")
	}

	if assign.Right.Type() != ast.STRING {
		t.Fatal("expecting rvalue to be a string")
	}

	if right, ok := assign.Right.(*ast.String); !ok || right.Value != "some string" {
		t.Fatal("invalid string in rvalue")
	}
}

func TestParseExpr1(t *testing.T) {
	input := "all of them"
	parser := test(input)
	node, err := parser.parseExpr(0)

	if err != nil {
		t.Fatal("error parsing all of them")
	}

	infix, ok := node.(*ast.Infix)
	if !ok {
		t.Fatal("expecting infix expression")
	}

	left, ok := infix.Left.(*ast.Keyword)
	if !ok {
		t.Fatal("expecting all as keyword")
	}

	if left.Token.Type != lexer.ALL {
		t.Fatal("invalid all token")
	}

	right, ok := infix.Right.(*ast.Keyword)
	if !ok {
		t.Fatal("expecting them as keyword")
	}

	if right.Token.Type != lexer.THEM {
		t.Fatal("invalid all token")
	}

}

func TestParseBytes2(t *testing.T) {
	input := `rule AlternativesExample1
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

    condition:
        $hex_string
}`

	parser, err := New(input)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := parser.Nodes[0].(*ast.Rule)
	if !ok {
		t.Fatal("expecting rule")
	}

}

func TestParseBytes(t *testing.T) {
	input := `rule Foobar {
    strings:
        $b = { ff ee 10 ?? ?a [1-10] }

    condition:
        $b

}`
	parser, err := New(input)
	if err != nil {
		t.Fatal(err)
	}

	rule, ok := parser.Nodes[0].(*ast.Rule)
	if !ok {
		t.Fatal("expecting rule")
	}

	assign, ok := rule.Strings[0].(*ast.Assignment)
	if !ok {
		t.Fatal("expecting assignment")
	}

	bytes, ok := assign.Right.(*ast.Bytes)
	if !ok {
		t.Fatal("expecting bytes")
	}

	if len(bytes.Items) != 9 {
		t.Fatalf("expecting 6 byte nodes, got %v", len(bytes.Items))
	}
}

func TestParseSet(t *testing.T) {
	input := "($a, $b, $c)"

	parser := test(input)
	node, _ := parser.parseExpr(0)

	set, ok := node.(*ast.Set)
	if !ok {
		t.Fatalf("expecting a set, got %v", node.Type())
	}

	if len(set.Nodes) != 3 {
		t.Fatalf("expecting a set of 3, got %v", len(set.Nodes))
	}
}
