package lexer

import (
	"strings"
	"testing"
)

func TestScanInteger(t *testing.T) {
	input := "1234"
	lexer := New(input)
	tok, err := lexer.Next()
	if err != nil {
		t.Fatal(err)
	}

	if tok.Raw != input {
		t.Fatal("invalid raw value")
	}

}

func TestScanHexNumber(t *testing.T) {
	input := "0x1234"
	lexer := New(input)
	tok, err := lexer.Next()
	if err != nil {
		t.Fatal(err)
	}

	if tok.Raw != input {
		t.Fatal("invalid raw value")
	}

}

func TestScanString(t *testing.T) {
	input := "\"hello world\""
	lexer := New(input)
	tok, err := lexer.Next()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(input, tok.Raw) {
		t.Fatal("must contain input")
	}
}

func TestScanComment(t *testing.T) {
	input := `/* foobar
foobaz
*/`
	lexer := New(input)
	tok, err := lexer.Next()
	if err != nil {
		t.Fatal(err)
	}

	if tok.Type != COMMENT {
		t.Fatal("expecting comment")
	}

}
