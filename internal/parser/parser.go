package parser

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/kgwinnup/go-yara/internal/ast"
	"github.com/kgwinnup/go-yara/internal/lexer"
)

type Parser struct {
	lexer *lexer.Lexer
	Nodes []ast.Node
}

func New(input string) (*Parser, error) {
	lexer := lexer.New(input)

	parser := &Parser{
		lexer: lexer,
		Nodes: make([]ast.Node, 0),
	}

	err := parser.parse()

	return parser, err
}

func test(input string) *Parser {
	lexer := lexer.New(input)

	return &Parser{
		lexer: lexer,
		Nodes: make([]ast.Node, 0),
	}

}

func (p *Parser) parse() error {
	p.Nodes = make([]ast.Node, 0)

	for p.lexer.HasNext() {

		tok, err := p.lexer.Peek()
		if err == io.EOF {
			break
		}

		switch tok.Type {
		case lexer.IMPORT:
			mod, err := p.parseImport()
			if err != nil {
				return err
			}
			p.Nodes = append(p.Nodes, mod)

		case lexer.PRIVATE, lexer.GLOBAL, lexer.RULE:
			rule, err := p.parseRule()

			if err != nil {
				return err
			}

			p.Nodes = append(p.Nodes, rule)
		}

	}

	return nil
}

func (p *Parser) parseImport() (ast.Node, error) {
	tok, _ := p.lexer.Next()

	value, err := p.expectRead(lexer.STRING, "expecting string value for import")
	if err != nil {
		return nil, err
	}

	return &ast.Import{
		Token: tok,
		Value: value.Raw,
	}, nil
}

func (p *Parser) parseRule() (ast.Node, error) {

	p.whitespace()

	tok, err := p.lexer.Peek()
	if err != nil {
		return nil, err
	}

	rule := &ast.Rule{}

	if tok.Type == lexer.PRIVATE {
		rule.Private = true
		p.lexer.Next()
	} else if tok.Type == lexer.GLOBAL {
		rule.Global = true
		p.lexer.Next()
	}

	_, err = p.expectRead(lexer.RULE, "expecting rule token")
	if err != nil {
		return nil, err
	}

	name, err := p.expectRead(lexer.IDENTITY, "expecting a rule name")
	if err != nil {
		return nil, err
	}
	rule.Name = name.Raw

	tok, err = p.lexer.Peek()
	if err != nil {
		return nil, err
	}

	if tok.Type == lexer.LBRACE {
		p.lexer.Next()
	} else if tok.Type == lexer.COLON {
		tags, err := p.parseTags()
		if err != nil {
			return nil, err
		}

		rule.Tags = tags
	}

	for {
		tok, err = p.lexer.Peek()
		if err != nil {
			return nil, err
		}

		if tok.Type == lexer.META {
			p.lexer.Next()
			_, err := p.expectRead(lexer.COLON, "expecting colon, e.g. 'meta:'")
			if err != nil {
				return nil, err
			}

			nodes, err := p.parseBody()
			if err != nil {
				return nil, err
			}

			rule.Meta = nodes
		} else if tok.Type == lexer.STRINGS {
			p.lexer.Next()
			_, err := p.expectRead(lexer.COLON, "expecting colon, e.g. 'strings:'")
			if err != nil {
				return nil, err
			}

			nodes, err := p.parseBody()
			if err != nil {
				return nil, err
			}

			rule.Strings = nodes

		} else if tok.Type == lexer.CONDITION {
			p.lexer.Next()

			_, err := p.expectRead(lexer.COLON, "expecting colon, e.g. 'condition:'")
			if err != nil {
				return nil, err
			}

			node, err := p.parseExpr(0)
			if err != nil {
				return nil, err
			}

			rule.Condition = node
		} else {
			break
		}
	}

	_, err = p.expectRead(lexer.RBRACE, "expecting closing brace for rule")
	if err != nil {
		return nil, err
	}

	return rule, nil
}

func (p *Parser) parseBody() ([]ast.Node, error) {

	nodes := make([]ast.Node, 0)

	for {

		assignment := &ast.Assignment{}
		assignment.Attributes = make(map[int]ast.Node, 0)

		tok, err := p.lexer.Peek()
		if err != nil {
			return nil, err
		}

		if tok.Type == lexer.CONDITION || tok.Type == lexer.STRINGS || tok.Type == lexer.META || tok.Type == lexer.RBRACE {
			break
		}

		name, err := p.lexer.Next()
		if err != nil {
			return nil, err
		}
		assignment.Left = name.Raw

		if name.Type != lexer.IDENTITY && name.Type != lexer.VARIABLE {
			return nil, errors.New("assignment must be an identity or variable")
		}

		_, err = p.expectRead(lexer.ASSIGNMENT, "expecting equals char for assignment")
		if err != nil {
			return nil, err
		}

		right, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}
		assignment.Right = right

		for {
			tok, err := p.lexer.Peek()
			if err != nil {
				return nil, err
			}

			if tok.Type == lexer.WIDE ||
				tok.Type == lexer.ASCII ||
				tok.Type == lexer.XOR ||
				tok.Type == lexer.NOCASE ||
				tok.Type == lexer.BASE64 ||
				tok.Type == lexer.BASE64WIDE {

				node, err := p.parseExpr(0)
				if err != nil {
					return nil, err
				}

				assignment.Attributes[tok.Type] = node
				continue
			}

			break
		}

		nodes = append(nodes, assignment)
	}

	return nodes, nil
}

func (p *Parser) parseTags() ([]string, error) {
	tags := make([]string, 0)

	_, err := p.expectRead(lexer.COLON, "expecting a colon")
	if err != nil {
		return nil, err
	}

	for {
		tok, err := p.lexer.Peek()
		if err != nil {
			return nil, err
		}

		if tok.Type == lexer.LBRACE {
			p.lexer.Next()
			break
		}

		tag, err := p.expectRead(lexer.IDENTITY, "invalid tag")
		if err != nil {
			return nil, err
		}

		tags = append(tags, tag.Raw)
	}

	return tags, nil
}

func (p *Parser) whitespace() {
	for {
		if tok, _ := p.lexer.Peek(); tok != nil && tok.Type == lexer.NEWLINE {
			p.lexer.Next()
			continue
		}

		break
	}
}

var prefixPower = map[int][]int{
	lexer.LPAREN:   {0, 0},
	lexer.LBRACKET: {0, 0},
	lexer.PLUS:     {0, 24},
	lexer.MINUS:    {0, 24},
}

var infixPower = map[int][]int{
	lexer.OR:          {1, 2},
	lexer.AND:         {3, 4},
	lexer.COMMA:       {5, 6},
	lexer.MATCHES:     {7, 8},
	lexer.IEQUALS:     {7, 8},
	lexer.IENDSWITH:   {7, 8},
	lexer.ENDSWITH:    {7, 8},
	lexer.ISTARTSWITH: {7, 8},
	lexer.STARTSWITH:  {7, 8},
	lexer.ICONTAINS:   {7, 8},
	lexer.CONTAINS:    {7, 8},
	lexer.NOTEQUAL:    {7, 8},
	lexer.EQUAL:       {7, 8},
	lexer.IN:          {7, 8},
	lexer.AT:          {7, 8},
	lexer.OF:          {7, 8},
	lexer.GTE:         {9, 10},
	lexer.GT:          {9, 10},
	lexer.LTE:         {9, 10},
	lexer.LT:          {9, 10},
	lexer.PIPE:        {11, 12},
	lexer.CARET:       {13, 14},
	lexer.AMPERSAND:   {15, 16},
	lexer.SHIFTLEFT:   {17, 18},
	lexer.SHIFTRIGHT:  {17, 18},
	lexer.MINUS:       {19, 20},
	lexer.PLUS:        {19, 20},
	lexer.MOD:         {21, 22},
	lexer.DIVIDE:      {21, 22},
	lexer.ASTERISK:    {21, 22},
	lexer.TILDE:       {23, 24},
	lexer.DOT:         {25, 26},
	lexer.RANGE:       {25, 26},
	lexer.LBRACKET:    {25, 26},
}

func (p *Parser) makeSet(node ast.Node) ast.Node {

	temp := node
	ret := make([]ast.Node, 0)

	for {
		if infix, ok := temp.(*ast.Infix); ok && infix.Token.Type == lexer.COMMA {
			ret = append(ret, infix.Right)
			temp = infix.Left
			continue
		}

		ret = append(ret, temp)
		break
	}

	return &ast.Set{Nodes: ret}
}

func (p *Parser) parseFor() (ast.Node, error) {
	_, err := p.expectRead(lexer.FOR, "expecting a for keyword")
	if err != nil {
		return nil, err
	}

	expr, err := p.lexer.Next()
	if err != nil {
		return nil, err
	}

	switch expr.Type {
	case lexer.INTEGER, lexer.ANY, lexer.ALL:
	default:
		return nil, errors.New(fmt.Sprintf("for expression expects 'any' or 'all' keywords, got '%v'", expr))
	}

	tok, _ := p.lexer.Peek()

	if tok.Type == lexer.IDENTITY {
		_var, _ := p.lexer.Next()
		if _var.Type != lexer.IDENTITY {
			return nil, errors.New("expecting an identity")
		}

		_, _ = p.lexer.Next()

		set, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}

		if prefix, ok := set.(*ast.Prefix); ok {
			set = prefix.Right
		}

		_, err = p.expectRead(lexer.COLON, "expecting colon")
		if err != nil {
			return nil, err
		}

		_, err = p.expectRead(lexer.LPAREN, "expecting left paren")
		if err != nil {
			return nil, err
		}

		body, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}

		_, err = p.expectRead(lexer.RPAREN, "expecting right paren")
		if err != nil {
			return nil, err
		}

		return &ast.For{
			Expr:      expr,
			Var:       _var.Raw,
			StringSet: set,
			Body:      body,
		}, nil

	} else if tok.Type == lexer.IN || tok.Type == lexer.OF {
		_, _ = p.lexer.Next()
		set, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}

		_, err = p.expectRead(lexer.COLON, "expecting colon")
		if err != nil {
			return nil, err
		}

		_, err = p.expectRead(lexer.LPAREN, "expecting left paren")
		if err != nil {
			return nil, err
		}

		body, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}

		_, err = p.expectRead(lexer.RPAREN, "expecting right paren")
		if err != nil {
			return nil, err
		}

		return &ast.For{
			Expr:      expr,
			Var:       "",
			StringSet: set,
			Body:      body,
		}, nil
	} else {
		return nil, errors.New(fmt.Sprintf("for expression expects 'of' or 'in' keywords or an identity like 'i', got '%v'", expr))
	}

}

func (p *Parser) parseExpr(power int) (ast.Node, error) {

	p.whitespace()

	tok, err := p.lexer.Peek()
	if err != nil {
		return nil, err
	}

	var left ast.Node

	if powers, ok := prefixPower[tok.Type]; ok {
		op, _ := p.lexer.Next()

		expr, err := p.parseExpr(powers[1])
		if err != nil {
			return nil, err
		}

		if op.Type == lexer.LPAREN {
			_, err := p.expectRead(lexer.RPAREN, "expecting closing paren")
			if err != nil {
				return nil, err
			}

		}

		if op.Type == lexer.LBRACKET {
			_, err := p.expectRead(lexer.RBRACKET, "expecting closing bracket")
			if err != nil {
				return nil, err
			}
		}

		if op.Type == lexer.LPAREN {
			// check if this is a set definition ($a,$b,$c)
			if infix, ok := expr.(*ast.Infix); ok && infix.Token.Type == lexer.COMMA {
				left = p.makeSet(infix)
			} else {
				left = &ast.Prefix{
					Token: op,
					Right: expr,
				}
			}
		} else {
			left = &ast.Prefix{
				Token: op,
				Right: expr,
			}
		}

	} else {

		switch tok.Type {
		case lexer.INTEGER:
			tok, _ := p.lexer.Next()

			if strings.HasPrefix(tok.Raw, "0x") {
				n2, err := strconv.ParseInt(tok.Raw[2:], 16, 64)
				if err != nil {
					return nil, err
				}

				left = &ast.Integer{
					Token: tok,
					Value: n2,
				}

			} else {
				n2, err := strconv.ParseInt(tok.Raw, 10, 64)
				if err != nil {
					return nil, err
				}

				left = &ast.Integer{
					Token: tok,
					Value: n2,
				}
			}

		case lexer.FOR:
			node, err := p.parseFor()
			if err != nil {
				return nil, err
			}

			left = node

		case lexer.FILESIZE, lexer.WIDE, lexer.NOCASE, lexer.ASCII, lexer.THEM, lexer.NONE, lexer.ALL, lexer.ANY:
			tok, _ := p.lexer.Next()
			left = &ast.Keyword{
				Token: tok,
				Value: tok.Raw,
			}

		case lexer.XOR, lexer.BASE64, lexer.BASE64WIDE:
			kw, _ := p.lexer.Next()

			tok, _ = p.lexer.Peek()
			if tok.Type == lexer.LPAREN {
				p.lexer.Next()

				node, err := p.parseExpr(0)
				if err != nil {
					return nil, err
				}

				left = &ast.Keyword{
					Token:     kw,
					Value:     kw.Raw,
					Attribute: node,
				}

				_, err = p.expectRead(lexer.RPAREN, "missing right paren in keyword attribute")
				if err != nil {
					return nil, err
				}
			} else {
				left = &ast.Keyword{
					Token: kw,
					Value: kw.Raw,
				}
			}

		case lexer.STRING:
			tok, _ := p.lexer.Next()
			left = &ast.String{
				Token: tok,
				Value: tok.Raw,
			}

		case lexer.REGEX:
			tok, _ := p.lexer.Next()
			left = &ast.Regex{
				Token: tok,
				Value: tok.Raw,
			}

		case lexer.BOOL:
			tok, _ := p.lexer.Next()
			val := false
			if strings.ToLower(tok.Raw) == "true" {
				val = true
			}

			left = &ast.Bool{
				Token: tok,
				Value: val,
			}

		case lexer.VARIABLE:
			tok, _ := p.lexer.Next()
			tok2, _ := p.lexer.Peek()

			if tok2.Type == lexer.ASTERISK {
				p.lexer.Next()

				left = &ast.Variable{
					Token: tok,
					Value: tok.Raw + "*",
				}

			} else {

				left = &ast.Variable{
					Token: tok,
					Value: tok.Raw,
				}
			}

		case lexer.IDENTITY:
			tok, _ := p.lexer.Next()
			left = &ast.Identity{
				Token: tok,
				Value: tok.Raw,
			}

		case lexer.LBRACE:
			return p.parseBytes()

		default:
			return nil, errors.New(fmt.Sprintf("invalid expression at: '%v'", tok.Raw))
		}
	}

	if integer, ok := left.(*ast.Integer); ok {
		tok, _ := p.lexer.Peek()
		if tok.Type == lexer.KB {
			p.lexer.Next()
			integer.Value = integer.Value * 1024
		} else if tok.Type == lexer.MB {
			p.lexer.Next()
			integer.Value = integer.Value * (2 ^ 20)
		}
	}

	for {
		tok, _ := p.lexer.Peek()
		if tok == nil {
			break
		}

		powers, ok := infixPower[tok.Type]
		if !ok {
			break
		}

		if powers[0] < power {
			break
		}

		op, _ := p.lexer.Next()

		right, err := p.parseExpr(powers[1])
		if err != nil {
			return nil, err
		}

		left = &ast.Infix{
			Token: op,
			Left:  left,
			Right: right,
		}

		tok, _ = p.lexer.Peek()
		if tok != nil && op.Type == lexer.LBRACKET && tok.Type == lexer.RBRACKET {
			p.lexer.Next()
		}
	}

	return left, nil

}

func (p *Parser) parseBytes() (ast.Node, error) {
	tok, err := p.expectRead(lexer.LBRACE, "expecting open brace for byte definition")
	if err != nil {
		return nil, err
	}

	bytes := make([]string, 0)

	stack := make([]int, 0)

	for {
		tok, _ := p.lexer.Peek()

		if tok.Type == lexer.EOF {
			return nil, errors.New("EOF reached while parsing bytes")
		}

		if tok.Type == lexer.RBRACE {
			break
		}

		tok, err := p.lexer.Next()
		if err != nil {
			return nil, err
		}

		switch tok.Type {
		case lexer.LPAREN, lexer.LBRACKET:
			stack = append([]int{tok.Type}, stack...)

		case lexer.RPAREN:
			if stack[0] == lexer.LPAREN {
				stack = stack[1:]
				bytes = append(bytes, tok.Raw)
			} else {
				return nil, errors.New("invalid byte value")
			}

		case lexer.RBRACKET:
			if stack[0] == lexer.LBRACKET {
				stack = stack[1:]
				bytes = append(bytes, tok.Raw)
			} else {
				return nil, errors.New("invalid byte value")
			}

		default:
			bytes = append(bytes, tok.Raw)
		}
	}

	if len(stack) != 0 {
		return nil, errors.New("imbalanced parens or brackets in byte definition")
	}

	_, err = p.expectRead(lexer.RBRACE, "expecting closing brace for byte definition")
	if err != nil {
		return nil, err
	}

	return &ast.Bytes{Token: tok, Items: bytes}, nil
}

func (p *Parser) expectRead(tokenType int, errorMsg string) (*lexer.Token, error) {
	tok, err := p.lexer.Next()
	if err != nil {
		return nil, err
	}

	if tok.Type != tokenType {
		return nil, errors.New(errorMsg)
	}

	return tok, nil

}
