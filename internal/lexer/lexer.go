package lexer

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	EOF = iota
	NEWLINE
	COMMENT
	LPAREN
	RPAREN
	LBRACE
	RBRACE
	LBRACKET
	RBRACKET
	DOT
	RANGE
	PLUS
	MINUS
	DIVIDE
	ASTERISK
	MOD
	CARET
	TILDE
	SHIFTLEFT
	SHIFTRIGHT
	AMPERSAND
	PIPE
	LT
	LTE
	GT
	GTE
	EQUAL
	NOTEQUAL
	CONTAINS
	ICONTAINS
	STARTSWITH
	ISTARTSWITH
	ENDSWITH
	IENDSWITH
	IEQUALS
	MATCHES
	NOTDEFINED
	AND
	OR
	COMMA
	COLON
	ASSIGNMENT
	INTEGER
	IDENTITY
	VARIABLE
	STRING
	REGEX
	BOOL
	NOCASE
	WIDE
	ASCII
	XOR
	BASE64
	BASE64WIDE
	FULLWORD
	PRIVATE
	ALL
	ANY
	AT
	CONDITION
	GLOBAL
	STRINGS
	INT16
	INT16BE
	INT32
	INT32BE
	INT8
	INT8BE
	UINT16
	UINT16BE
	UINT32
	UINT32BE
	UINT8
	UINT8BE
	META
	NONE
	OF
	RULE
	THEM
	ENTRYPOINT
	FILESIZE
	FOR
	IMPORT
	INCLUDE
	IN
	NOT
	DEFINED
	KB
	MB
)

var keywords = map[string]int{
	"true":        BOOL,
	"false":       BOOL,
	"contains":    CONTAINS,
	"icontains":   ICONTAINS,
	"startswith":  STARTSWITH,
	"istartswith": ISTARTSWITH,
	"endswith":    ENDSWITH,
	"iendswith":   IENDSWITH,
	"iequals":     IEQUALS,
	"matches":     MATCHES,
	"and":         AND,
	"or":          OR,
	"not":         NOT,
	"all":         ALL,
	"any":         ANY,
	"ascii":       ASCII,
	"nocase":      NOCASE,
	"at":          AT,
	"base64":      BASE64,
	"base64wide":  BASE64WIDE,
	"entrypoint":  ENTRYPOINT,
	"filesize":    FILESIZE,
	"for":         FOR,
	"fullword":    FULLWORD,
	"import":      IMPORT,
	"in":          IN,
	"include":     INCLUDE,
	"int8":        INT8,
	"int8be":      INT8BE,
	"uint8":       UINT8,
	"uint8be":     UINT8BE,
	"int16":       INT16,
	"int16be":     INT16BE,
	"uint16":      UINT16,
	"uint16be":    UINT16BE,
	"int32":       INT32,
	"int32be":     INT32BE,
	"uint32":      UINT32,
	"uint32be":    UINT32BE,
	"rule":        RULE,
	"of":          OF,
	"private":     PRIVATE,
	"them":        THEM,
	"xor":         XOR,
	"wide":        WIDE,
	"defined":     DEFINED,
	"strings":     STRINGS,
	"condition":   CONDITION,
	"meta":        META,
	"KB":          KB,
	"MB":          MB,
}

type Token struct {
	Raw  string
	Type int
	Row  int
	Col  int
}

type Lexer struct {
	input []rune
	index int
	cur   *Token
	err   error
	row   int
	col   int
}

func New(input string) *Lexer {

	scanner := &Lexer{
		input: []rune(input),
		index: 0,
		row:   1,
		cur:   nil,
	}

	// populate the initial cur/err nodes for peek to work from parser
	scanner.cur, scanner.err = scanner.next()
	return scanner
}

func (s *Lexer) scanAll() ([]*Token, error) {
	toks := make([]*Token, 0)

	for s.HasNext() {
		tok, err := s.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		toks = append(toks, tok)
	}

	return toks, nil
}

func (s *Lexer) HasNext() bool {
	return s.err != io.EOF
}

func (s *Lexer) Next() (*Token, error) {
	tok := s.cur
	err := s.err

	s.cur, s.err = s.next()
	return tok, err
}

func (s *Lexer) Peek() (*Token, error) {
	return s.cur, s.err
}

func (s *Lexer) read() (rune, error) {
	if s.index < len(s.input) {
		temp := s.input[s.index]

		if temp == '\n' {
			s.row++
			s.col = 0
		} else {
			s.col++
		}

		s.index++
		return temp, nil
	}

	return '\000', io.EOF
}

func (s *Lexer) peek() rune {
	if s.index < len(s.input) {
		return s.input[s.index]
	}

	return '\000'
}

func (s *Lexer) next() (*Token, error) {

	for {
		tok := s.peek()

		if !unicode.IsSpace(tok) {
			break
		}

		_, err := s.read()
		if err != nil {
			return nil, err
		}
	}

	if s.index >= len(s.input) {
		return nil, io.EOF
	}

	switch s.input[s.index] {
	case '/':
		s.read()

		if s.peek() == '/' {
			s.read()
			var builder strings.Builder

			for {
				if s.peek() == '\n' {
					s.read()
					break
				}

				if s.peek() == '\000' {
					break
				}

				r, _ := s.read()
				builder.WriteRune(r)
			}

			return &Token{Raw: builder.String(), Type: COMMENT, Row: s.row, Col: s.col}, nil
		}

		if s.peek() == '*' {
			s.read()
			return s.readComment()
		}

		return s.readRegex()

	case '\\':
		return &Token{Raw: "\\", Type: DIVIDE, Row: s.row, Col: s.col}, nil

	case ',':
		s.read()
		return &Token{Raw: ",", Type: COMMA, Row: s.row, Col: s.col}, nil

	case ':':
		s.read()
		return &Token{Raw: ":", Type: COLON, Row: s.row, Col: s.col}, nil

	case '(':
		s.read()
		return &Token{Raw: "(", Type: LPAREN, Row: s.row, Col: s.col}, nil

	case ')':
		s.read()
		return &Token{Raw: ")", Type: RPAREN, Row: s.row, Col: s.col}, nil

	case '{':
		s.read()
		return &Token{Raw: "{", Type: LBRACE, Row: s.row, Col: s.col}, nil

	case '}':
		s.read()
		return &Token{Raw: "}", Type: RBRACE, Row: s.row, Col: s.col}, nil

	case '[':
		s.read()
		return &Token{Raw: "[", Type: LBRACKET, Row: s.row, Col: s.col}, nil

	case ']':
		s.read()
		return &Token{Raw: "]", Type: RBRACKET, Row: s.row, Col: s.col}, nil

	case '+':
		s.read()
		return &Token{Raw: "+", Type: PLUS, Row: s.row, Col: s.col}, nil

	case '-':
		s.read()
		return &Token{Raw: "-", Type: MINUS, Row: s.row, Col: s.col}, nil

	case '*':
		s.read()
		return &Token{Raw: "*", Type: ASTERISK, Row: s.row, Col: s.col}, nil

	case '%':
		s.read()
		return &Token{Raw: "%", Type: MOD, Row: s.row, Col: s.col}, nil

	case '.':
		s.read()
		if s.peek() == '.' {
			s.read()
			return &Token{Raw: "..", Type: RANGE, Row: s.row, Col: s.col}, nil
		}
		return &Token{Raw: ".", Type: DOT, Row: s.row, Col: s.col}, nil

	case '|':
		s.read()
		return &Token{Raw: "|", Type: PIPE, Row: s.row, Col: s.col}, nil

	case '&':
		s.read()
		return &Token{Raw: "&", Type: AMPERSAND, Row: s.row, Col: s.col}, nil

	case '>':
		s.read()

		if s.peek() == '>' {
			s.read()
			return &Token{Raw: ">>", Type: SHIFTRIGHT, Row: s.row, Col: s.col}, nil

		}

		if s.peek() == '=' {
			s.read()
			return &Token{Raw: ">=", Type: GTE, Row: s.row, Col: s.col}, nil

		}

		return &Token{Raw: ">", Type: GT, Row: s.row, Col: s.col}, nil

	case '<':
		s.read()

		if s.peek() == '<' {
			s.read()
			return &Token{Raw: "<<", Type: SHIFTLEFT, Row: s.row, Col: s.col}, nil

		}

		if s.peek() == '=' {
			s.read()
			return &Token{Raw: "<=", Type: LTE, Row: s.row, Col: s.col}, nil

		}

		return &Token{Raw: "<", Type: LT, Row: s.row, Col: s.col}, nil

	case '^':
		s.read()
		return &Token{Raw: "^", Type: CARET, Row: s.row, Col: s.col}, nil

	case '!':
		s.read()

		if s.peek() == '=' {
			s.read()
			return &Token{Raw: "!=", Type: NOTEQUAL, Row: s.row, Col: s.col}, nil
		}

		return nil, s.readError(s.row, s.col, "invalid character")

	case '=':
		s.read()

		if s.peek() == '=' {
			s.read()
			return &Token{Raw: "==", Type: EQUAL, Row: s.row, Col: s.col}, nil

		}

		return &Token{Raw: "=", Type: ASSIGNMENT, Row: s.row, Col: s.col}, nil
	case '"':
		return s.readString()

	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return s.readNumber()

	case '$', '#', '?', '@':
		r, _ := s.read()
		ident, err := s.readIdentity()
		if err != nil {
			return nil, err
		}

		if r == '$' {
			return &Token{Raw: "$" + ident.Raw, Type: VARIABLE, Row: s.row, Col: s.col}, nil
		}

		if r == '#' {
			return &Token{Raw: "#" + ident.Raw, Type: VARIABLE, Row: s.row, Col: s.col}, nil
		}

		if r == '@' {
			return &Token{Raw: "@" + ident.Raw, Type: VARIABLE, Row: s.row, Col: s.col}, nil
		}

		return &Token{Raw: "?" + ident.Raw, Type: IDENTITY, Row: s.row, Col: s.col}, nil

	default:

		tok := s.peek()
		if tok != '?' && tok != '_' && !unicode.IsLetter(tok) {
			return nil, s.readError(s.row, s.col, fmt.Sprintf("invalid character '%v'", tok))
		}

		ident, err := s.readIdentity()
		if err != nil {
			return nil, err
		}

		if typ, ok := keywords[ident.Raw]; ok {
			return &Token{Raw: ident.Raw, Type: typ, Row: ident.Row, Col: ident.Col}, nil
		}

		return ident, nil
	}
}

func (s *Lexer) readIdentity() (*Token, error) {
	var builder strings.Builder
	row := s.row
	col := s.col

	tok := s.peek()

	if unicode.IsLetter(tok) {
		r, err := s.read()
		if err != nil {
			return nil, err
		}

		builder.WriteRune(r)
	}

	for {
		tok := s.peek()

		if unicode.IsLetter(tok) || unicode.IsDigit(tok) || tok == '_' || tok == '?' {
			r, err := s.read()
			if err != nil {
				return nil, err
			}

			builder.WriteRune(r)
			continue
		}

		break
	}

	return &Token{
		Raw:  builder.String(),
		Type: IDENTITY,
		Row:  row,
		Col:  col,
	}, nil
}

func (s *Lexer) readComment() (*Token, error) {
	var builder strings.Builder
	row := s.row
	col := s.col

	for {
		r := s.peek()

		if r == '\000' {
			return nil, s.readError(row, col, "EOF file reached while scanning comment")
		}

		if r == '*' {
			s.read()

			if s.peek() == '/' {
				s.read()
				break
			} else {
				builder.WriteRune(r)
			}
		} else {
			r1, _ := s.read()
			builder.WriteRune(r1)
		}

	}

	return &Token{Raw: builder.String(), Type: COMMENT, Row: row, Col: col}, nil
}

func isHexDigit(r rune) bool {
	switch r {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	case 'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F':
		return true
	default:
		return false
	}
}

func (s *Lexer) readNumber() (*Token, error) {
	var builder strings.Builder
	row := s.row
	col := s.col
	isHex := false

	if s.peek() == '0' {
		r, err := s.read()
		if err != nil {
			return nil, err
		}

		builder.WriteRune(r)

		if s.peek() == 'x' || s.peek() == 'X' {
			r, err := s.read()
			if err != nil {
				return nil, err
			}

			builder.WriteRune(r)

			isHex = true
		}
	}

	for {
		tok := s.peek()

		if isHex && !isHexDigit(tok) {
			break
		}

		if !unicode.IsDigit(tok) {
			break
		}

		r, err := s.read()
		if err != nil {
			return nil, err
		}

		builder.WriteRune(r)
	}

	typ := INTEGER

	if isHex && builder.Len() == 2 {
		return nil, s.readError(row, col, "invalid hex integer, must contain at least 1 number after 0x")
	}

	return &Token{
		Raw:  builder.String(),
		Type: typ,
		Row:  row,
		Col:  col,
	}, nil
}

func (s *Lexer) readRegex() (*Token, error) {
	var builder strings.Builder
	row := s.row
	col := s.col

	for {
		tok := s.peek()

		if tok == '\000' {
			return nil, s.readError(row, col, "non-terminated string")
		}

		// check if the slash is escaped
		if tok == '\\' {
			s.read()

			tok = s.peek()
			if tok == '/' {
				s.read()
				builder.WriteByte('\\')
				builder.WriteByte('/')
				continue
			}

			builder.WriteByte('\\')
			continue
		}

		if tok == '/' {
			s.read()
			break
		}

		r, err := s.read()
		if err != nil {
			return nil, err
		}

		builder.WriteRune(r)
	}

	return &Token{
		Raw:  builder.String(),
		Type: REGEX,
		Row:  row,
		Col:  col,
	}, nil
}

func (s *Lexer) readString() (*Token, error) {
	var builder strings.Builder
	row := s.row
	col := s.col

	s.read() // initial quote

	for {
		tok := s.peek()

		if tok == '\000' {
			return nil, s.readError(row, col, "non-terminated string")
		}

		if tok == '"' {
			s.read()
			break
		}

		r, err := s.read()
		if err != nil {
			return nil, err
		}

		builder.WriteRune(r)
	}

	return &Token{
		Raw:  builder.String(),
		Type: STRING,
		Row:  row,
		Col:  col,
	}, nil
}

func (l *Lexer) readError(row, col int, errorMsg string) error {
	return errors.New(fmt.Sprintf("error %v:%v: %v", row, col, errorMsg))
}
