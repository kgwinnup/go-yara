package exec

import (
	"testing"

	_ "embed"
)

//go:embed test.base64
var inputBase64 string

func testCompile(rule string, input string) ([]*ScanOutput, error) {
	compiled, err := Compile(rule)
	if err != nil {
		return nil, err
	}

	out, err := compiled.Scan([]byte(input), false, 3)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func TestRuleNocase(t *testing.T) {

	rule := `rule Foobar : Tag1 {
    strings:
        $s1 = "foobar"
        $s2 = "foobaz" nocase
    condition:
        $s1 and $s2
}
`

	input := "foobaZ foobar"
	out, _ := testCompile(rule, input)

	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}

	if out[0].Tags[0] != "Tag1" {
		t.Fatal("invalid tag")
	}

}

func TestRuleNocase2(t *testing.T) {

	rule := `rule Foobar : Tag1 {
    strings:
        $s1 = "Foobar" nocase
        $s2 = "foobaz" nocase
    condition:
        $s1 and $s2
}
`

	input := "foObAZ fooBAR"

	out, _ := testCompile(rule, input)

	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}

	if out[0].Tags[0] != "Tag1" {
		t.Fatal("invalid tag")
	}

}

func TestRuleCount(t *testing.T) {

	rule := `rule Foobar {
    strings:
        $s1 = "foobar"
    condition:
        #s1 > 2
}
`

	input := "foobar foobar foobar"
	out, _ := testCompile(rule, input)

	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}
}

func TestRuleOr(t *testing.T) {

	rule := `rule Example
{
    strings:
        $a = "text1"
        $b = "text2"
        $c = "text3"
        $d = "text4"

    condition:
        ($a or $b) and ($c or $d)
}
`

	input := "text1 text4"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}
}

func TestRuleAt(t *testing.T) {

	rule := `rule Foobar
{
    strings:
        $a = "text1"

    condition:
        $a at 10
}
`
	input := "0123456789text1"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("AT pattern failed to match")
	}

	rule = `rule Foobar
{
    strings:
        $a = "text1"

    condition:
        $a at (5 + 5)
}
`
	out, _ = testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("AT pattern failed to match")
	}

}

func TestRuleMinusAt(t *testing.T) {

	rule := `rule Foobar
{
    strings:
        $a = "text1"

    condition:
        $a at -(-(5 + 5))
}
`
	input := "0123456789text1"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("AT pattern failed to match")
	}

}

func TestRuleIn(t *testing.T) {

	rule := `rule Foobar
{
    strings:
        $a = "text1"

    condition:
        $a in (8..filesize)
}
`

	input := "0123456789text1-----"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("IN pattern failed to match")
	}
}

func TestOf(t *testing.T) {
	rule := `
rule OfExample1
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"

    condition:
        2 of ($a,$b,$c)
}
`

	input := "dummy2 dummy3"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("OF pattern failed to match")
	}
}

func TestForRange(t *testing.T) {
	rule := `rule Occurrences
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        for any i in (0..3) : ( @a[i] + 10 == @b[i] )
}`

	input := "dummy1    dummy2"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("OF pattern failed to match")
	}
}

func TestForThem(t *testing.T) {
	rule := `
rule Occurrences
{
    strings:
        $a1 = "dummy1"
        $a2 = "dummy2"
        $b = "foobar"

    condition:
        // comment
        for any of them : ( @ > @b )
}
`
	input := "foobar dummy1    dummy2 dummy2"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("OF pattern failed to match")
	}
}

func TestForAllThem(t *testing.T) {
	rule := `
rule Occurrences
{
    strings:
        $a1 = "dummy1"
        $a2 = "dummy2"

    condition:
        for all of them : ( # > 2 )
}
`
	input := "foobar dummy1 dummy1 dummy1   dummy2 dummy2 dummy2"
	out, _ := testCompile(rule, input)
	if len(out) == 0 {
		t.Fatal("OF pattern failed to match")
	}
}

func TestRuleBytes(t *testing.T) {

	rule := `rule Foobar : Tag1 {
    strings:
        $s1 = { 41 41 41 [1-5] ( 42 | 43 ) } 
    condition:
        $s1
}
`

	input := "AAADDB"
	out, _ := testCompile(rule, input)

	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}

	rule = `rule Foobar : Tag1 {
    strings:
        $s1 = { 41 41 41 [1-5] ( 48 | 49 ) } 
    condition:
        $s1
}
`

	input = "AAADB"
	out, _ = testCompile(rule, input)

	if len(out) != 0 {
		t.Fatal("patterns failed to match")
	}

}

func TestRuleBytes3(t *testing.T) {

	rule := `rule Foobar : Tag1 {
    strings:
        $s1 = { 68 65 6c 6c 6f } 
    condition:
        $s1
}
`
	input := "hello"
	out, _ := testCompile(rule, input)

	if len(out) == 0 {
		t.Fatal("patterns failed to match")
	}

}

func TestBase64(t *testing.T) {
	rule := `rule Foobar {
    strings:
        $s1 = "foobar foobaZ" base64 nocase
    condition:
        $s1
}`

	out, _ := testCompile(rule, inputBase64)
	if len(out) == 0 {
		t.Fatal("failed to match base64")
	}
}

func TestRegex(t *testing.T) {
	rule := `rule Foobar {
    strings:
        $s1 = /(foobar|foobaz)[0-9]{1,2}/ 
    condition:
        $s1
}`

	out, _ := testCompile(rule, "foobar12")
	if len(out) == 0 {
		t.Fatal("failed to match regex")
	}
}
