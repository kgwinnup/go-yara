package exec

import (
	"testing"
)

func testCompile(rule string, input string) ([]*ScanOutput, error) {
	compiled, err := Compile(rule)
	if err != nil {
		return nil, err
	}

	out, err := compiled.Scan([]byte(input))
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
