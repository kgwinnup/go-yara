package ast

import (
	"testing"
)

func TestBytesBytePattern(t *testing.T) {
	bs := Bytes{
		Token: nil,
		Items: []string{"ff", "ff", "(", "aa", "|", "bb", ")"},
	}

	out, _ := bs.BytePattern()

	if len(out) != 2 {
		t.Fatal("expecting two byte patterns")
	}

	if out[0][2] != 170 {
		t.Fatal("expecting 0xaa at the end of first array")
	}

	if out[1][2] != 187 {
		t.Fatal("expecting 0xbb at the end of first array")
	}

}
