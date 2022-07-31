package exec

import (
	"errors"
	"fmt"
)

const (
	LOAD = iota
	PUSH
	EXCEPT
	AND
	OR
	EQUAL
	NOTEQUAL
	GT
	GTE
	LT
	LTE
	ADD
	MINUS
	MINUSU
	BAND
	BOR
	BXOR
	SHIFTLEFT
	SHIFTRIGHT
	AT
	IN
)

type Op struct {
	OpCode   int
	VarParam string
	IntParam int64
}

func (o Op) String() string {
	switch o.OpCode {
	case LOAD:
		return fmt.Sprintf("LOAD %v", o.VarParam)
	case PUSH:
		return fmt.Sprintf("PUSH %v", o.IntParam)
	case AND:
		return "AND"
	case OR:
		return "OR"
	case EQUAL:
		return "EQUAL"
	case NOTEQUAL:
		return "NOTEQUAL"
	case GT:
		return "GT"
	case GTE:
		return "GTE"
	case LT:
		return "LT"
	case LTE:
		return "LTE"
	case BAND:
		return "BAND"
	case BOR:
		return "BOR"
	case BXOR:
		return "BXOR"
	case ADD:
		return "ADD"
	case MINUS:
		return "MINUS"
	case MINUSU:
		return "MINUSU"
	case SHIFTLEFT:
		return "SHIFTLEFT"
	case SHIFTRIGHT:
		return "SHIFTRIGHT"
	case AT:
		return "AT"
	case IN:
		return fmt.Sprintf("IN %v", o.VarParam)
	default:
		return "WAT"
	}
}

func eval(rule *Rule, mappings map[string]Pattern) (int64, error) {

	index := 0
	var ret int64
	stack := make([]int64, 0)
	var right int64
	var left int64

	pop := func() int64 {
		ret, stack = stack[0], stack[1:]
		return ret
	}

	push := func(i int64) {
		stack = append([]int64{i}, stack...)
	}

	for {

		if index >= len(rule.instr) {
			break
		}

		cur := rule.instr[index]

		switch cur.OpCode {
		case LOAD:
			if pattern, ok := mappings[cur.VarParam]; ok {
				push(pattern.Count())
			} else {
				push(0)
			}

		case PUSH:
			push(cur.IntParam)

		case BAND:
			right = pop()
			left = pop()

			ret := right & left
			push(ret)

		case BOR:
			right = pop()
			left = pop()

			ret := right | left
			push(ret)

		case BXOR:
			right = pop()
			left = pop()

			ret := right ^ left
			push(ret)

		case AND:
			right = pop()
			left = pop()

			if left > 0 && right > 0 {
				push(1)
			} else {
				push(0)
			}

		case OR:
			right = pop()
			left = pop()

			if left > 0 || right > 0 {
				push(1)
			} else {
				push(0)
			}

		case EQUAL:
			right = pop()
			left = pop()

			if left == right {
				push(1)
			} else {
				push(0)
			}

		case NOTEQUAL:
			right = pop()
			left = pop()

			if left != right {
				push(1)
			} else {
				push(0)
			}

		case ADD:
			right = pop()
			left = pop()

			ret := left + right
			push(ret)

		case MINUS:
			right = pop()
			left = pop()

			ret := left - right
			push(ret)

		case MINUSU:
			right = pop()

			ret := -right
			push(ret)

		case GT:
			right = pop()
			left = pop()

			if left > right {
				push(1)
			} else {
				push(0)
			}

		case GTE:
			right = pop()
			left = pop()

			if left >= right {
				push(1)
			} else {
				push(0)
			}

		case LT:
			right = pop()
			left = pop()

			if left < right {
				push(1)
			} else {
				push(0)
			}

		case LTE:
			right = pop()
			left = pop()

			if left <= right {
				push(1)
			} else {
				push(0)
			}

		case SHIFTLEFT:
			right = pop()
			left = pop()

			ret := left << right
			push(ret)

		case SHIFTRIGHT:
			right = pop()
			left = pop()

			ret := left >> right
			push(ret)

		case AT:
			right = pop()

			if pattern, ok := mappings[cur.VarParam]; ok {
				result := 0
				for _, index := range pattern.Indexes() {
					if index == int(right) {
						result = 1
					}
				}

				push(int64(result))

			} else {
				push(0)
			}

		case IN:
			// high value in range
			right = pop()
			// low value in range
			left = pop()

			if pattern, ok := mappings[cur.VarParam]; ok {
				result := 0
				for _, index := range pattern.Indexes() {
					if index > int(left) && index < int(right) {
						result++
					}
				}

				push(int64(result))

			} else {
				push(0)
			}

		default:
			return -1, errors.New(fmt.Sprintf("exec: invalid instruction '%v'\n", cur.OpCode))
		}

		index++
	}

	return stack[0], nil
}
