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
	stack := make([]int64, 0)
	var right int64
	var left int64

	pop := func(stack []int64) (int64, []int64) {
		return stack[0], stack[1:]
	}

	push := func(stack []int64, i int64) []int64 {
		return append([]int64{i}, stack...)
	}

	for {

		if index >= len(rule.instr) {
			break
		}

		cur := rule.instr[index]

		switch cur.OpCode {
		case LOAD:
			if pattern, ok := mappings[cur.VarParam]; ok {
				stack = push(stack, pattern.Count())
			} else {
				stack = push(stack, 0)
			}

		case PUSH:
			stack = push(stack, cur.IntParam)

		case BAND:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := right & left
			stack = push(stack, ret)

		case BOR:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := right | left
			stack = push(stack, ret)

		case BXOR:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := right ^ left
			stack = push(stack, ret)

		case AND:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left > 0 && right > 0 {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case OR:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left > 0 || right > 0 {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case EQUAL:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left == right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case NOTEQUAL:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left != right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case ADD:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := left + right
			stack = push(stack, ret)

		case MINUS:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := left - right
			stack = push(stack, ret)

		case MINUSU:
			right, stack = pop(stack)

			ret := -right
			stack = push(stack, ret)

		case GT:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left > right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case GTE:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left >= right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case LT:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left < right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case LTE:
			right, stack = pop(stack)
			left, stack = pop(stack)

			if left <= right {
				stack = push(stack, 1)
			} else {
				stack = push(stack, 0)
			}

		case SHIFTLEFT:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := left << right
			stack = push(stack, ret)

		case SHIFTRIGHT:
			right, stack = pop(stack)
			left, stack = pop(stack)

			ret := left >> right
			stack = push(stack, ret)

		case AT:
			right, stack = pop(stack)

			if pattern, ok := mappings[cur.VarParam]; ok {
				result := 0
				for _, index := range pattern.Indexes() {
					if index == int(right) {
						result = 1
					}
				}

				stack = push(stack, int64(result))

			} else {
				stack = push(stack, 0)
			}

		case IN:
			// high value in range
			right, stack = pop(stack)
			// low value in range
			left, stack = pop(stack)

			if pattern, ok := mappings[cur.VarParam]; ok {
				result := 0
				for _, index := range pattern.Indexes() {
					if index > int(left) && index < int(right) {
						result++
					}
				}

				stack = push(stack, int64(result))

			} else {
				stack = push(stack, 0)
			}

		default:
			return -1, errors.New(fmt.Sprintf("exec: invalid instruction '%v'\n", cur.OpCode))
		}

		index++
	}

	return stack[0], nil
}
