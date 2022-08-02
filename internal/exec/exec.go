package exec

import (
	"errors"
	"fmt"
)

const (
	LOADCOUNT = iota
	LOADOFFSET
	LOADSTATIC
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
	OF
	MOVR
	ADDR
	INCR
	DECR
	PUSHR
	LOOP
	CLEAR
)

type Op struct {
	OpCode   int
	IntParam int64
}

func (o Op) String() string {
	switch o.OpCode {
	case LOADCOUNT:
		return fmt.Sprintf("LOADCOUNT %v", o.IntParam)
	case LOADOFFSET:
		return fmt.Sprintf("LOADOFFSET %v", o.IntParam)
	case LOADSTATIC:
		return fmt.Sprintf("LOADSTATIC %v", o.IntParam)
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
		return fmt.Sprintf("IN %v", o.IntParam)
	case OF:
		return fmt.Sprintf("OF %v", o.IntParam)
	case MOVR:
		return fmt.Sprintf("MOVR %v", o.IntParam)
	case ADDR:
		return fmt.Sprintf("ADDR %v", o.IntParam)
	case INCR:
		return fmt.Sprintf("INCR %v", o.IntParam)
	case DECR:
		return fmt.Sprintf("DECR %v", o.IntParam)
	case PUSHR:
		return fmt.Sprintf("PUSHR %v", o.IntParam)
	case LOOP:
		return fmt.Sprintf("LOOP %v", o.IntParam)
	case CLEAR:
		return fmt.Sprintf("CLEAR")
	default:
		return "WAT"
	}
}

const (
	RC = iota
	R1
	R2
	R3
)

func Eval(rule *CompiledRule, matches []*[]int, static []int64) (int64, error) {

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

	regs := []int64{0, 0, 0, 0}

	for {

		if index >= len(rule.instr) {
			break
		}

		cur := rule.instr[index]

		switch cur.OpCode {
		case MOVR:
			left = pop()
			regs[cur.IntParam] = left

		case ADDR:
			left = pop()
			regs[cur.IntParam] += left

		case INCR:
			regs[cur.IntParam]++

		case DECR:
			regs[cur.IntParam]--

		case PUSHR:
			push(regs[cur.IntParam])

		case LOOP:
			if regs[RC] > 0 {
				index = int(cur.IntParam) - 1
				regs[RC]--
			}

		case CLEAR:
			regs[0] = 0
			regs[1] = 0
			regs[2] = 0
			regs[3] = 0

		case LOADCOUNT:
			if lst := matches[cur.IntParam]; lst != nil {
				push(int64(len(*lst)))
			} else {
				push(0)
			}

		case LOADOFFSET:
			index := pop()

			if lst := matches[cur.IntParam]; lst != nil {
				if int(index) < len(*lst) {
					push(int64((*lst)[index]))
				} else {
					push(0)
				}
			} else {
				push(0)
			}

		case LOADSTATIC:
			if int(cur.IntParam) < len(static) {
				push(static[int(cur.IntParam)])
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

			if lst := matches[cur.IntParam]; lst != nil {
				result := 0
				for _, index := range *lst {
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

			if lst := matches[cur.IntParam]; lst != nil {
				result := 0
				for _, index := range *lst {
					if index > int(left) && index < int(right) {
						result++
					}
				}

				push(int64(result))

			} else {
				push(0)
			}

		case OF:
			set := make([]int64, 0)
			setSize := pop()

			for i := 0; i < int(setSize); i++ {
				set = append(set, pop())
			}

			count := 0
			for _, n := range set {
				if n > 0 {
					count++
				}

				if count >= int(cur.IntParam) {
					break
				}
			}

			if cur.IntParam > 0 && count >= int(cur.IntParam) {
				push(1)
			} else if cur.IntParam == 0 && count == 0 { // none of ($*)
				push(1)
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
