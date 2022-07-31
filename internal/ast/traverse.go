package ast

import "errors"

type Fn func(Node, map[int]Fn, interface{}) (Node, error)

func DoInfix(node Node, mappings map[int]Fn, state interface{}) (Node, error) {
	infix, ok := node.(*Infix)
	if !ok {
		return nil, errors.New("invalid node, expecting infix")
	}

	left, err := Traverse(infix.Left, mappings, state)
	if err != nil {
		return nil, err
	}

	right, err := Traverse(infix.Right, mappings, state)
	if err != nil {
		return nil, err
	}

	infix.Left = left
	infix.Right = right
	return infix, nil
}

func DoPrefix(node Node, mappings map[int]Fn, state interface{}) (Node, error) {
	prefix, ok := node.(*Prefix)
	if !ok {
		return nil, errors.New("invalid node, expecting prefix")
	}

	right, err := Traverse(prefix.Right, mappings, state)
	if err != nil {
		return nil, err
	}

	prefix.Right = right
	return prefix, nil
}

func Mappings() map[int]Fn {
	mappings := make(map[int]Fn)
	mappings[INFIX] = DoInfix
	mappings[PREFIX] = DoPrefix

	return mappings
}

func Traverse(node Node, mappings map[int]Fn, state interface{}) (Node, error) {
	if node == nil {
		return nil, errors.New("wat, node is nil")
	}

	f, ok := mappings[node.Type()]
	if !ok {
		return node, nil
	}

	return f(node, mappings, state)
}
