package exec

type Node struct {
	id          int
	data        byte
	children    map[byte]*Node
	fail        *Node
	alternative *Node
	match       int
	// index in the current pattern, used for partial compares if
	// access to the start of the pattern is needed.
	matchIndex int
	pattern    Pattern
}

func build(patterns []Pattern) []*Node {

	nodes := make([]*Node, 0)

	root := &Node{
		id:          0,
		data:        0,
		children:    make(map[byte]*Node),
		fail:        nil,
		alternative: nil,
		match:       -1,
		matchIndex:  0,
		pattern:     nil,
	}

	nodes = append(nodes, root)

	cur := root
	ids := 1

	for i, pattern := range patterns {
		cur = root

		bs := pattern.Pattern()
		for j, b := range bs {

			if node, ok := cur.children[b]; ok {

				if j == len(bs)-1 {
					node.match = i
				}

				cur = node
				continue
			}

			node := &Node{
				id:         ids,
				data:       b,
				children:   make(map[byte]*Node),
				fail:       nil,
				match:      -1,
				matchIndex: j,
				pattern:    pattern,
			}

			nodes = append(nodes, node)
			ids++

			if j == len(bs)-1 {
				node.match = i
			}

			cur.children[b] = node
			cur = node
		}
	}

	root.fail = root

	failQueue := make([]*Node, 0)

	// set the first node of each branch fail point back to root
	for _, child := range root.children {
		child.fail = root
		failQueue = append(failQueue, child)
	}

	for {
		// if the initial branch nodes are all consumed
		if len(failQueue) == 0 {
			break
		}

		// pop one item off the queue
		cur, failQueue = failQueue[0], failQueue[1:]

		// for each child in this branch find the largest suffix
		for _, child := range cur.children {
			temp := cur.fail

			for {
				_, ok := temp.children[child.data]

				// we're at the largest suffix so far
				if !ok && temp != root {
					temp = temp.fail
				}

				if temp == root || ok {
					break
				}

			}

			if node, ok := temp.children[child.data]; ok {
				child.fail = node // proper suffix
			} else {
				child.fail = root // no suffix
			}

			// add this node to the queue for processing
			failQueue = append(failQueue, child)
		}

		if cur.fail != nil && cur.fail.match >= 0 {
			cur.alternative = cur.fail
		} else {
			cur.alternative = cur.fail.alternative
		}
	}

	return nodes
}

// next will perform a single byte transition of the automata,
// returning any indexes where a pattern is hit
func next(nodes []*Node, index int, b byte, bindex int) int {

	node := nodes[index]

Start:
	// check if there is a path
	new, ok := node.children[b]

	// if there is a child node that matches the input
	if ok {
		// transition to the next node
		node = new

		// check if this node completes a match
		if node.match >= 0 {
			node.pattern.AddIndex(bindex - node.matchIndex)
		}

		// jump to each alternative matching node if they exist
		temp := node.alternative
		for {
			if temp == nil {
				break
			}

			node.pattern.AddIndex(bindex - node.matchIndex)
			temp = temp.alternative
		}

	} else {

		// jump to each failure node until a next matching
		// transition node is found, or back at the root.
		for {
			_, ok := node.children[b]

			if node.id == 0 {
				break
			}

			if ok {
				break
			}

			node = node.fail
		}

		// rerun this input char again as we moved nodes
		if _, ok := node.children[b]; ok {
			goto Start
		}
	}

	return node.id
}
