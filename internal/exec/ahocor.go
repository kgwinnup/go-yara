package exec

import (
	"regexp"
)

type ACNode struct {
	id          int
	data        byte
	children    [256]*ACNode
	fail        *ACNode
	alternative *ACNode
	match       int
	// index in the current pattern, used for partial compares if
	// access to the start of the pattern is needed.
	matchOffset int
	// signals that this particular node's match is a partial
	// Match. The fullMatch value is the full value to match
	// against, contains ?? bytes as well
	fullMatch  [][]int
	matchIndex []int
	// signal if the node contains a regex prefix match. If there is a
	// prefix match, check the input bytes starting at the prefix
	// match.
	re *regexp.Regexp
}

func ACBuild(patterns []*Pattern) []*ACNode {

	nodes := make([]*ACNode, 0)

	root := &ACNode{
		id:          0,
		data:        0,
		children:    [256]*ACNode{},
		fail:        nil,
		alternative: nil,
		match:       -1,
		matchOffset: 0,
	}

	nodes = append(nodes, root)

	cur := root
	ids := 1

	for _, pattern := range patterns {
		cur = root

		bs := pattern.Pattern
		for j, b := range bs {

			if node := cur.children[b]; node != nil {

				if j == len(bs)-1 {
					node.match = pattern.MatchIndex

					if pattern.IsPartial {
						node.fullMatch = append(node.fullMatch, pattern.FullMatch)
						node.matchIndex = append(node.matchIndex, pattern.MatchIndex)
					}
				}

				cur = node
				continue
			}

			node := &ACNode{
				id:          ids,
				data:        b,
				children:    [256]*ACNode{},
				fail:        nil,
				match:       -1,
				matchOffset: j,
			}

			if j == len(bs)-1 {
				node.match = pattern.MatchIndex

				if pattern.IsPartial {
					node.fullMatch = make([][]int, 0)
					node.fullMatch = append(node.fullMatch, pattern.FullMatch)
					node.matchIndex = make([]int, 0)
					node.matchIndex = append(node.matchIndex, pattern.MatchIndex)
				}

			}

			nodes = append(nodes, node)
			ids++

			cur.children[b] = node
			cur = node
		}
	}

	root.fail = root

	failQueue := make([]*ACNode, 0)

	// set the first node of each branch fail point back to root
	for _, child := range root.children {
		if child == nil {
			continue
		}
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
			if child == nil {
				continue
			}

			temp := cur.fail

			for {
				node := temp.children[child.data]
				ok := node != nil

				// we're at the largest suffix so far
				if !ok && temp != root {
					temp = temp.fail
				}

				if temp == root || ok {
					break
				}

			}

			if node := temp.children[child.data]; node != nil {
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

// ACNext will perform a single byte transition of the automata,
// returning any indexes where a pattern is hit
func ACNext(matches []*[]int, nodes []*ACNode, input []byte) {

	node := nodes[0]

	for i := 0; i < len(input); i++ {
		b := input[i]
		// check if there is a path
		new := node.children[b]

		// if there is a child node that matches the input
		if new != nil {
			// transition to the next node
			node = new

			// check if this node completes a match
			if node.match >= 0 && node.fullMatch == nil {
				if lst := matches[node.match]; lst != nil {
					*lst = append(*lst, i-node.matchOffset)
				} else {
					matches[node.match] = &[]int{i - node.matchOffset}
				}

			}

			if node.match >= 0 && node.fullMatch != nil {
				for k, part := range node.fullMatch {

					match := true

					for j := 0; j < len(part); j++ {
						if part[j]&0x1000 == 0x1000 {
							continue
						}

						if j+i-node.matchOffset >= len(input) {
							match = false
							break
						}

						if byte(part[j]) != input[j+i-node.matchOffset] {
							match = false
							break
						}
					}

					if match {
						if lst := matches[node.matchIndex[k]]; lst != nil {
							*lst = append(*lst, i-node.matchOffset)
						} else {
							matches[node.matchIndex[k]] = &[]int{i - node.matchOffset}
						}

						break
					}
				}

			}

			if node.match >= 0 && node.re != nil {
				indexes := node.re.FindAllIndex(input[i-node.matchOffset:], -1)

				if len(matches) > 0 {
					base := i - node.matchOffset
					for _, i := range indexes {
						if lst := matches[node.match]; lst != nil {
							*lst = append(*lst, base+i[0])
						} else {
							matches[node.match] = &[]int{base + i[0]}
						}
					}
				}

			}

			// jump to each alternative matching node if they exist
			temp := node.alternative
			for {
				if temp == nil {
					break
				}

				if temp.match >= 0 && temp.fullMatch == nil {
					if lst := matches[temp.match]; lst != nil {
						*lst = append(*lst, i-temp.matchOffset)
					} else {
						matches[temp.match] = &[]int{i - temp.matchOffset}
					}

				} else if temp.match >= 0 && node.fullMatch != nil {

					for k, part := range node.fullMatch {

						match := true

						for j := 0; j < len(part); j++ {
							if part[j]&0x1000 == 0x1000 {
								continue
							}

							if j+i-node.matchOffset >= len(input) {
								match = false
								break
							}

							if byte(part[j]) != input[j+i-node.matchOffset] {
								match = false
								break
							}
						}

						if match {
							if lst := matches[temp.matchIndex[k]]; lst != nil {
								*lst = append(*lst, i-temp.matchOffset)
							} else {
								matches[temp.matchIndex[k]] = &[]int{i - temp.matchOffset}
							}

							break
						}
					}

				} else if node.match >= 0 && node.re != nil {
					indexes := node.re.FindAllIndex(input[i-node.matchOffset:], -1)

					if len(matches) > 0 {
						base := i - node.matchOffset
						for _, i := range indexes {
							if lst := matches[node.match]; lst != nil {
								*lst = append(*lst, base+i[0])
							} else {
								matches[node.match] = &[]int{base + i[0]}
							}
						}
					}

				}

				temp = temp.alternative
			}

		} else {

			// jump to each failure node until a next matching
			// transition node is found, or back at the root.
			for {
				ok := node.children[b] != nil

				if node.id == 0 {
					break
				}

				if ok {
					break
				}

				node = node.fail
			}

			// rerun this input char again as we moved nodes
			if node.children[b] != nil {
				i--
			}
		}
	}
}

func ACNextNocase(matches []*[]int, nodes []*ACNode, input []byte) {

	node := nodes[0]

	for i := 0; i < len(input); i++ {
		b := input[i]
		if b >= 0x41 && b <= 0x5a {
			b = b | 0x20
		}
		// check if there is a path
		new := node.children[b]

		// if there is a child node that matches the input
		if new != nil {
			// transition to the next node
			node = new

			// check if this node completes a match
			if node.match >= 0 {
				if lst := matches[node.match]; lst != nil {
					*lst = append(*lst, i-node.matchOffset)
				} else {
					matches[node.match] = &[]int{i - node.matchOffset}
				}
			}

			// jump to each alternative matching node if they exist
			temp := node.alternative
			for {
				if temp == nil {
					break
				}

				if lst := matches[node.match]; lst != nil {
					*lst = append(*lst, i-node.matchOffset)
				} else {
					matches[node.match] = &[]int{i - node.matchOffset}
				}

				temp = temp.alternative
			}

		} else {

			// jump to each failure node until a next matching
			// transition node is found, or back at the root.
			for {
				ok := node.children[b] != nil

				if node.id == 0 {
					break
				}

				if ok {
					break
				}

				node = node.fail
			}

			// rerun this input char again as we moved nodes
			if node.children[b] != nil {
				i--
			}
		}
	}
}
