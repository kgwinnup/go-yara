package exec

type Pattern interface {
	// Check will take as input the slice of bytes to scan, and a list
	// of possible indexes where the scanning can begin.
	// the list of indexes is intended for use when partial patterns
	// are used.
	// return value is the number of occurances found
	Check(input []byte, indexes []int) int

	// Pattern returns the byte pattern to be used in the
	// automata. The bool return value is whether this pattern should
	// be treated as no case. This only works for ascii.
	Pattern() []byte

	// Rule returns the name of the rule this pattern is associated with.
	Rule() string

	// returns the name of the pattern, $s1 = "foobar", $s1 in this case
	Name() string

	// adds a new index position within the input
	AddIndex(i int)

	// return list of index offsets where this pattern was found
	Indexes() []int

	// returns the size of the byte pattern
	Size() int

	//returns the number of hits in the buffer
	Count() int64
}

type ConstantPattern struct {
	name string
	size int
}

func (c *ConstantPattern) Check(input []byte, indexes []int) int {
	return 0
}

func (c *ConstantPattern) Pattern() []byte {
	return []byte{}
}

func (c *ConstantPattern) Rule() string {
	return ""
}

func (c *ConstantPattern) Name() string {
	return ""
}

func (c *ConstantPattern) AddIndex(i int) {
}

func (c *ConstantPattern) Indexes() []int {
	return []int{}
}

func (c *ConstantPattern) Size() int {
	return 0
}

func (c *ConstantPattern) Count() int64 {
	return int64(c.size)
}

type StringPattern struct {
	name string
	// pattern to be used in the automta
	pattern []byte
	// what rule this pattern is tied to.
	rule    string
	nocase  bool
	indexes []int
	size    int
	count   int
}

// Check for string patterns is just the count of indexes found. This
// is because the entire string to be searched for is added to the
// automata. So the indexes will always be the complete string.
func (s *StringPattern) Check(input []byte, indexes []int) int {
	return len(indexes)
}

func (s *StringPattern) Pattern() []byte {
	s.size = len(s.pattern)
	return s.pattern
}

func (s *StringPattern) Rule() string {
	return s.rule
}

func (s *StringPattern) Name() string {
	return s.name
}

func (s *StringPattern) AddIndex(i int) {
	s.indexes = append(s.indexes, i)
	s.count++
}

func (s *StringPattern) Indexes() []int {
	return s.indexes
}

func (s *StringPattern) Size() int {
	return s.size
}

func (s *StringPattern) Count() int64 {
	return int64(s.count)
}
