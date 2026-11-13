package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

const maxIncludeDepth = 32

type profileNode struct {
	name     string
	value    string
	relation bool
	final    bool
	parent   *profileNode
	children []*profileNode
}

func newProfileRoot() *profileNode {
	return &profileNode{name: "(root)"}
}

func (n *profileNode) add(name, value string, relation, checkFinal bool) *profileNode {
	for _, c := range n.children {
		if c.name != name {
			continue
		}

		if !relation && !c.relation {
			return c
		}

		if checkFinal && c.final {
			return nil
		}
	}

	c := &profileNode{name: name, value: value, relation: relation, parent: n}
	n.children = append(n.children, c)

	return c
}

func (n *profileNode) subsection(name string) *profileNode {
	for _, c := range n.children {
		if c.name == name && !c.relation {
			return c
		}
	}

	return nil
}

const (
	parseStateInitComment = iota
	parseStateStdLine
	parseStateGetOBrace
)

type profileParser struct {
	state      int
	groupLevel int
	discard    int
	root       *profileNode
	current    *profileNode
	depth      int
}

func parseProfile(scanner *bufio.Scanner, root *profileNode, depth int) error {
	p := &profileParser{state: parseStateInitComment, root: root, depth: depth}

	for n := 1; scanner.Scan(); n++ {
		if err := p.parseLine(scanner.Text()); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading the configuration: %w", err)
	}

	return nil
}

func (p *profileParser) parseLine(line string) error {
	line = strings.TrimRight(line, "\r\n")

	if name, ok := directive(line, "include"); ok {
		return parseIncludeFile(name, p.root, p.depth+1)
	}

	if name, ok := directive(line, "includedir"); ok {
		return parseIncludeDir(name, p.root, p.depth+1)
	}

	switch p.state {
	case parseStateInitComment:
		if _, ok := directive(line, "module"); ok {
			return InvalidErrorf("module directive (%s): loading the configuration from a module is not supported", line)
		}

		if !strings.HasPrefix(line, "[") {
			return nil
		}

		p.state = parseStateStdLine
	case parseStateGetOBrace:
		if !strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "{") {
			return InvalidErrorf("line (%s): expected the opening brace of a subsection", line)
		}

		p.state = parseStateStdLine

		return nil
	}

	return p.parseStdLine(line)
}

func directive(line, name string) (string, bool) {
	rest, ok := strings.CutPrefix(line, name)
	if !ok || rest == "" || !isProfileSpace(rest[0]) {
		return "", false
	}

	return strings.TrimLeftFunc(rest, unicode.IsSpace), true
}

func isProfileSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

func (p *profileParser) parseStdLine(line string) error {
	cp := strings.TrimLeftFunc(line, unicode.IsSpace)
	if cp == "" || cp[0] == ';' || cp[0] == '#' {
		return nil
	}

	switch cp[0] {
	case '[':
		return p.parseSection(line, cp)
	case '}':
		return p.parseCloseBrace(line, cp)
	default:
		return p.parseRelation(line, cp)
	}
}

func (p *profileParser) parseSection(line, cp string) error {
	if p.groupLevel > 1 {
		return InvalidErrorf("line (%s): a section header may not appear inside a subsection", line)
	}

	end := strings.IndexByte(cp, ']')
	if end < 0 {
		return InvalidErrorf("line (%s): the section header is not closed", line)
	}

	p.current = p.root.add(cp[1:end], "", false, false)
	p.groupLevel = 1

	if p.current.final {
		p.discard = 1
	} else {
		p.discard = 0
	}

	rest := cp[end+1:]
	if strings.HasPrefix(rest, "*") {
		p.current.final = true
		rest = rest[1:]
	}

	if strings.TrimSpace(rest) != "" {
		return InvalidErrorf("line (%s): unexpected text after the section header", line)
	}

	return nil
}

func (p *profileParser) parseCloseBrace(line, cp string) error {
	if p.groupLevel < 2 {
		return InvalidErrorf("line (%s): a closing brace has no subsection to close", line)
	}

	if strings.HasPrefix(cp[1:], "*") && p.discard == 0 {
		p.current.final = true
	}

	p.groupLevel--

	if p.groupLevel < p.discard {
		p.discard = 0
	}

	if p.discard == 0 {
		p.current = p.current.parent
	}

	return nil
}

func (p *profileParser) parseRelation(line, cp string) error {
	eq := strings.IndexByte(cp, '=')
	if eq <= 0 {
		return InvalidErrorf("line (%s): expected a relation of the form tag = value", line)
	}

	tag := strings.TrimRightFunc(cp[:eq], unicode.IsSpace)
	if strings.IndexFunc(tag, unicode.IsSpace) >= 0 {
		return InvalidErrorf("line (%s): a tag may not contain whitespace", line)
	}

	final := false
	if i := strings.IndexByte(tag, '*'); i >= 0 {
		tag, final = tag[:i], true
	}

	value := strings.TrimLeftFunc(cp[eq+1:], unicode.IsSpace)

	switch {
	case strings.HasPrefix(value, `"`):
		value = unquoteProfileValue(value[1:])
	case value == "":
		p.state = parseStateGetOBrace

		return p.openSubsection(tag, final)
	case value[0] == '{' && strings.TrimSpace(value[1:]) == "":
		return p.openSubsection(tag, final)
	default:
		value = strings.TrimRightFunc(value, unicode.IsSpace)
	}

	if p.discard != 0 {
		return nil
	}

	if n := p.current.add(tag, value, true, true); n != nil && final {
		n.final = true
	}

	return nil
}

func (p *profileParser) openSubsection(tag string, final bool) error {
	p.groupLevel++

	if p.discard != 0 {
		return nil
	}

	p.current = p.current.add(tag, "", false, false)

	if p.current.final {
		p.discard = p.groupLevel
	}

	if final {
		p.current.final = true
	}

	return nil
}

func unquoteProfileValue(s string) string {
	var b strings.Builder

	for i := 0; i < len(s) && s[i] != '"'; i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++

			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			default:
				b.WriteByte(s[i])
			}

			continue
		}

		b.WriteByte(s[i])
	}

	return b.String()
}

func parseIncludeFile(name string, root *profileNode, depth int) error {
	// MIT krb5 places no bound on nesting, so a file that includes itself would exhaust the stack.
	if depth > maxIncludeDepth {
		return InvalidErrorf("include (%s): includes are nested more than %d deep", name, maxIncludeDepth)
	}

	fh, err := os.Open(name) //nolint:gosec // G703: krb5.conf names the files it includes, as it does for MIT krb5.
	if err != nil {
		return InvalidErrorf("include (%s): %v", name, err)
	}
	defer fh.Close()

	if err = parseProfile(bufio.NewScanner(fh), root, depth); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return nil
}

func parseIncludeDir(name string, root *profileNode, depth int) error {
	if depth > maxIncludeDepth {
		return InvalidErrorf("includedir (%s): includes are nested more than %d deep", name, maxIncludeDepth)
	}

	entries, err := os.ReadDir(name)
	if err != nil {
		return InvalidErrorf("includedir (%s): %v", name, err)
	}

	names := make([]string, 0, len(entries))

	for _, e := range entries {
		if includable(e.Name()) {
			names = append(names, e.Name())
		}
	}

	slices.Sort(names)

	for _, n := range names {
		if err = parseIncludeFile(filepath.Join(name, n), root, depth); err != nil {
			return err
		}
	}

	return nil
}

func includable(name string) bool {
	// MIT krb5 skips dotfiles and names other than *.conf that hold anything but alphanumerics, dashes and
	// underscores, so editor backups and package manager leftovers are not read.
	if strings.HasPrefix(name, ".") {
		return false
	}

	if strings.HasSuffix(name, ".conf") {
		return true
	}

	for _, r := range name {
		if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_') {
			return false
		}
	}

	return true
}

type profile struct {
	files []*profileNode
}

func (p *profile) values(path ...string) []string {
	// Values are gathered from each file in turn, stopping after the first file in which the relation or a section
	// on its path is marked final, as MIT krb5's profile iterator does.
	var out []string

	for _, root := range p.files {
		section, final := root, false

		for _, name := range path[:len(path)-1] {
			if section = section.subsection(name); section == nil {
				break
			}

			final = final || section.final
		}

		if section != nil {
			for _, c := range section.children {
				if c.relation && c.name == path[len(path)-1] {
					out = append(out, c.value)
					final = final || c.final
				}
			}
		}

		if final {
			break
		}
	}

	return out
}

func (p *profile) value(path ...string) (string, bool) {
	v := p.values(path...)
	if len(v) == 0 {
		return "", false
	}

	return v[0], true
}

func (p *profile) subsections(path ...string) []string {
	return p.childNames(false, path...)
}

func (p *profile) relations(path ...string) []string {
	return p.childNames(true, path...)
}

func (p *profile) childNames(relation bool, path ...string) []string {
	var out []string

	for _, root := range p.files {
		section, final := root, false

		for _, name := range path {
			if section = section.subsection(name); section == nil {
				break
			}

			final = final || section.final
		}

		if section != nil {
			for _, c := range section.children {
				if c.relation == relation && !slices.Contains(out, c.name) {
					out = append(out, c.name)
				}
			}
		}

		if final {
			break
		}
	}

	return out
}

func readProfileScanner(scanner *bufio.Scanner) (*profileNode, error) {
	root := newProfileRoot()

	if err := parseProfile(scanner, root, 0); err != nil {
		return nil, err
	}

	return root, nil
}

func readProfilePath(name string) (*profileNode, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}

	root := newProfileRoot()

	if info.IsDir() {
		err = parseIncludeDir(name, root, 0)
	} else {
		err = parseIncludeFile(name, root, 0)
	}

	if err != nil {
		return nil, err
	}

	return root, nil
}
