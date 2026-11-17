package main

import (
	"fmt"
	"regexp"
	"strings"
)

// M7-D Phase 2B-3 hardening: AQL structural validation.
//
// The worker's statement is untrusted. It is tokenised and parsed against a
// deliberately small grammar, then re-rendered canonically by this code, with the
// tenant predicate emitted as an AND term outside the rule body. Anything the
// grammar does not recognise is rejected — never "cleaned up".
//
// Supported subset:
//
//	SELECT <field-list> FROM events WHERE <expr> [LAST <n> DAYS]
//	expr    := orExpr
//	orExpr  := andExpr (OR andExpr)*
//	andExpr := notExpr (AND notExpr)*
//	notExpr := [NOT] primary
//	primary := '(' expr ')' | predicate
//	predicate := operand (=|!=|<>|<|>|<=|>=|LIKE) operand
//	           | operand [NOT] IN '(' operand (',' operand)* ')'
//	operand := field | 'string' | number | LOWER(field) | UPPER(field)
//
// Everything else — comments, statements, functions beyond LOWER/UPPER, string
// concatenation, subqueries, unknown operators — is rejected.

var (
	reAQLIdent     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reSelectItem   = regexp.MustCompile(`^(\*|[A-Za-z_][A-Za-z0-9_]*)$`)
	reDomainID     = regexp.MustCompile(`^[0-9]{1,10}$`)
)

// ValidatedAQL is the safe, tenant-scoped statement built from a worker result.
type ValidatedAQL struct {
	AQL            string
	SelectList     string
	Expression     string
	TimeWindowDays int
}

type aqlTokKind int

const (
	tokEOF aqlTokKind = iota
	tokIdent
	tokString
	tokNumber
	tokOp
	tokLParen
	tokRParen
	tokComma
	tokStar
)

type aqlTok struct {
	kind   aqlTokKind
	text   string
	quoted bool // double-quoted identifier
}

func tokenizeAQL(s string) ([]aqlTok, error) {
	var toks []aqlTok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '\r' || c == '\n':
			return nil, fmt.Errorf("%w: newlines are not allowed", ErrAQLInvalid)
		case c == '(':
			toks = append(toks, aqlTok{kind: tokLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, aqlTok{kind: tokRParen, text: ")"})
			i++
		case c == ',':
			toks = append(toks, aqlTok{kind: tokComma, text: ","})
			i++
		case c == '*':
			toks = append(toks, aqlTok{kind: tokStar, text: "*"})
			i++
		case c == '\'':
			i++
			var b strings.Builder
			closed := false
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					// Keep the escaped character; the renderer re-escapes it.
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated string literal", ErrAQLInvalid)
			}
			toks = append(toks, aqlTok{kind: tokString, text: b.String()})
		case c == '"':
			i++
			var b strings.Builder
			closed := false
			for i < len(s) {
				if s[i] == '"' {
					i++
					closed = true
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated quoted identifier", ErrAQLInvalid)
			}
			name := strings.TrimSpace(b.String())
			if name == "" || strings.ContainsAny(name, "\"'();") {
				return nil, fmt.Errorf("%w: invalid quoted identifier", ErrAQLInvalid)
			}
			toks = append(toks, aqlTok{kind: tokIdent, text: name, quoted: true})
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
				j++
			}
			toks = append(toks, aqlTok{kind: tokNumber, text: s[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			toks = append(toks, aqlTok{kind: tokIdent, text: s[i:j]})
			i = j
		case c == '=' || c == '<' || c == '>' || c == '!':
			j := i + 1
			if j < len(s) && (s[j] == '=' || (c == '<' && s[j] == '>')) {
				j++
			}
			op := s[i:j]
			if op != "=" && op != "!=" && op != "<>" && op != "<" && op != ">" && op != "<=" && op != ">=" {
				return nil, fmt.Errorf("%w: unsupported operator %q", ErrAQLInvalid, op)
			}
			toks = append(toks, aqlTok{kind: tokOp, text: op})
			i = j
		default:
			return nil, fmt.Errorf("%w: unsupported character %q", ErrAQLInvalid, string(c))
		}
	}
	return append(toks, aqlTok{kind: tokEOF}), nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

type aqlOperand struct {
	kind  string // field | string | number
	name  string
	text  string
	fn    string // LOWER | UPPER
	inner *aqlOperand
}

type aqlExpr interface{}

type aqlBool struct {
	op          string // AND | OR
	left, right aqlExpr
}
type aqlNot struct{ e aqlExpr }
type aqlCmp struct {
	left, right aqlOperand
	op          string
}
type aqlIn struct {
	left aqlOperand
	neg  bool
	list []aqlOperand
}

type aqlParser struct {
	toks []aqlTok
	pos  int
}

func (p *aqlParser) peek() aqlTok { return p.toks[p.pos] }
func (p *aqlParser) next() aqlTok { t := p.toks[p.pos]; p.pos++; return t }
func (p *aqlParser) isKeyword(kw string) bool {
	t := p.peek()
	return t.kind == tokIdent && !t.quoted && strings.EqualFold(t.text, kw)
}
func (p *aqlParser) expectKeyword(kw string) error {
	if !p.isKeyword(kw) {
		return fmt.Errorf("%w: expected %s", ErrAQLInvalid, kw)
	}
	p.next()
	return nil
}

func (p *aqlParser) parseExpr() (aqlExpr, error) { return p.parseOr() }

func (p *aqlParser) parseOr() (aqlExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("OR") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &aqlBool{op: "OR", left: left, right: right}
	}
	return left, nil
}

func (p *aqlParser) parseAnd() (aqlExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("AND") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &aqlBool{op: "AND", left: left, right: right}
	}
	return left, nil
}

func (p *aqlParser) parseNot() (aqlExpr, error) {
	if p.isKeyword("NOT") {
		p.next()
		e, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &aqlNot{e: e}, nil
	}
	return p.parsePrimary()
}

func (p *aqlParser) parsePrimary() (aqlExpr, error) {
	if p.peek().kind == tokLParen {
		p.next()
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("%w: missing closing parenthesis", ErrAQLInvalid)
		}
		p.next()
		return e, nil
	}
	return p.parsePredicate()
}

func (p *aqlParser) parsePredicate() (aqlExpr, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	neg := false
	if p.isKeyword("NOT") {
		neg = true
		p.next()
	}
	if p.isKeyword("IN") {
		if left.kind != "field" && left.kind != "func" {
			return nil, fmt.Errorf("%w: IN requires an approved field expression on the left", ErrAQLInvalid)
		}
		p.next()
		if p.peek().kind != tokLParen {
			return nil, fmt.Errorf("%w: IN requires a value list", ErrAQLInvalid)
		}
		p.next()
		var list []aqlOperand
		for {
			op, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if op.kind == "field" {
				return nil, fmt.Errorf("%w: IN list must contain literals", ErrAQLInvalid)
			}
			list = append(list, op)
			if p.peek().kind == tokComma {
				p.next()
				continue
			}
			break
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("%w: IN list is not closed", ErrAQLInvalid)
		}
		p.next()
		if len(list) == 0 {
			return nil, fmt.Errorf("%w: IN list is empty", ErrAQLInvalid)
		}
		return &aqlIn{left: left, neg: neg, list: list}, nil
	}
	if neg {
		return nil, fmt.Errorf("%w: NOT must be followed by IN or a group", ErrAQLInvalid)
	}
	opTok := p.next()
	op := ""
	if opTok.kind == tokOp {
		op = opTok.text
	} else if opTok.kind == tokIdent && !opTok.quoted && (strings.EqualFold(opTok.text, "LIKE")) {
		op = "LIKE"
	} else {
		return nil, fmt.Errorf("%w: unsupported comparison", ErrAQLInvalid)
	}
	if left.kind != "field" && left.kind != "func" {
		return nil, fmt.Errorf("%w: left side of a comparison must be a field", ErrAQLInvalid)
	}
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	if op == "LIKE" && right.kind == "field" {
		return nil, fmt.Errorf("%w: LIKE requires a literal pattern", ErrAQLInvalid)
	}
	return &aqlCmp{left: left, op: op, right: right}, nil
}

func (p *aqlParser) parseOperand() (aqlOperand, error) {
	t := p.next()
	switch t.kind {
	case tokString:
		return aqlOperand{kind: "string", text: t.text}, nil
	case tokNumber:
		return aqlOperand{kind: "number", text: t.text}, nil
	case tokIdent:
		if !t.quoted {
			up := strings.ToUpper(t.text)
			if up == "LOWER" || up == "UPPER" {
				if p.peek().kind != tokLParen {
					return aqlOperand{}, fmt.Errorf("%w: %s requires an argument", ErrAQLInvalid, up)
				}
				p.next()
				inner, err := p.parseOperand()
				if err != nil {
					return aqlOperand{}, err
				}
				if inner.kind != "field" {
					return aqlOperand{}, fmt.Errorf("%w: %s applies to a field only", ErrAQLInvalid, up)
				}
				if p.peek().kind != tokRParen {
					return aqlOperand{}, fmt.Errorf("%w: %s call is not closed", ErrAQLInvalid, up)
				}
				p.next()
				return aqlOperand{kind: "func", fn: up, inner: &inner}, nil
			}
			switch up {
			case "AND", "OR", "NOT", "IN", "SELECT", "FROM", "WHERE", "EVENTS", "LAST", "DAYS", "LIKE":
				return aqlOperand{}, fmt.Errorf("%w: unexpected keyword %s", ErrAQLInvalid, up)
			}
		}
		if strings.Contains(t.text, "domainid") && strings.EqualFold(t.text, "domainid") {
			return aqlOperand{}, fmt.Errorf("%w: worker output must not carry a domain constraint", ErrAQLInvalid)
		}
		return aqlOperand{kind: "field", name: t.text}, nil
	default:
		return aqlOperand{}, fmt.Errorf("%w: unexpected token", ErrAQLInvalid)
	}
}

// renderOperand emits a canonical, safely quoted operand.
func renderOperand(o aqlOperand) string {
	switch o.kind {
	case "string":
		return "'" + strings.ReplaceAll(o.text, "'", "''") + "'"
	case "number":
		return o.text
	case "field":
		if reAQLIdent.MatchString(o.name) && !isReservedAQLWord(o.name) {
			return o.name
		}
		return `"` + strings.ReplaceAll(o.name, `"`, "") + `"`
	case "func":
		return o.fn + "(" + renderOperand(*o.inner) + ")"
	}
	return ""
}

func isReservedAQLWord(s string) bool {
	switch strings.ToUpper(s) {
	case "AND", "OR", "NOT", "IN", "LIKE", "SELECT", "FROM", "WHERE", "EVENTS", "LAST", "DAYS", "LOWER", "UPPER":
		return true
	}
	return false
}

func renderExpr(e aqlExpr) string {
	switch v := e.(type) {
	case *aqlBool:
		return "(" + renderExpr(v.left) + " " + v.op + " " + renderExpr(v.right) + ")"
	case *aqlNot:
		return "NOT (" + renderExpr(v.e) + ")"
	case *aqlCmp:
		return renderOperand(v.left) + " " + v.op + " " + renderOperand(v.right)
	case *aqlIn:
		parts := make([]string, 0, len(v.list))
		for _, item := range v.list {
			parts = append(parts, renderOperand(item))
		}
		neg := ""
		if v.neg {
			neg = "NOT "
		}
		return renderOperand(v.left) + " " + neg + "IN(" + strings.Join(parts, ", ") + ")"
	}
	return ""
}

// TenantScopedAQL validates a worker AQL statement against the supported subset
// and rebuilds it with the verified native domain constraint and time window.
func TenantScopedAQL(workerAQL, nativeDomainID string, timeWindowDays int) (*ValidatedAQL, error) {
	if !reDomainID.MatchString(nativeDomainID) {
		return nil, fmt.Errorf("%w: native domain id is not usable", ErrAQLInvalid)
	}
	if timeWindowDays <= 0 || timeWindowDays > 90 {
		return nil, fmt.Errorf("%w: time window must be 1..90 days", ErrAQLInvalid)
	}
	stmt := strings.TrimSpace(workerAQL)
	if stmt == "" {
		return nil, fmt.Errorf("%w: empty statement", ErrAQLInvalid)
	}
	if len(stmt) > 64<<10 {
		return nil, fmt.Errorf("%w: statement too large", ErrAQLInvalid)
	}
	toks, err := tokenizeAQL(stmt)
	if err != nil {
		return nil, err
	}
	p := &aqlParser{toks: toks}
	if !p.isKeyword("SELECT") {
		return nil, fmt.Errorf("%w: statement must start with SELECT", ErrAQLInvalid)
	}
	p.next()

	var selectItems []string
	for {
		t := p.next()
		switch t.kind {
		case tokIdent:
			item := t.text
			if !t.quoted && !reSelectItem.MatchString(item) {
				return nil, fmt.Errorf("%w: unsupported select item", ErrAQLInvalid)
			}
			if !t.quoted && strings.EqualFold(item, "FROM") {
				return nil, fmt.Errorf("%w: empty select list", ErrAQLInvalid)
			}
			selectItems = append(selectItems, item)
		case tokStar:
			selectItems = append(selectItems, "*")
		default:
			return nil, fmt.Errorf("%w: unsupported select list", ErrAQLInvalid)
		}
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if len(selectItems) == 0 {
		return nil, fmt.Errorf("%w: empty select list", ErrAQLInvalid)
	}
	if err := p.expectKeyword("FROM"); err != nil {
		return nil, err
	}
	if err := p.expectKeyword("EVENTS"); err != nil {
		return nil, err
	}
	if err := p.expectKeyword("WHERE"); err != nil {
		return nil, err
	}
	expr, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	// A worker-supplied time window is only allowed when it matches the requested
	// window. Silently replacing it would change the detection's temporal
	// semantics.
	if p.isKeyword("LAST") {
		p.next()
		n := p.next()
		if n.kind != tokNumber {
			return nil, fmt.Errorf("%w: LAST requires a number", ErrAQLInvalid)
		}
		if err := p.expectKeyword("DAYS"); err != nil {
			return nil, err
		}
		if strings.TrimSpace(n.text) != fmt.Sprintf("%d", timeWindowDays) {
			return nil, fmt.Errorf("%w: worker time window LAST %s DAYS conflicts with the requested %d days",
				ErrAQLInvalid, n.text, timeWindowDays)
		}
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("%w: trailing tokens after the expression", ErrAQLInvalid)
	}

	body := renderExpr(expr)
	if body == "" {
		return nil, fmt.Errorf("%w: empty expression", ErrAQLInvalid)
	}
	selectList := strings.Join(selectItems, ", ")
	aql := fmt.Sprintf("SELECT %s FROM events WHERE domainid=%s AND (%s) LAST %d DAYS",
		selectList, nativeDomainID, body, timeWindowDays)
	return &ValidatedAQL{AQL: aql, SelectList: selectList, Expression: body, TimeWindowDays: timeWindowDays}, nil
}
