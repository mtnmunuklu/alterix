package evaluator

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/VirusTotal/gyp/pb"
	"github.com/mtnmunuklu/alterix/yara/evaluator/modifiers"
)

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

const precedenceNotExpression int8 = 15
const precedenceUnaryExpression int8 = 15

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[pb.BinaryExpression_Operator]int8{
	pb.BinaryExpression_BITWISE_OR:  3,
	pb.BinaryExpression_XOR:         4,
	pb.BinaryExpression_BITWISE_AND: 5,
	pb.BinaryExpression_EQ:          6,
	pb.BinaryExpression_NEQ:         6,
	pb.BinaryExpression_LT:          7,
	pb.BinaryExpression_LE:          7,
	pb.BinaryExpression_GT:          7,
	pb.BinaryExpression_GE:          7,
	pb.BinaryExpression_SHIFT_LEFT:  8,
	pb.BinaryExpression_SHIFT_RIGHT: 8,
	pb.BinaryExpression_PLUS:        9,
	pb.BinaryExpression_MINUS:       9,
	pb.BinaryExpression_TIMES:       10,
	pb.BinaryExpression_DIV:         10,
	pb.BinaryExpression_MOD:         10,
}

var operators = map[pb.BinaryExpression_Operator]string{
	pb.BinaryExpression_MATCHES:     "matches",
	pb.BinaryExpression_CONTAINS:    "contains",
	pb.BinaryExpression_ICONTAINS:   "icontains",
	pb.BinaryExpression_IEQUALS:     "iequals",
	pb.BinaryExpression_STARTSWITH:  "startswith",
	pb.BinaryExpression_ISTARTSWITH: "istartswith",
	pb.BinaryExpression_ENDSWITH:    "endswith",
	pb.BinaryExpression_IENDSWITH:   "iendswith",
	pb.BinaryExpression_AT:          "at",
	pb.BinaryExpression_IN:          "in",
	pb.BinaryExpression_BITWISE_OR:  "|",
	pb.BinaryExpression_XOR:         "^",
	pb.BinaryExpression_BITWISE_AND: "&",
	pb.BinaryExpression_EQ:          "==",
	pb.BinaryExpression_NEQ:         "!=",
	pb.BinaryExpression_LT:          "<",
	pb.BinaryExpression_LE:          "<=",
	pb.BinaryExpression_GT:          ">",
	pb.BinaryExpression_GE:          ">=",
	pb.BinaryExpression_SHIFT_LEFT:  "<<",
	pb.BinaryExpression_SHIFT_RIGHT: ">>",
	pb.BinaryExpression_PLUS:        "+",
	pb.BinaryExpression_MINUS:       "-",
	pb.BinaryExpression_TIMES:       "*",
	pb.BinaryExpression_DIV:         "\\",
	pb.BinaryExpression_MOD:         "%",
}

var forKeywords = map[pb.ForKeyword]string{
	pb.ForKeyword_NONE: "none",
	pb.ForKeyword_ALL:  "all",
	pb.ForKeyword_ANY:  "any",
}

var stringSetKeywords = map[pb.StringSetKeyword]string{
	pb.StringSetKeyword_THEM: "them",
}

func getExpressionPrecedence(expression *pb.Expression) int8 {
	switch expression.GetExpression().(type) {
	case *pb.Expression_OrExpression:
		return precedenceOrExpression
	case *pb.Expression_AndExpression:
		return precedenceAndExpression
	case *pb.Expression_BinaryExpression:
		return getBinaryExpressionPrecedence(expression.GetBinaryExpression())
	case *pb.Expression_NotExpression:
		return precedenceNotExpression
	case *pb.Expression_UnaryExpression:
		return precedenceUnaryExpression
	default:
		// Expression with no precedence defined. Return maximum value.
		return math.MaxInt8
	}
}

func getBinaryExpressionPrecedence(expression *pb.BinaryExpression) int8 {
	prec, ok := binaryOperatorsPrecedence[expression.GetOperator()]
	if !ok {
		return math.MaxInt8
	}

	return prec
}

// Helper function to prioritize "Fullword" in the list
func prioritizeFullword(modifiers []string) []string {
	if len(modifiers) > 0 && contains(modifiers, "fullword") {
		// Remove all occurrences of "Fullword"
		modifiers = removeAll(modifiers, "fullword")

		// Append "Fullword" to the end of the list
		modifiers = append(modifiers, "fullword")
	}

	return modifiers
}

// Helper function to check if a string is present in a list
func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Helper function to remove all occurrences of a string from a list
func removeAll(list []string, value string) []string {
	var result []string
	for _, item := range list {
		if item != value {
			result = append(result, item)
		}
	}
	return result
}

func (rule RuleEvaluator) evaluateStrings(ctx context.Context, identifier string, str *pb.String) (string, error) {
	switch val := str.GetValue().(type) {
	case *pb.String_Text:
		// Process TextString value
		return rule.processTextString(str.GetText(), identifier)

	case *pb.String_Hex:
		// Process Hex value
		return rule.processHex(str.GetHex(), identifier)

	case *pb.String_Regexp:
		// Process Regexp value
		return rule.processRegexp(str.GetRegexp(), identifier)

	default:
		return "", fmt.Errorf(`unsupported string value type "%T"`, val)
	}
}
func (rule RuleEvaluator) processTextString(text *pb.TextString, identifier string) (string, error) {
	// Process TextString value and return the filter
	var filter string

	// Extract fieldModifiers from textModifiers
	fieldModifiers, err := extractFieldModifiers(text.GetModifiers())
	if err != nil {
		return "", err
	}

	// Check if "Fullword" is present in the string list
	fieldModifiers = prioritizeFullword(fieldModifiers)

	// Get comparator function based on fieldModifiers
	comparator, err := modifiers.GetComparator(fieldModifiers...)
	if err != nil {
		return "", err
	}

	if len(rule.fieldmappings[identifier]) == 0 {
		filter, err = rule.matchValue(text.GetText(), []string{identifier}, comparator)
	} else {
		filter, err = rule.matchValue(text.GetText(), rule.fieldmappings[identifier], comparator)
	}

	if err != nil {
		return filter, err
	}

	return filter, nil
}

// Processes Hex value and returns the YARA filter
func (rule RuleEvaluator) processHex(hex *pb.HexTokens, identifier string) (string, error) {
	var filter strings.Builder

	if err := rule.serializeHexString(&filter, hex); err != nil {
		return "", err
	}

	return filter.String(), nil
}

// Processes Regexp value and returns the YARA filter
func (rule RuleEvaluator) processRegexp(regexp *pb.Regexp, identifier string) (string, error) {
	var filter strings.Builder

	if err := rule.serializeRegexp(&filter, regexp); err != nil {
		return "", err
	}

	return filter.String(), nil
}

// Serializes HexTokens and appends the result to the filter
func (rule RuleEvaluator) serializeHexString(filter *strings.Builder, hex *pb.HexTokens) error {
	if _, err := filter.WriteString("{ "); err != nil {
		return err
	}

	if err := rule.serializeHexTokens(filter, hex); err != nil {
		return err
	}

	if _, err := filter.WriteString("}"); err != nil {
		return err
	}

	return nil
}

// Serializes HexTokens and appends the result to the filter
func (rule RuleEvaluator) serializeHexTokens(filter *strings.Builder, ts *pb.HexTokens) error {
	for _, t := range ts.Token {
		if err := rule.serializeHexToken(filter, t); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a HexToken and appends the result to the filter
func (rule RuleEvaluator) serializeHexToken(filter *strings.Builder, t *pb.HexToken) error {
	switch val := t.GetValue().(type) {
	case *pb.HexToken_Sequence:
		return rule.serializeBytesSequence(filter, t.GetSequence())
	case *pb.HexToken_Jump:
		return rule.serializeJump(filter, t.GetJump())
	case *pb.HexToken_Alternative:
		return rule.serializeHexAlternative(filter, t.GetAlternative())
	default:
		return fmt.Errorf(`unsupported hextoken type: "%T"`, val)
	}
}

// Serializes BytesSequence and appends the result to the filter
func (rule RuleEvaluator) serializeBytesSequence(filter *strings.Builder, b *pb.BytesSequence) error {
	if len(b.Value) != len(b.Mask) || len(b.Value) != len(b.Nots) {
		return fmt.Errorf(
			`length of value, mask and nots must match in a BytesSequence. Found: %d, %d, %d`,
			len(b.Value),
			len(b.Mask),
			len(b.Nots))
	}

	for i, val := range b.Value {
		if b.Nots[i] {
			if _, err := filter.WriteString("~"); err != nil {
				return err
			}
		}
		switch mask := b.Mask[i]; mask {
		case 0:
			if _, err := filter.WriteString("?? "); err != nil {
				return err
			}
		case 0x0F:
			valStr := fmt.Sprintf("%02X", val)
			if _, err := filter.WriteString("?" + string(valStr[1]) + " "); err != nil {
				return err
			}
		case 0xF0:
			valStr := fmt.Sprintf("%02X", val)
			if _, err := filter.WriteString(string(valStr[0]) + "? "); err != nil {
				return err
			}
		case 0xFF:
			if _, err := filter.WriteString(fmt.Sprintf("%02X ", val)); err != nil {
				return err
			}
		default:
			return fmt.Errorf(`unsupported byte mask: "%x"`, mask)
		}
	}

	return nil
}

// Serializes Jump and appends the result to the filter
func (rule RuleEvaluator) serializeJump(filter *strings.Builder, jump *pb.Jump) error {
	if _, err := filter.WriteString("["); err != nil {
		return err
	}

	if jump.Start != nil && jump.End != nil && jump.GetStart() == jump.GetEnd() {
		if _, err := filter.WriteString(fmt.Sprintf("%d] ", jump.GetStart())); err != nil {
			return err
		}
	} else {
		if jump.Start != nil {
			if _, err := filter.WriteString(fmt.Sprintf("%d", jump.GetStart())); err != nil {
				return err
			}
		}

		if _, err := filter.WriteString("-"); err != nil {
			return err
		}

		if jump.End != nil {
			if _, err := filter.WriteString(fmt.Sprintf("%d", jump.GetEnd())); err != nil {
				return err
			}
		}

		if _, err := filter.WriteString("] "); err != nil {
			return err
		}
	}

	return nil
}

// Serializes HexAlternative and appends the result to the filter
func (rule RuleEvaluator) serializeHexAlternative(filter *strings.Builder, alt *pb.HexAlternative) error {
	if _, err := filter.WriteString("( "); err != nil {
		return err
	}

	for i, tokens := range alt.Tokens {
		if err := rule.serializeHexTokens(filter, tokens); err != nil {
			return err
		}
		if i < len(alt.Tokens)-1 {
			if _, err := filter.WriteString("| "); err != nil {
				return err
			}
		}
	}

	if _, err := filter.WriteString(") "); err != nil {
		return err
	}

	return nil
}

// Serializes Regexp and appends the result to the filter
func (rule RuleEvaluator) serializeRegexp(filter *strings.Builder, r *pb.Regexp) error {
	if _, err := filter.WriteString("/"); err != nil {
		return err
	}

	if _, err := filter.WriteString(r.GetText()); err != nil {
		return err
	}

	if _, err := filter.WriteString("/"); err != nil {
		return err
	}

	if r.Modifiers.GetI() {
		if _, err := filter.WriteString("i"); err != nil {
			return err
		}
	}
	if r.Modifiers.GetS() {
		if _, err := filter.WriteString("s"); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to extract fieldModifiers from StringModifiers
func extractFieldModifiers(textModifiers *pb.StringModifiers) ([]string, error) {
	var fieldModifiers []string

	if textModifiers.GetNocase() {
		fieldModifiers = append(fieldModifiers, "nocase")
	}
	if textModifiers.GetAscii() {
		fieldModifiers = append(fieldModifiers, "ascii")
	}
	if textModifiers.GetWide() {
		fieldModifiers = append(fieldModifiers, "wide")
	}
	if textModifiers.GetFullword() {
		fieldModifiers = append(fieldModifiers, "fullword")
	}
	if textModifiers.GetXor() {
		fieldModifier := "xor"
		min := textModifiers.GetXorMin()
		max := textModifiers.GetXorMax()
		if min != 0 || max != 255 {
			if min == max {
				fieldModifier = fmt.Sprintf("xor(%d)", min)
			} else {
				fieldModifier = fmt.Sprintf("xor(%d-%d)", min, max)
			}
		}
		fieldModifiers = append(fieldModifiers, fieldModifier)
	}
	if textModifiers.GetBase64() {
		alphabet := textModifiers.GetBase64Alphabet()
		if alphabet != "" {
			fieldModifiers = append(fieldModifiers, fmt.Sprintf("base64(\"%s\")", alphabet))
		} else {
			fieldModifiers = append(fieldModifiers, "base64")
		}
	}
	if textModifiers.GetBase64Wide() {
		alphabet := textModifiers.GetBase64Alphabet()
		if alphabet != "" {
			fieldModifiers = append(fieldModifiers, fmt.Sprintf("base64wide(\"%s\")", alphabet))
		} else {
			fieldModifiers = append(fieldModifiers, "base64wide")
		}
	}

	return fieldModifiers, nil
}

func (rule *RuleEvaluator) matchValue(value string, fields []string, comparator modifiers.ComparatorFunc) (string, error) {
	var filters []string
	for i, field := range fields {
		filter, err := comparator(field, value)
		if err != nil {
			return "", err
		}

		filters = append(filters, filter)

		if i < len(fields)-1 {
			filters = append(filters, " or ")
		}
	}

	if len(fields) > 1 {
		// if there are multiple fields, wrap filters in parentheses to keep operator precedence
		return "(" + strings.Join(filters, "") + ")", nil
	} else {
		// if there's only one field, filters can be added directly
		return strings.Join(filters, ""), nil
	}
}

func (rule RuleEvaluator) evaluateExpression(condition *strings.Builder, expression *pb.Expression) error {
	// Switch-case to check the type
	switch v := expression.GetExpression().(type) {
	case *pb.Expression_BoolValue:
		fmt.Println("BoolValue:", v.BoolValue)
		if _, err := condition.WriteString(fmt.Sprintf("%v", expression.GetBoolValue())); err != nil {
			return err
		}
	case *pb.Expression_OrExpression:
		fmt.Println("OrExpression:", v.OrExpression)
		if err := rule.serializeOrExpression(condition, expression.GetOrExpression()); err != nil {
			return err
		}
	case *pb.Expression_AndExpression:
		fmt.Println("AndExpression:", v.AndExpression)
		if err := rule.serializeAndExpression(condition, expression.GetAndExpression()); err != nil {
			return err
		}
	case *pb.Expression_StringIdentifier:
		fmt.Println("StringIdentifier:", v.StringIdentifier)
		if _, err := condition.WriteString(expression.GetStringIdentifier()); err != nil {
			return err
		}
	case *pb.Expression_ForInExpression:
		fmt.Println("ForInExpression:", v.ForInExpression)
		if err := rule.serializeForInExpression(condition, expression.GetForInExpression()); err != nil {
			return err
		}
	case *pb.Expression_ForOfExpression:
		fmt.Println("ForOfExpression:", v.ForOfExpression)
		if err := rule.serializeForOfExpression(condition, expression.GetForOfExpression()); err != nil {
			return err
		}
	case *pb.Expression_BinaryExpression:
		fmt.Println("BinaryExpression:", v.BinaryExpression)
		if err := rule.serializeBinaryExpression(condition, expression.GetBinaryExpression()); err != nil {
			return err
		}
	case *pb.Expression_Range:
		fmt.Println("Range:", v.Range)
		if err := rule.serializeRange(condition, expression.GetRange()); err != nil {
			return err
		}
	case *pb.Expression_Text:
		fmt.Println("Text:", v.Text)
		if _, err := condition.WriteString(`"`); err != nil {
			return err
		}
		if _, err := condition.WriteString(expression.GetText()); err != nil {
			return err
		}
		if _, err := condition.WriteString(`"`); err != nil {
			return err
		}
	case *pb.Expression_DoubleValue:
		fmt.Println("DoubleValue:", v.DoubleValue)
		if _, err := condition.WriteString(fmt.Sprintf("%f", expression.GetDoubleValue())); err != nil {
			return err
		}
	case *pb.Expression_NumberValue:
		fmt.Println("NumberValue:", v.NumberValue)
		if _, err := condition.WriteString(fmt.Sprintf("%d", expression.GetNumberValue())); err != nil {
			return err
		}
	default:
		// If an unknown type is encountered, perform actions here
		fmt.Println("Unknown type")
	}

	return nil
}

func (rule RuleEvaluator) serializeOrExpression(condition *strings.Builder, expression *pb.Expressions) error {
	return rule.serializeTerms(condition, expression.Terms, " or ", precedenceOrExpression)
}

func (rule RuleEvaluator) serializeAndExpression(condition *strings.Builder, expression *pb.Expressions) error {
	return rule.serializeTerms(condition, expression.Terms, " and ", precedenceAndExpression)
}

func (rule RuleEvaluator) serializeTerms(condition *strings.Builder, terms []*pb.Expression, joinStr string, precedence int8) error {
	for i, term := range terms {
		addParens := getExpressionPrecedence(term) < precedenceAndExpression
		if addParens {
			if _, err := condition.WriteString("( "); err != nil {
				return err
			}
		}

		if err := rule.evaluateExpression(condition, term); err != nil {
			return err
		}

		if addParens {
			if _, err := condition.WriteString(" )"); err != nil {
				return err
			}
		}

		if i < len(terms)-1 {
			if _, err := condition.WriteString(joinStr); err != nil {
				return err
			}
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeForInExpression(condition *strings.Builder, expression *pb.ForInExpression) error {
	if _, err := condition.WriteString("for "); err != nil {
		return err
	}

	if err := rule.serializeForExpression(condition, expression.ForExpression); err != nil {
		return err
	}

	if _, err := condition.WriteString(" " + strings.Join(expression.GetIdentifiers(), ",")); err != nil {
		return err
	}

	if _, err := condition.WriteString(" in "); err != nil {
		return err
	}

	if err := rule.serializeIterator(condition, expression.Iterator); err != nil {
		return err
	}

	if _, err := condition.WriteString(" : ("); err != nil {
		return err
	}

	if err := rule.evaluateExpression(condition, expression.Expression); err != nil {
		return err
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}

	return nil
}

func (rule RuleEvaluator) serializeForExpression(condition *strings.Builder, expression *pb.ForExpression) error {
	switch val := expression.GetFor().(type) {
	case *pb.ForExpression_Expression:
		return rule.evaluateExpression(condition, expression.GetExpression())
	case *pb.ForExpression_Keyword:
		return rule.serializeForKeyword(condition, expression.GetKeyword())
	default:
		return fmt.Errorf(`unsupported ForExpression value type "%s"`, val)
	}
}

func (rule RuleEvaluator) serializeForKeyword(condition *strings.Builder, expression pb.ForKeyword) error {
	kw, ok := forKeywords[expression]
	if !ok {
		return fmt.Errorf(`unknown keyword "%v"`, expression)
	}

	if _, err := condition.WriteString(kw); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) serializeIterator(condition *strings.Builder, expression *pb.Iterator) error {
	switch val := expression.GetIterator().(type) {
	case *pb.Iterator_IntegerSet:
		return rule.serializeIntegerSet(condition, expression.GetIntegerSet())
	case *pb.Iterator_Identifier:
		return rule.serializeIdentifier(condition, expression.GetIdentifier())
	default:
		return fmt.Errorf(`unsupported Iterator value type "%s"`, val)
	}
}

func (rule RuleEvaluator) serializeIntegerSet(condition *strings.Builder, expression *pb.IntegerSet) error {
	switch val := expression.GetSet().(type) {
	case *pb.IntegerSet_IntegerEnumeration:
		return rule.serializeIntegerEnumeration(condition, expression.GetIntegerEnumeration())
	case *pb.IntegerSet_Range:
		return rule.serializeRange(condition, expression.GetRange())
	default:
		return fmt.Errorf(`unsupported IntegerSet value type "%s"`, val)
	}
}

func (rule RuleEvaluator) serializeIntegerEnumeration(condition *strings.Builder, expression *pb.IntegerEnumeration) error {
	if _, err := condition.WriteString("("); err != nil {
		return err
	}

	if err := rule.serializeTerms(condition, expression.Values, ", ", math.MinInt8); err != nil {
		return err
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) serializeRange(condition *strings.Builder, expression *pb.Range) error {
	if _, err := condition.WriteString("("); err != nil {
		return err
	}

	if err := rule.evaluateExpression(condition, expression.Start); err != nil {
		return err
	}

	if _, err := condition.WriteString(".."); err != nil {
		return err
	}

	if err := rule.evaluateExpression(condition, expression.End); err != nil {
		return err
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) serializeIdentifier(condition *strings.Builder, expression *pb.Identifier) error {
	for i, item := range expression.GetItems() {
		switch val := item.GetItem().(type) {
		case *pb.Identifier_IdentifierItem_Identifier:
			if i > 0 {
				if _, err := condition.WriteString("."); err != nil {
					return err
				}
			}
			if _, err := condition.WriteString(item.GetIdentifier()); err != nil {
				return err
			}
		case *pb.Identifier_IdentifierItem_Index:
			if _, err := condition.WriteString("["); err != nil {
				return err
			}
			if err := rule.evaluateExpression(condition, item.GetIndex()); err != nil {
				return err
			}

			if _, err := condition.WriteString("]"); err != nil {
				return err
			}
		case *pb.Identifier_IdentifierItem_Arguments:
			if _, err := condition.WriteString("("); err != nil {
				return err
			}

			for i, arg := range item.GetArguments().Terms {
				if err := rule.evaluateExpression(condition, arg); err != nil {
					return err
				}
				if i < len(item.GetArguments().Terms)-1 {
					if _, err := condition.WriteString(", "); err != nil {
						return err
					}
				}
			}

			if _, err := condition.WriteString(")"); err != nil {
				return err
			}
		default:
			return fmt.Errorf(`unsupported identifier type "%T"`, val)
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeBinaryExpression(condition *strings.Builder, expression *pb.BinaryExpression) error {
	if getExpressionPrecedence(expression.Left) < getBinaryExpressionPrecedence(expression) {
		if _, err := condition.WriteString("("); err != nil {
			return err
		}
	}
	if err := rule.evaluateExpression(condition, expression.Left); err != nil {
		return err
	}
	if getExpressionPrecedence(expression.Left) < getBinaryExpressionPrecedence(expression) {
		if _, err := condition.WriteString(")"); err != nil {
			return err
		}
	}

	op, ok := operators[expression.GetOperator()]
	if !ok {
		return fmt.Errorf(`unknown operator "%v"`, expression.GetOperator())
	}

	if _, err := condition.WriteString(" " + op + " "); err != nil {
		return err
	}

	if getExpressionPrecedence(expression.Right) < getBinaryExpressionPrecedence(expression) {
		if _, err := condition.WriteString("("); err != nil {
			return err
		}
	}
	if err := rule.evaluateExpression(condition, expression.Right); err != nil {
		return err
	}
	if getExpressionPrecedence(expression.Right) < getBinaryExpressionPrecedence(expression) {
		if _, err := condition.WriteString(")"); err != nil {
			return err
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeForOfExpression(condition *strings.Builder, expression *pb.ForOfExpression) error {
	if (expression.GetStringSet() == nil && expression.GetRuleEnumeration() == nil) || (expression.GetStringSet() != nil && expression.GetRuleEnumeration() != nil) {
		panic("expecting one string set or rule set in \"ForOf\"")
	}
	if expression.GetExpression() != nil {
		if _, err := condition.WriteString("for "); err != nil {
			return err
		}
	}

	if err := rule.serializeForExpression(condition, expression.ForExpression); err != nil {
		return err
	}

	if _, err := condition.WriteString(" of "); err != nil {
		return err
	}

	if expression.GetStringSet() != nil {
		if err := rule.serializeStringSet(condition, expression.StringSet); err != nil {
			return err
		}
	}

	if expression.GetRuleEnumeration() != nil {
		if err := rule.serializeRuleEnumeration(condition, expression.RuleEnumeration); err != nil {
			return err
		}
	}

	if expression.GetRange() != nil {
		if _, err := condition.WriteString(" in "); err != nil {
			return err
		}
		if err := rule.serializeRange(condition, expression.Range); err != nil {
			return err
		}
	}

	if expression.GetAt() != nil {
		if _, err := condition.WriteString(" at "); err != nil {
			return err
		}
		if err := rule.evaluateExpression(condition, expression.At); err != nil {
			return err
		}
	}

	if expression.GetExpression() != nil {
		if _, err := condition.WriteString(" : ("); err != nil {
			return err
		}

		if err := rule.evaluateExpression(condition, expression.Expression); err != nil {
			return err
		}

		if _, err := condition.WriteString(")"); err != nil {
			return err
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeStringSet(condition *strings.Builder, expression *pb.StringSet) error {
	switch val := expression.GetSet().(type) {
	case *pb.StringSet_Strings:
		return rule.serializeStringEnumeration(condition, expression.GetStrings())
	case *pb.StringSet_Keyword:
		return rule.serializeStringSetKeyword(condition, expression.GetKeyword())
	default:
		return fmt.Errorf(`unsupported StringSet value type "%s"`, val)
	}
}

func (rule RuleEvaluator) serializeStringEnumeration(condition *strings.Builder, expression *pb.StringEnumeration) error {
	if _, err := condition.WriteString("("); err != nil {
		return err
	}

	for i, item := range expression.GetItems() {
		if _, err := condition.WriteString(item.GetStringIdentifier()); err != nil {
			return err
		}
		if i < len(expression.GetItems())-1 {
			if _, err := condition.WriteString(", "); err != nil {
				return err
			}
		}
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) serializeStringSetKeyword(condition *strings.Builder, expression pb.StringSetKeyword) error {
	kw, ok := stringSetKeywords[expression]
	if !ok {
		return fmt.Errorf(`unknown keyword "%v"`, expression)
	}

	if _, err := condition.WriteString(kw); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) serializeRuleEnumeration(condition *strings.Builder, expression *pb.RuleEnumeration) error {
	if _, err := condition.WriteString("("); err != nil {
		return err
	}

	for i, item := range expression.GetItems() {
		if _, err := condition.WriteString(item.GetRuleIdentifier()); err != nil {
			return err
		}
		if i < len(expression.GetItems())-1 {
			if _, err := condition.WriteString(", "); err != nil {
				return err
			}
		}
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}
	return nil
}
