package yevaluator

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/VirusTotal/gyp/pb"
	"github.com/mtnmunuklu/alterix/yara/yevaluator/modifiers"
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

var keywords = map[pb.Keyword]string{
	pb.Keyword_ENTRYPOINT: "entrypoint",
	pb.Keyword_FILESIZE:   "filesize",
}

var forKeywords = map[pb.ForKeyword]string{
	pb.ForKeyword_NONE: "none",
	pb.ForKeyword_ALL:  "all",
	pb.ForKeyword_ANY:  "any",
}

var stringSetKeywords = map[pb.StringSetKeyword]string{
	pb.StringSetKeyword_THEM: "them",
}

var unaryOperators = map[pb.UnaryExpression_Operator]string{
	pb.UnaryExpression_BITWISE_NOT: "~",
	pb.UnaryExpression_UNARY_MINUS: "-",
	pb.UnaryExpression_DEFINED:     "defined",
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

func (rule RuleEvaluator) evaluateMeta(metaValue *strings.Builder, meta *pb.Meta) error {
	switch val := meta.GetValue().(type) {
	case *pb.Meta_Text:
		metaValue.WriteString(meta.GetText())
	case *pb.Meta_Number:
		metaValue.WriteString(fmt.Sprintf(`%v`, meta.GetNumber()))
	case *pb.Meta_Boolean:
		metaValue.WriteString(fmt.Sprintf(`%v`, meta.GetBoolean()))
	default:
		return fmt.Errorf(`unsupported meta value type "%T"`, val)
	}

	return nil
}

func (rule RuleEvaluator) evaluateStrings(filter *strings.Builder, identifier string, str *pb.String) error {
	switch val := str.GetValue().(type) {
	case *pb.String_Text:
		// Process TextString value
		return rule.processTextString(filter, str.GetText(), identifier)

	case *pb.String_Hex:
		// Process Hex value
		return rule.processHex(filter, str.GetHex(), identifier)

	case *pb.String_Regexp:
		// Process Regexp value
		return rule.processRegexp(filter, str.GetRegexp(), identifier)

	default:
		return fmt.Errorf(`unsupported string value type "%T"`, val)
	}
}
func (rule RuleEvaluator) processTextString(filter *strings.Builder, text *pb.TextString, identifier string) error {
	// Extract fieldModifiers from textModifiers
	fieldModifiers, err := extractFieldModifiers(text.GetModifiers())
	if err != nil {
		return err
	}

	// Check if "Fullword" is present in the string list
	fieldModifiers = prioritizeFullword(fieldModifiers)

	// Get comparator function based on fieldModifiers
	comparator, err := modifiers.GetComparator(fieldModifiers...)
	if err != nil {
		return err
	}

	if len(rule.fieldmappings[identifier]) == 0 {
		err = rule.matchValue(filter, text.GetText(), []string{identifier}, comparator)
	} else {
		err = rule.matchValue(filter, text.GetText(), rule.fieldmappings[identifier], comparator)
	}

	if err != nil {
		return err
	}

	return nil
}

// Processes Hex value and returns the YARA filter
func (rule RuleEvaluator) processHex(filter *strings.Builder, hex *pb.HexTokens, identifier string) error {
	if _, err := filter.WriteString(identifier + " = "); err != nil {
		return err
	}
	if err := rule.serializeHexString(filter, hex); err != nil {
		return err
	}

	return nil
}

// Processes Regexp value and returns the YARA filter
func (rule RuleEvaluator) processRegexp(filter *strings.Builder, regexp *pb.Regexp, identifier string) error {
	if _, err := filter.WriteString(identifier + " = "); err != nil {
		return err
	}
	if err := rule.serializeRegexp(filter, regexp); err != nil {
		return err
	}

	return nil
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

func (rule *RuleEvaluator) matchValue(filter *strings.Builder, value string, fields []string, comparator modifiers.ComparatorFunc) error {
	var subFilter strings.Builder
	for i, field := range fields {
		ftr, err := comparator(field, value)
		if err != nil {
			return err
		}
		subFilter.WriteString(ftr)

		if i < len(fields)-1 {
			subFilter.WriteString(" or ")
		}
	}

	if len(fields) > 1 {
		// if there are multiple fields, wrap filters in parentheses to keep operator precedence
		filter.WriteString("(" + subFilter.String() + ")")
	} else {
		// if there's only one field, filters can be added directly
		filter.WriteString(subFilter.String())
	}

	return nil
}

func (rule RuleEvaluator) evaluateExpression(condition *strings.Builder, expression *pb.Expression) error {
	// Switch-case to check the type
	switch val := expression.GetExpression().(type) {
	case *pb.Expression_BoolValue:
		//fmt.Println("BoolValue:", v.BoolValue)
		if _, err := condition.WriteString(fmt.Sprintf("%v", expression.GetBoolValue())); err != nil {
			return err
		}
	case *pb.Expression_OrExpression:
		//fmt.Println("OrExpression:", v.OrExpression)
		if err := rule.serializeOrExpression(condition, expression.GetOrExpression()); err != nil {
			return err
		}
	case *pb.Expression_AndExpression:
		//fmt.Println("AndExpression:", v.AndExpression)
		if err := rule.serializeAndExpression(condition, expression.GetAndExpression()); err != nil {
			return err
		}
	case *pb.Expression_StringIdentifier:
		//fmt.Println("StringIdentifier:", v.StringIdentifier)
		if _, err := condition.WriteString(expression.GetStringIdentifier()); err != nil {
			return err
		}
	case *pb.Expression_ForInExpression:
		//fmt.Println("ForInExpression:", v.ForInExpression)
		if err := rule.serializeForInExpression(condition, expression.GetForInExpression()); err != nil {
			return err
		}
	case *pb.Expression_ForOfExpression:
		//fmt.Println("ForOfExpression:", v.ForOfExpression)
		var forOfCondition strings.Builder
		if err := rule.serializeForOfExpression(&forOfCondition, expression.GetForOfExpression()); err != nil {
			return err
		}
		if err := rule.processForOfCondition(&forOfCondition, condition, rule.getStringIdentifiers()); err != nil {
			return err
		}
	case *pb.Expression_BinaryExpression:
		//fmt.Println("BinaryExpression:", v.BinaryExpression)
		if err := rule.serializeBinaryExpression(condition, expression.GetBinaryExpression()); err != nil {
			return err
		}
	case *pb.Expression_UnaryExpression:
		//fmt.Println("UnaryExpression:", v.UnaryExpression)
		if err := rule.serializeUnaryExpression(condition, expression.GetUnaryExpression()); err != nil {
			return err
		}
	case *pb.Expression_NumberValue:
		//fmt.Println("NumberValue:", v.NumberValue)
		if _, err := condition.WriteString(fmt.Sprintf("%d", expression.GetNumberValue())); err != nil {
			return err
		}
	case *pb.Expression_Text:
		//fmt.Println("Text:", v.Text)
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
		//fmt.Println("DoubleValue:", v.DoubleValue)
		if _, err := condition.WriteString(fmt.Sprintf("%f", expression.GetDoubleValue())); err != nil {
			return err
		}
	case *pb.Expression_Range:
		//fmt.Println("Range:", v.Range)
		if err := rule.serializeRange(condition, expression.GetRange()); err != nil {
			return err
		}
	case *pb.Expression_Keyword:
		//fmt.Println("Keyword:", v.Keyword)
		if err := rule.serializeKeyword(condition, expression.GetKeyword()); err != nil {
			return err
		}
	case *pb.Expression_Identifier:
		//fmt.Println("Identifier:", v.Identifier)
		if err := rule.serializeIdentifier(condition, expression.GetIdentifier()); err != nil {
			return err
		}
	case *pb.Expression_Regexp:
		//fmt.Println("Regexp:", v.Regexp)
		if err := rule.serializeRegexp(condition, expression.GetRegexp()); err != nil {
			return err
		}
	case *pb.Expression_NotExpression:
		//fmt.Println("NotExpression:", v.NotExpression)
		if err := rule.serializeNotExpression(condition, expression.GetNotExpression()); err != nil {
			return err
		}
	case *pb.Expression_IntegerFunction:
		//fmt.Println("IntegerFunction:", v.IntegerFunction)
		if err := rule.serializeIntegerFunction(condition, expression.GetIntegerFunction()); err != nil {
			return err
		}
	case *pb.Expression_StringOffset:
		//fmt.Println("StringOffset:", v.StringOffset)
		if err := rule.serializeStringOffset(condition, expression.GetStringOffset()); err != nil {
			return err
		}
	case *pb.Expression_StringLength:
		//fmt.Println("StringLength:", v.StringLength)
		if err := rule.serializeStringLength(condition, expression.GetStringLength()); err != nil {
			return err
		}
	case *pb.Expression_StringCount:
		//fmt.Println("StringCount:", v.StringCount)
		if _, err := condition.WriteString(expression.GetStringCount()); err != nil {
			return err
		}
	case *pb.Expression_PercentageExpression:
		//fmt.Println("PercentageExpression:", v.PercentageExpression)
		if err := rule.serializePercentageExpression(condition, expression.GetPercentageExpression()); err != nil {
			return err
		}
	default:
		// If an unknown type is encountered, perform actions here
		return fmt.Errorf(`unsupported expression type "%T"`, val)
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
		if item.HasWildcard != nil && *item.HasWildcard {
			var matchesIdentifiers []string
			for _, str := range rule.Strings {
				matchesPattern, _ := path.Match(item.GetStringIdentifier(), "$"+str.GetIdentifier())
				if matchesPattern {
					matchesIdentifiers = append(matchesIdentifiers, "$"+str.GetIdentifier())
				}
			}
			if len(matchesIdentifiers) > 0 {
				if _, err := condition.WriteString(strings.Join(matchesIdentifiers, ", ")); err != nil {
					return err
				}
			} else if _, err := condition.WriteString(item.GetStringIdentifier()); err != nil {
				return err
			}

		} else if _, err := condition.WriteString(item.GetStringIdentifier()); err != nil {
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

func (rule RuleEvaluator) serializeUnaryExpression(condition *strings.Builder, expression *pb.UnaryExpression) error {
	op, ok := unaryOperators[expression.GetOperator()]
	if !ok {
		return fmt.Errorf(`unknown unary operator "%v"`, expression.GetOperator())
	}

	if _, err := condition.WriteString(op); err != nil {
		return err
	}

	// If the operator is "defined" it is followed by a space. Other unary
	// operators like "-" and "~" are immediately followed by the operand,
	// without any spaces in between.
	if expression.GetOperator() == pb.UnaryExpression_DEFINED {
		if _, err := condition.WriteString(" "); err != nil {
			return err
		}
	}

	return rule.evaluateExpression(condition, expression.GetExpression())
}

func (rule RuleEvaluator) serializeKeyword(condition *strings.Builder, expression pb.Keyword) error {
	kw, ok := keywords[expression]
	if !ok {
		return fmt.Errorf(`unknown keyword "%v"`, expression)
	}

	if _, err := condition.WriteString(kw); err != nil {
		return err
	}

	return nil
}

func (rule RuleEvaluator) serializeNotExpression(condition *strings.Builder, expression *pb.Expression) error {
	if _, err := condition.WriteString("not "); err != nil {
		return err
	}

	if getExpressionPrecedence(expression) < precedenceNotExpression {
		if _, err := condition.WriteString("("); err != nil {
			return err
		}
	}

	if err := rule.evaluateExpression(condition, expression); err != nil {
		return err
	}

	if getExpressionPrecedence(expression) < precedenceNotExpression {
		if _, err := condition.WriteString(")"); err != nil {
			return err
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeIntegerFunction(condition *strings.Builder, expression *pb.IntegerFunction) error {
	if _, err := condition.WriteString(expression.GetFunction()); err != nil {
		return err
	}

	if _, err := condition.WriteString("("); err != nil {
		return err
	}

	if err := rule.evaluateExpression(condition, expression.GetArgument()); err != nil {
		return err
	}

	if _, err := condition.WriteString(")"); err != nil {
		return err
	}

	return nil
}

func (rule RuleEvaluator) serializeStringOffset(condition *strings.Builder, expression *pb.StringOffset) error {

	if _, err := condition.WriteString(expression.GetStringIdentifier()); err != nil {
		return err
	}

	if expression.GetIndex() != nil {
		if _, err := condition.WriteString("["); err != nil {
			return err
		}
		if err := rule.evaluateExpression(condition, expression.GetIndex()); err != nil {
			return err
		}
		if _, err := condition.WriteString("]"); err != nil {
			return err
		}
	}

	return nil
}

func (rule RuleEvaluator) serializeStringLength(condition *strings.Builder, expression *pb.StringLength) error {

	if _, err := condition.WriteString(expression.GetStringIdentifier()); err != nil {
		return err
	}

	if expression.GetIndex() != nil {
		if _, err := condition.WriteString("["); err != nil {
			return err
		}
		if err := rule.evaluateExpression(condition, expression.GetIndex()); err != nil {
			return err
		}
		if _, err := condition.WriteString("]"); err != nil {
			return err
		}
	}

	return nil
}

func (rule RuleEvaluator) serializePercentageExpression(condition *strings.Builder, expression *pb.Percentage) error {
	if err := rule.evaluateExpression(condition, expression.Expression); err != nil {
		return err
	}
	if _, err := condition.WriteString("%"); err != nil {
		return err
	}
	return nil
}

func (rule RuleEvaluator) processForOfCondition(forOfCondition *strings.Builder, condition *strings.Builder, stringsList []string) error {
	switch forOfCondition.String() {
	case "any of them":
		return rule.processAnyOfThem(condition, stringsList)
	case "all of them":
		return rule.processAllOfThem(condition, stringsList)
	case "none of them":
		return rule.processNoneOfThem(condition, stringsList)
	default:
		if strings.HasPrefix(forOfCondition.String(), "all of (") {
			return rule.processComplexCondition(forOfCondition, condition, stringsList, rule.processAllOfThem)
		} else if strings.HasPrefix(forOfCondition.String(), "any of (") {
			return rule.processComplexCondition(forOfCondition, condition, stringsList, rule.processAnyOfThem)
		} else if strings.HasPrefix(forOfCondition.String(), "none of (") {
			return rule.processComplexCondition(forOfCondition, condition, stringsList, rule.processNoneOfThem)
		} else if strings.HasSuffix(forOfCondition.String(), "of them") {
			return rule.processNOfThemCondition(forOfCondition, condition, stringsList)
		} else if strings.Contains(forOfCondition.String(), "of (") && strings.HasSuffix(forOfCondition.String(), ")") {
			return rule.processNOfThemConditionWithParenthesis(forOfCondition, condition, stringsList)
		}
		condition.WriteString(forOfCondition.String())
		return nil
	}
}

func (rule RuleEvaluator) processAnyOfThem(condition *strings.Builder, stringsList []string) error {
	rule.processOr(condition, stringsList)
	return nil
}

func (rule RuleEvaluator) processAllOfThem(condition *strings.Builder, stringsList []string) error {
	rule.processAnd(condition, stringsList)
	return nil
}

func (rule RuleEvaluator) processNoneOfThem(condition *strings.Builder, stringsList []string) error {
	condition.WriteString("not ")
	rule.processAnd(condition, stringsList)
	return nil
}

func (rule RuleEvaluator) processNOfThemCondition(forOfCondition, condition *strings.Builder, stringsList []string) error {
	numStr := forOfCondition.String()
	if ofIndex := strings.Index(numStr, " "); ofIndex > 0 {
		numStr = numStr[:ofIndex]
		if num, err := strconv.Atoi(numStr); err == nil {
			if num <= len(stringsList) && num > 0 {
				rule.processNOfThem(num, condition, stringsList)
				return nil
			} else if num == 0 {
				return fmt.Errorf("'of them' number must be greater than 0")
			} else {
				return fmt.Errorf("number in 'of them' is greater than the size of the string identifier list")
			}
		}
	}
	condition.WriteString(forOfCondition.String())
	return nil
}

func (rule RuleEvaluator) processNOfThemConditionWithParenthesis(forOfCondition, condition *strings.Builder, stringsList []string) error {
	openIndex := strings.Index(forOfCondition.String(), "(")
	closeIndex := strings.LastIndex(forOfCondition.String(), ")")
	if openIndex < 0 || closeIndex < 0 || closeIndex < openIndex {
		return fmt.Errorf("malformed condition: %s", forOfCondition.String())
	}

	numStr := forOfCondition.String()
	//fmt.Println(numStr)

	if ofIndex := strings.Index(numStr, " "); ofIndex > 0 {
		numStr = numStr[:ofIndex]
		if num, err := strconv.Atoi(numStr); err == nil {
			// Extract the content within the parentheses
			content := forOfCondition.String()[openIndex+1 : closeIndex]

			// Split the content into a list of strings
			subStringsList, err := rule.parseComplexCondition(content, stringsList)
			if err != nil {
				return err
			}

			// Process the condition based on the extracted list
			rule.processNOfThem(num, condition, subStringsList)
			return nil
		}
	}
	condition.WriteString(forOfCondition.String())
	return nil
}

func (rule RuleEvaluator) processOr(condition *strings.Builder, stringsList []string) {
	var result strings.Builder
	result.WriteString("(")

	for _, str := range stringsList {
		result.WriteString(str)
		result.WriteString(" or ")
	}

	resultStr := result.String()
	resultStr = resultStr[:len(resultStr)-4]

	condition.WriteString(resultStr)
	condition.WriteString(")")
}

func (rule RuleEvaluator) processAnd(condition *strings.Builder, stringsList []string) {
	var result strings.Builder
	result.WriteString("(")

	for i, str := range stringsList {
		result.WriteString(str)
		if i < len(stringsList)-1 {
			result.WriteString(" and ")
		}
	}

	resultStr := result.String()
	condition.WriteString(resultStr)
	condition.WriteString(")")
}

func (rule RuleEvaluator) processComplexCondition(forOfCondition, condition *strings.Builder, stringsList []string, processor func(*strings.Builder, []string) error) error {
	openIndex := strings.Index(forOfCondition.String(), "(")
	closeIndex := strings.LastIndex(forOfCondition.String(), ")")
	if openIndex < 0 || closeIndex < 0 || closeIndex < openIndex {
		return fmt.Errorf("malformed condition: %s", forOfCondition.String())
	}

	subCondition := forOfCondition.String()[openIndex+1 : closeIndex]
	subCondition = rule.cleanCondition(subCondition)

	subStringsList, err := rule.parseComplexCondition(subCondition, stringsList)
	if err != nil {
		return err
	}

	return processor(condition, subStringsList)
}

func (rule RuleEvaluator) parseComplexCondition(condition string, stringsList []string) ([]string, error) {
	parts := strings.Split(condition, ",")
	var result []string

	for _, part := range parts {
		part = rule.cleanCondition(part)
		found := false
		for _, str := range stringsList {
			if part == str {
				result = append(result, str)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("string identifier '%s' not found in the list", part)
		}
	}

	return result, nil
}

func (rule RuleEvaluator) processNOfThem(num int, condition *strings.Builder, stringsList []string) {
	if num == 1 {
		rule.processAnyOfThem(condition, stringsList)
	} else if num == len(stringsList) {
		rule.processAllOfThem(condition, stringsList)
	} else {
		rule.processCombination(num, condition, stringsList)
	}
}

func (rule RuleEvaluator) processCombination(num int, condition *strings.Builder, stringsList []string) {
	keys := make([]string, 0, len(stringsList))
	keys = append(keys, stringsList...)
	sort.Strings(keys)

	var combinations []string
	rule.generateCombination(num, keys, 0, "", &combinations)

	condition.WriteString("(")

	for i, combination := range combinations {
		if i > 0 {
			condition.WriteString(" or ")
		}
		var andBuilder strings.Builder
		andBuilder.WriteString("(")
		for i, strIndex := range combination {
			index, _ := strconv.Atoi(string(strIndex))
			andBuilder.WriteString(stringsList[index])
			if i < len(combination)-1 {
				andBuilder.WriteString(" and ")
			}
		}
		andBuilder.WriteString(")")
		condition.WriteString(andBuilder.String())

	}

	condition.WriteString(")")
}

func (rule RuleEvaluator) generateCombination(num int, keys []string, index int, current string, combinations *[]string) {
	if num == 0 {
		*combinations = append(*combinations, current)
		return
	}

	for i := index; i <= len(keys)-num; i++ {
		rule.generateCombination(num-1, keys, i+1, current+strconv.Itoa(i), combinations)
	}
}

func (rule RuleEvaluator) cleanCondition(condition string) string {
	return strings.ReplaceAll(condition, " ", "")
}

func (rule RuleEvaluator) getStringIdentifiers() []string {
	var identifiers []string

	for _, str := range rule.Strings {
		identifiers = append(identifiers, "$"+str.GetIdentifier())
	}

	return identifiers
}
