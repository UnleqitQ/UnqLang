#include "lexer.hpp"
#include <iostream>
#include "../parser.hpp"

namespace unqlang {
	operator_type_t lexer_parse_operator_type(const std::string& op_str) {
		if (op_str == "+") return operator_type_t::Plus;
		if (op_str == "-") return operator_type_t::Minus;
		if (op_str == "*") return operator_type_t::Asterisk;
		if (op_str == "/") return operator_type_t::Slash;
		if (op_str == "%") return operator_type_t::Percent;
		if (op_str == "!") return operator_type_t::Exclamation;
		if (op_str == "?") return operator_type_t::Question;
		if (op_str == "->") return operator_type_t::Arrow;
		if (op_str == "<") return operator_type_t::LessThan;
		if (op_str == ">") return operator_type_t::GreaterThan;
		if (op_str == "<<") return operator_type_t::ShiftLeft;
		if (op_str == ">>") return operator_type_t::ShiftRight;
		if (op_str == "&") return operator_type_t::Ampersand;
		if (op_str == "|") return operator_type_t::Pipe;
		if (op_str == "^") return operator_type_t::Caret;
		if (op_str == "~") return operator_type_t::Tilde;
		if (op_str == "++") return operator_type_t::PlusPlus;
		if (op_str == "--") return operator_type_t::MinusMinus;
		if (op_str == "==") return operator_type_t::EqualEqual;
		if (op_str == "!=") return operator_type_t::NotEqual;
		if (op_str == "<=") return operator_type_t::LessEqual;
		if (op_str == ">=") return operator_type_t::GreaterEqual;
		if (op_str == "&&") return operator_type_t::LogicalAnd;
		if (op_str == "||") return operator_type_t::LogicalOr;
		if (op_str == "=") return operator_type_t::Equal;
		return operator_type_t::Unknown;
	}
	punctuation_type_t lexer_parse_punctuation_type(char punc) {
		switch (punc) {
			case '(': return punctuation_type_t::LeftParen;
			case ')': return punctuation_type_t::RightParen;
			case '{': return punctuation_type_t::LeftBrace;
			case '}': return punctuation_type_t::RightBrace;
			case '[': return punctuation_type_t::LeftBracket;
			case ']': return punctuation_type_t::RightBracket;
			case ';': return punctuation_type_t::Semicolon;
			case ',': return punctuation_type_t::Comma;
			case '.': return punctuation_type_t::Dot;
			case ':': return punctuation_type_t::Colon;
			default: return punctuation_type_t::Unknown;
		}
	}

	const Parser<char, lexer_token> sl_comment_lexer = (token("//") > *(satisfy<char>([](char c) { return c != '\n'; },
			"not-newline")) < (symbol('\n') || parse_eof<char, char>('\0')))
		.map<lexer_token>([](const std::vector<char>& comment_chars) {
			std::string comment_str(comment_chars.begin(), comment_chars.end());
			return lexer_token{lexer_token::type_t::Comment, comment_str};
		}, "single-line-comment");
	const Parser<char, lexer_token> ml_comment_lexer = (token("/*") > Parser<char, std::vector<char>>(
			[](const std::vector<char>& input, std::vector<std::pair<std::vector<char>, size_t>>& output, ParserTable&) {
				size_t pos = 0;
				while (pos < input.size()) {
					if (pos + 1 < input.size() && input[pos] == '*' && input[pos + 1] == '/') {
						// End of comment
						output.emplace_back(std::vector<char>(input.begin(), input.begin() + pos), pos);
						return;
					}
					pos++;
				}
				// If we reach here, we didn't find the closing */
				// So we don't produce any output (indicating failure)
			}, "comment-body") < token("*/"))
		.map<lexer_token>([](const std::vector<char>& comment_chars) {
			std::string comment_str(comment_chars.begin(), comment_chars.end());
			return lexer_token{lexer_token::type_t::Comment, comment_str};
		}, "multi-line-comment");
	const Parser<char, lexer_token> comment_lexer = sl_comment_lexer || ml_comment_lexer;
	const Parser<char, int> hex_lexer = (token("0x") + +(symbol_range('0', '9') | symbol_range('a', 'f') |
			symbol_range('A', 'F')))
		.map<int>([](const std::pair<std::vector<char>, std::vector<char>>& p) {
			std::string hex_str(p.second.begin(), p.second.end());
			return std::stoi(hex_str, nullptr, 16);
		}, "hex");
	const Parser<char, int> decimal_lexer = (+symbol_range('0', '9'))
		.map<int>([](const std::vector<char>& digits) {
			std::string dec_str(digits.begin(), digits.end());
			return std::stoi(dec_str);
		}, "dec");
	const Parser<char, int> char_lexer = (symbol('\'') >
			(
				(symbol('\\') + satisfy<char>([](char c) { return true; }, "any")).map<char>(
					[](const std::pair<char, char>& p) {
						switch (p.second) {
							case 'n': return '\n';
							case 'r': return '\r';
							case 't': return '\t';
							case '\\': return '\\';
							case '\'': return '\'';
							default: return p.second; // Unknown escape, just return the char itself
						}
					}, "escape") ||
				satisfy<char>([](char c) { return c != '\''; }, "non-quote")
			) < symbol('\''))
		.map<int>([](char c) {
			return static_cast<int>(c);
		}, "char");
	const Parser<char, lexer_token> integer_lexer = (hex_lexer || decimal_lexer || char_lexer)
		.map<lexer_token>([](int value) {
			return lexer_token{lexer_token::type_t::Integer, value};
		}, "integer");
	// float is skipped for now
	const Parser<char, lexer_token> identifier_lexer = ((symbol_range('a', 'z') | symbol_range('A', 'Z') | symbol('_')) +
			*(symbol_range('a', 'z') | symbol_range('A', 'Z') | symbol_range('0', '9') | symbol('_')))
		.map<lexer_token>([](const std::pair<char, std::vector<char>>& p) {
			std::string id_str;
			id_str.push_back(p.first);
			id_str.append(p.second.begin(), p.second.end());
			return lexer_token{lexer_token::type_t::Identifier, id_str};
		}, "identifier");
	const Parser<char, lexer_token> string_lexer = (symbol('"') >
			*(
				(symbol('\\') + satisfy<char>([](char c) { return true; }, "any")).map<char>(
					[](const std::pair<char, char>& p) {
						switch (p.second) {
							case 'n': return '\n';
							case 'r': return '\r';
							case 't': return '\t';
							case '\\': return '\\';
							case '"': return '"';
							default: return p.second; // Unknown escape, just return the char itself
						}
					}, "escape") ||
				satisfy<char>([](char c) { return c != '"'; }, "non-quote")
			) < symbol('"'))
		.map<lexer_token>([](const std::vector<char>& p) {
			std::string str(p.begin(), p.end());
			return lexer_token{lexer_token::type_t::String, str};
		}, "string");
	std::vector<std::string> operator_strings = {
		"++", "--", "==", "!=", "<<", ">>", "<=", ">=", "&&", "||", "+", "-", "*", "/", "%", "=", "<", ">", "!", "&", "|",
		"^", "~"
	};
	const Parser<char, lexer_token> operator_lexer = tokens(operator_strings, "operators", false, true)
		.map<lexer_token>([](const std::vector<char>& op) {
			std::string op_str(op.begin(), op.end());
			return lexer_token{lexer_token::type_t::Operator, lexer_parse_operator_type(op_str)};
		}, "operator");
	std::vector<char> punctuation_chars = {
		'(', ')', '{', '}', '[', ']', ';', ',', '.', ':'
	};
	const Parser<char, lexer_token> punctuation_lexer = symbols(punctuation_chars, "punctuation")
		.map<lexer_token>([](char punc) {
			return lexer_token{lexer_token::type_t::Punctuation, lexer_parse_punctuation_type(punc)};
		}, "punctuation");
	std::vector<std::string> keyword_strings = {
		"if",
		"else",
		"while",
		"for",
		"return",
		"int",
		// "float",
		"char",
		"bool",
		"void",

		"struct",
		"union",
		"typedef",
		"break",
		"continue",
		"sizeof",
		"true",
		"false"
	};
	const Parser<char, lexer_token> keyword_lexer = tokens(keyword_strings, "keywords", false, true)
		.map<lexer_token>([](const std::vector<char>& kw) {
			std::string kw_str(kw.begin(), kw.end());
			return lexer_token{lexer_token::type_t::Keyword, kw_str};
		}, "keyword");
	const Parser<char, std::monostate> whitespace_lexer = (*symbols(std::vector<char>{' ', '\t', '\n', '\r'},
			"whitespace"))
		.map<std::monostate>([](const std::vector<char>&) {
			// Ignore whitespace
			return std::monostate{};
		}, "whitespace");

	const Parser<char, lexer_token> any_lexer =
		comment_lexer ||
		keyword_lexer ||
		identifier_lexer ||
		integer_lexer ||
		string_lexer ||
		operator_lexer ||
		punctuation_lexer;
	const Parser<char, std::vector<lexer_token>> lexer_parser = *(whitespace_lexer > any_lexer);

	std::vector<lexer_token> run_lexer(const std::string& source) {
		std::vector<char> input(source.begin(), source.end());
		std::vector<std::pair<std::vector<lexer_token>, size_t>> output;
		ParserTable table;
		lexer_parser.parse(input, output, table);
		if (output.empty()) {
			return {};
		}
		// Just take the first successful parse that consumed the most input
		auto best_parse = std::ranges::max_element(output,
			[](const auto& a, const auto& b) {
				return a.second < b.second;
			});
		return best_parse->first;
	}

	std::ostream& operator<<(std::ostream& os, const lexer_token& tok) {
		os << "Token(Type: ";
		switch (tok.type) {
			case lexer_token::type_t::Identifier:
				os << "Identifier, Value: " << std::get<std::string>(tok.value);
				break;
			case lexer_token::type_t::Integer:
				os << "Integer, Value: " << std::get<int>(tok.value);
				break;
			case lexer_token::type_t::Float:
				//os << "Float, Value: " << std::get<double>(tok.value);
				break;
			case lexer_token::type_t::String:
				os << "String, Value: \"" << std::get<std::string>(tok.value) << "\"";
				break;
			case lexer_token::type_t::Operator:
				os << "Operator, Value: '" << std::get<operator_type_t>(tok.value) << "'";
				break;
			case lexer_token::type_t::Punctuation:
				os << "Punctuation, Value: '" << std::get<punctuation_type_t>(tok.value) << "'";
				break;
			case lexer_token::type_t::Keyword:
				os << "Keyword, Value: " << std::get<std::string>(tok.value);
				break;
			case lexer_token::type_t::Comment:
				os << "Comment, Value: \"" << std::get<std::string>(tok.value) << "\"";
				break;
			case lexer_token::type_t::Unknown:
				os << "Unknown, Value: " << std::get<std::string>(tok.value);
				break;
		}
		os << ")";
		return os;
	}
} // compiler
