#pragma once

#include <string>
#include <vector>
#include <variant>
#include <iostream>
#include <format>

namespace compiler {
	enum class operator_type_t : uint8_t {
		Plus, // +
		Minus, // -
		Asterisk, // *
		Slash, // /
		Percent, // %
		Exclamation, // !
		Question, // ?
		Arrow, // ->
		LessThan, // <
		GreaterThan, // >
		ShiftLeft, // <<
		ShiftRight, // >>
		Ampersand, // &
		Pipe, // |
		Caret, // ^
		Tilde, // ~
		PlusPlus, // ++
		MinusMinus, // --
		EqualEqual, // ==
		NotEqual, // !=
		LessEqual, // <=
		GreaterEqual, // >=
		LogicalAnd, // &&
		LogicalOr, // ||
		Equal, // =
		Unknown
	};
	enum class punctuation_type_t {
		LeftParen, // (
		RightParen, // )
		LeftBrace, // {
		RightBrace, // }
		LeftBracket, // [
		RightBracket, // ]
		Semicolon, // ;
		Comma, // ,
		Dot, // .
		Colon, // :
		Unknown
	};
	struct lexer_token {
		enum class type_t {
			Identifier,
			Integer,
			Float,
			String,
			Operator,
			Punctuation,
			Keyword,
			Comment,
			Unknown
		} type;
		std::variant<
			std::string, // For Identifier, String, Keyword (also for Unknown)
			int, // For Integer
			// double, // For Float
			punctuation_type_t, // For Punctuation
			operator_type_t // For Operator
		> value;
		friend std::ostream& operator<<(std::ostream& os, const lexer_token& tok);
	};

	inline std::ostream& operator<<(std::ostream& os, const operator_type_t& op) {
		switch (op) {
			case operator_type_t::Plus: return os << "+";
			case operator_type_t::Minus: return os << "-";
			case operator_type_t::Asterisk: return os << "*";
			case operator_type_t::Slash: return os << "/";
			case operator_type_t::Percent: return os << "%";
			case operator_type_t::Exclamation: return os << "!";
			case operator_type_t::Question: return os << "?";
			case operator_type_t::Arrow: return os << "->";
			case operator_type_t::LessThan: return os << "<";
			case operator_type_t::GreaterThan: return os << ">";
			case operator_type_t::ShiftLeft: return os << "<<";
			case operator_type_t::ShiftRight: return os << ">>";
			case operator_type_t::Ampersand: return os << "&";
			case operator_type_t::Pipe: return os << "|";
			case operator_type_t::Caret: return os << "^";
			case operator_type_t::Tilde: return os << "~";
			case operator_type_t::PlusPlus: return os << "++";
			case operator_type_t::MinusMinus: return os << "--";
			case operator_type_t::EqualEqual: return os << "==";
			case operator_type_t::NotEqual: return os << "!=";
			case operator_type_t::LessEqual: return os << "<=";
			case operator_type_t::GreaterEqual: return os << ">=";
			case operator_type_t::LogicalAnd: return os << "&&";
			case operator_type_t::LogicalOr: return os << "||";
			case operator_type_t::Equal: return os << "=";
			default: return os << "UnknownOperator";
		}
	}
	inline std::ostream& operator<<(std::ostream& os, const punctuation_type_t& punc) {
		switch (punc) {
			case punctuation_type_t::LeftParen: return os << "(";
			case punctuation_type_t::RightParen: return os << ")";
			case punctuation_type_t::LeftBrace: return os << "{";
			case punctuation_type_t::RightBrace: return os << "}";
			case punctuation_type_t::LeftBracket: return os << "[";
			case punctuation_type_t::RightBracket: return os << "]";
			case punctuation_type_t::Semicolon: return os << ";";
			case punctuation_type_t::Comma: return os << ",";
			case punctuation_type_t::Dot: return os << ".";
			case punctuation_type_t::Colon: return os << ":";
			default: return os << "UnknownPunctuation";
		}
	}

	operator_type_t lexer_parse_operator_type(const std::string& op_str);
	punctuation_type_t lexer_parse_punctuation_type(char punc);

	std::vector<lexer_token> run_lexer(const std::string& source);
} // compiler

template<>
struct std::formatter<compiler::operator_type_t> : std::formatter<std::string> {
	auto format(const compiler::operator_type_t& op, format_context& ctx) const {
		std::string op_str;
		switch (op) {
			case compiler::operator_type_t::Plus: op_str = "+";
				break;
			case compiler::operator_type_t::Minus: op_str = "-";
				break;
			case compiler::operator_type_t::Asterisk: op_str = "*";
				break;
			case compiler::operator_type_t::Slash: op_str = "/";
				break;
			case compiler::operator_type_t::Percent: op_str = "%";
				break;
			case compiler::operator_type_t::Exclamation: op_str = "!";
				break;
			case compiler::operator_type_t::Question: op_str = "?";
				break;
			case compiler::operator_type_t::Arrow: op_str = "->";
				break;
			case compiler::operator_type_t::LessThan: op_str = "<";
				break;
			case compiler::operator_type_t::GreaterThan: op_str = ">";
				break;
			case compiler::operator_type_t::ShiftLeft: op_str = "<<";
				break;
			case compiler::operator_type_t::ShiftRight: op_str = ">>";
				break;
			case compiler::operator_type_t::Ampersand: op_str = "&";
				break;
			case compiler::operator_type_t::Pipe: op_str = "|";
				break;
			case compiler::operator_type_t::Caret: op_str = "^";
				break;
			case compiler::operator_type_t::Tilde: op_str = "~";
				break;
			case compiler::operator_type_t::PlusPlus: op_str = "++";
				break;
			case compiler::operator_type_t::MinusMinus: op_str = "--";
				break;
			case compiler::operator_type_t::EqualEqual: op_str = "==";
				break;
			case compiler::operator_type_t::NotEqual: op_str = "!=";
				break;
			case compiler::operator_type_t::LessEqual: op_str = "<=";
				break;
			case compiler::operator_type_t::GreaterEqual: op_str = ">=";
				break;
			case compiler::operator_type_t::LogicalAnd: op_str = "&&";
				break;
			case compiler::operator_type_t::LogicalOr: op_str = "||";
				break;
			case compiler::operator_type_t::Equal: op_str = "=";
				break;
			default: op_str = "UnknownOperator";
				break;
		}
		return std::formatter<std::string, char>::format(op_str, ctx);
	}
};
template<>
struct std::formatter<compiler::punctuation_type_t> : std::formatter<std::string> {
	auto format(const compiler::punctuation_type_t& punc, format_context& ctx) const {
		std::string punc_str;
		switch (punc) {
			case compiler::punctuation_type_t::LeftParen: punc_str = "(";
				break;
			case compiler::punctuation_type_t::RightParen: punc_str = ")";
				break;
			case compiler::punctuation_type_t::LeftBrace: punc_str = "{";
				break;
			case compiler::punctuation_type_t::RightBrace: punc_str = "}";
				break;
			case compiler::punctuation_type_t::LeftBracket: punc_str = "[";
				break;
			case compiler::punctuation_type_t::RightBracket: punc_str = "]";
				break;
			case compiler::punctuation_type_t::Semicolon: punc_str = ";";
				break;
			case compiler::punctuation_type_t::Comma: punc_str = ",";
				break;
			case compiler::punctuation_type_t::Dot: punc_str = ".";
				break;
			case compiler::punctuation_type_t::Colon: punc_str = ":";
				break;
			default: punc_str = "UnknownPunctuation";
				break;
		}
		return std::formatter<std::string, char>::format(punc_str, ctx);
	}
};
