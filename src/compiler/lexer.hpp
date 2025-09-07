#pragma once

#include <string>
#include <vector>
#include <cctype>
#include <variant>

namespace compiler {
	struct lexer_token {
		enum class type_t {
			Identifier,
			Integer,
			// Float,
			// String,
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
			char // For Operator, Punctuation
		> value;
		friend std::ostream& operator<<(std::ostream& os, const lexer_token& tok);
	};

	std::vector<lexer_token> run_lexer(const std::string& source);
} // compiler
