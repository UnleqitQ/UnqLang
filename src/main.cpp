#include <iostream>

#include "compiler/lexer.hpp"
#include "compiler/ast.hpp"

int main() {
	std::string source_code = R"(
struct Point {
	int x;
	int y;
};

int main(int a) {
	Point p;
	p.x = 10;
	p.y = 20;
	if (p.x < p.y) {
		return p.x;
	} else {
		return p.y;
	}
	return 0;
}
)";
	std::cout << "Source Code:\n" << source_code << std::endl;
	auto tokens = compiler::run_lexer(source_code);
	std::vector<compiler::lexer_token> filtered_tokens;
	filtered_tokens.reserve(tokens.size());
	for (const auto& token : tokens) {
		std::cout << token << std::endl;
		if (token.type != compiler::lexer_token::type_t::Comment) {
			filtered_tokens.push_back(token);
		}
	}
	auto program = compiler::parse_ast_program(filtered_tokens);
	std::cout << program << std::endl;
	program.print();
	return 0;
}
