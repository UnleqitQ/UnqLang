#include <iostream>

#include "compiler/lexer.hpp"
#include "compiler/ast.hpp"
#include "compiler/compiler.hpp"

int main() {
	std::string source_code = R"(
struct Point {
	int x;
	int y;
	char[2] padding;
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
	program.print();
	compiler::Compiler compiler (program);
	std::cout << "Deduced size of int: " << compiler.deduce_type_size(std::make_shared<compiler::ast_type_node>(compiler::ast_type_node::type_t::Int, std::monostate{})) << " bytes" << std::endl;
	std::cout << "Deduced size of Point: " << compiler.deduce_type_size(std::make_shared<compiler::ast_type_node>(compiler::ast_type_node::type_t::Custom, std::string("Point"))) << " bytes" << std::endl;
	return 0;
}
