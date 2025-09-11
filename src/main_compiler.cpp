#include <chrono>
#include <iostream>
#include <typeinfo>

#include "unqlang/lexer.hpp"
#include "unqlang/ast.hpp"

void build_ast(const std::string& source_code, unqlang::ast_program& out_program) {
	auto tokens = unqlang::run_lexer(source_code);
	std::vector<unqlang::lexer_token> filtered_tokens;
	filtered_tokens.reserve(tokens.size());
	for (const auto& token : tokens) {
		if (token.type != unqlang::lexer_token::type_t::Comment) {
			filtered_tokens.push_back(token);
		}
	}
	try {
		out_program = unqlang::parse_ast_program(filtered_tokens);
	}
	catch (const std::exception& e) {
		std::cerr << "Error parsing AST: " << e.what() << std::endl;
		throw;
	}
}

int main() {
	std::string source_code = R"(
int multi_fibonacci(int n, int d, int e) {
	if (n <= d) {
		return 1;
	}
	else {
		int i = 0;
		int result = 0;
		while ((i < e) && (i + d < n)) {
			result = result + multi_fibonacci(n - d - i, d, e);
			++i;
		}
		return result;
	}
}

int main(int n, int d, int e) {
	int result = multi_fibonacci(n, d, e);
	puts("multi_fibonacci(");
	puti(n);
	puts(", ");
	puti(d);
	puts(", ");
	puti(e);
	puts(") = ");
	puti(result);
	puts("\n");
	return 0;
}
)";
	unqlang::ast_program program;
	try {
		build_ast(source_code, program);
	}
	catch (const std::exception& e) {
		std::cerr << "Error building AST: " << e.what() << std::endl;
		return 1;
	}
	program.print();

	std::cout << std::endl << "AST built successfully." << std::endl << std::endl;
	std::cout << std::string(80, '=') << std::endl << std::endl;

	return 0;
}
