#include <iostream>

#include "compiler/lexer.hpp"

int main() {
	std::string source_code = R"(int main() {
		/* This is a comment */
		printf("Hello, World!\n");
		/* Another comment */
		return 0;
	})";
	auto tokens = compiler::run_lexer(source_code);
	for (const auto& token : tokens) {
		std::cout << token << std::endl;
	}
	return 0;
}
