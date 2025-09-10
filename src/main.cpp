#include <chrono>
#include <iostream>
#include <typeinfo>
#include <type_traits>

#include "compiler/lexer.hpp"
#include "compiler/ast.hpp"
#include "compiler/ast_helpers.hpp"
#include "compiler/ast_interpreter.hpp"
#include "compiler/compiler.hpp"


template<typename T>
constexpr void analyze_type() {
	std::string name = typeid(T).name();
	std::cout << "C++ Type: " << name << std::endl;
	if constexpr (std::is_same_v<T, void>) {
		std::cout << "  Type: void" << std::endl;
	}
	else if constexpr (std::is_same_v<T, int32_t>) {
		std::cout << "  Type: int32_t" << std::endl;
	}
	else if constexpr (std::is_same_v<T, char>) {
		std::cout << "  Type: char" << std::endl;
	}
	else if constexpr (std::is_same_v<T, bool>) {
		std::cout << "  Type: bool" << std::endl;
	}
	else if constexpr (std::is_pointer_v<T>) {
		using base_t = std::remove_pointer_t<T>;
		std::cout << "  Type: pointer to" << std::endl;
		std::cout << "    C++ Type: " << typeid(base_t).name() << std::endl;
		// don't recurse into pointers to avoid infinite recursion
	}
	else if constexpr (std::is_array_v<T>) {
		using base_t = std::remove_extent_t<T>;
		constexpr size_t array_size = std::extent_v<T>;
		std::cout << "  Type: array of size " << array_size << " of" << std::endl;
		analyze_type<base_t>();
	}
	else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
		std::cout << "  Type: string (represented as char pointer)" << std::endl;
	}
	else if constexpr (std::is_class_v<T>) {
		std::cout << "  Type: struct/class" << std::endl;
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
	std::chrono::high_resolution_clock::time_point start_time = std::chrono::high_resolution_clock::now();
	std::cout << "Source Code:\n" << source_code << std::endl;
	auto tokens = compiler::run_lexer(source_code);
	std::vector<compiler::lexer_token> filtered_tokens;
	filtered_tokens.reserve(tokens.size());
	for (const auto& token : tokens) {
		if (token.type != compiler::lexer_token::type_t::Comment) {
			filtered_tokens.push_back(token);
		}
	}
	compiler::ast_program program;
	try {
		program = compiler::parse_ast_program(filtered_tokens);
	}
	catch (const std::exception& e) {
		std::cerr << "Error parsing AST: " << e.what() << std::endl;
		return 1;
	}
	program.print();
	compiler::interpreter::ast_interpreter interpreter;

	// Register external functions
	// puts(char*): void
	// puti(int): void
	std::vector<std::string> output_buffer; {
		interpreter.register_external_function(compiler::interpreter::external_function{
			"puts",
			std::make_shared<compiler::analysis::types::type_node>(compiler::analysis::types::primitive_type::VOID),
			{
				std::make_shared<compiler::analysis::types::type_node>(
					compiler::analysis::types::pointer_type{
						compiler::analysis::types::primitive_type::CHAR
					})
			},
			[&output_buffer](const std::vector<compiler::interpreter::value_t>& args,
			compiler::interpreter::ast_interpreter& interpreter) -> compiler::interpreter::value_t {
				if (args.size() != 1) {
					throw std::runtime_error("puts expects 1 argument");
				}
				const auto& str_value = args[0];
				if (str_value.type->kind != compiler::analysis::types::type_node::kind_t::POINTER ||
					std::get<compiler::analysis::types::pointer_type>(str_value.type->value).pointee_type->kind !=
					compiler::analysis::types::type_node::kind_t::PRIMITIVE ||
					std::get<compiler::analysis::types::primitive_type>(
						std::get<compiler::analysis::types::pointer_type>(str_value.type->value)
						.pointee_type->value) != compiler::analysis::types::primitive_type::CHAR) {
					throw std::runtime_error("puts expects a char pointer");
				}
				uint32_t ptr = str_value.get_as<uint32_t>();
				std::string output;
				while (true) {
					char c;
					std::memcpy(&c, interpreter.memory().data() + ptr, 1);
					if (c == '\0') {
						break;
					}
					output += c;
					++ptr;
				}
				output_buffer.push_back(output);
				return compiler::interpreter::value_t::l_value(
					{compiler::analysis::types::primitive_type::VOID},
					interpreter);
			}
		});

		interpreter.register_external_function(compiler::interpreter::external_function{
			"puti",
			std::make_shared<compiler::analysis::types::type_node>(compiler::analysis::types::primitive_type::VOID),
			{
				std::make_shared<compiler::analysis::types::type_node>(compiler::analysis::types::primitive_type::INT)
			},
			[&output_buffer](const std::vector<compiler::interpreter::value_t>& args,
			compiler::interpreter::ast_interpreter& interpreter) -> compiler::interpreter::value_t {
				if (args.size() != 1) {
					throw std::runtime_error("puti expects 1 argument");
				}
				const auto& int_value = args[0];
				if (int_value.type->kind != compiler::analysis::types::type_node::kind_t::PRIMITIVE ||
					std::get<compiler::analysis::types::primitive_type>(int_value.type->value) !=
					compiler::analysis::types::primitive_type::INT) {
					throw std::runtime_error("puti expects an int");
				}
				int32_t value = int_value.get_as<int32_t>();
				output_buffer.push_back(std::to_string(value));
				return compiler::interpreter::value_t::l_value(
					{compiler::analysis::types::primitive_type::VOID},
					interpreter);
			}
		});
	}

	try {
		interpreter.load_program(program);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading program: " << e.what() << std::endl;
		return 1;
	}
	try {
		interpreter.initialize_literals();
	}
	catch (const std::exception& e) {
		std::cerr << "Error initializing literals: " << e.what() << std::endl;
		return 1;
	}
	compiler::interpreter::value_t result;
	try {
		auto arg_n = compiler::interpreter::value_t::l_value<int32_t>(10, interpreter);
		auto arg_d = compiler::interpreter::value_t::l_value<int32_t>(1, interpreter);
		auto arg_e = compiler::interpreter::value_t::l_value<int32_t>(3, interpreter);
		result = interpreter.execute_function("main", {arg_n, arg_d, arg_e});
	}
	catch (const std::exception& e) {
		std::cerr << "Error executing program: " << e.what() << std::endl;
		return 1;
	}
	std::chrono::high_resolution_clock::time_point end_time = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> exec_time = end_time - start_time;
	std::cout << "Execution time: " << exec_time.count() << " ms" << std::endl;
	std::cout << "Program returned: " << result.as_int(interpreter) << std::endl;
	for (const auto& out : output_buffer) {
		std::cout << out;
	}
	return 0;
}
