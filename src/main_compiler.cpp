#include <chrono>
#include <iostream>
#include <ranges>
#include <typeinfo>

#include "assembly/assembly_parser.hpp"
#include "unqlang/lexer.hpp"
#include "unqlang/ast.hpp"
#include "unqlang/compiler/compiler.hpp"

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

void print_scope(const unqlang::compiler::scope& scp, int indent = 0) {
	std::string indent_str(indent * 2, ' ');
	std::cout << indent_str << "Scope:\n";
	std::cout << indent_str << std::format(
		"all_paths_return={}\n",
		scp.all_paths_return ? "true" : "false"
	);
	if (scp.symbol_table.empty()) {
		std::cout << indent_str << "Variables: None\n";
	}
	else {
		std::cout << indent_str << "Variables:\n";
		for (const auto& [key, names] : scp.symbols_by_statement) {
			std::cout << indent_str << "  At statement index " << key << ":\n";
			for (const auto& name : names) {
				const auto& var_info = scp.symbol_table.at(name);
				std::cout << indent_str << "    " <<
					std::format("{}: type='{}'",
						var_info.var_info.name,
						var_info.var_info.type
					)
					<< "\n";
			}
		}
	}
	if (scp.children.empty()) {
		std::cout << indent_str << "Children: None\n";
	}
	else {
		std::cout << indent_str << "Children:\n";
		for (const auto& [key, child_list] : scp.children) {
			std::cout << indent_str << "  Child at statement index " << key << ":\n";
			for (const auto& child_info : child_list) {
				std::cout << indent_str << "    Child scope:\n";
				print_scope(*child_info.child, indent + 3);
			}
		}
	}
}

void print_asm_scope(const unqlang::compiler::assembly_scope& scp, int indent = 0) {
	std::string indent_str(indent * 2, ' ');
	std::cout << indent_str << "Assembly Scope: ";
	std::cout << std::format(
		"stack_size={}, "
		"cumulative_stack_size={}, "
		"base_offset={},\n",
		scp.stack_size,
		scp.cumulative_stack_size,
		scp.base_offset
	);
	std::cout << indent_str << "all_paths_return=" << (scp.all_paths_return ? "true" : "false") << "\n";
	if (scp.symbol_table.empty()) {
		std::cout << indent_str << "Variables: None\n";
	}
	else {
		std::cout << indent_str << "Variables:\n";
		for (const auto& [key, names] : scp.symbols_by_statement) {
			std::cout << indent_str << "  At statement index " << key << ":\n";
			for (const auto& name : names) {
				const auto& var_info = scp.symbol_table.at(name);
				std::cout << indent_str << "    " <<
					std::format("{}: type='{}', size={}, offset={}",
						var_info.name,
						var_info.type,
						var_info.size,
						var_info.offset)
					<< "\n";
			}
		}
	}
	if (scp.children.empty()) {
		std::cout << indent_str << "Children: None\n";
	}
	else {
		std::cout << indent_str << "Children:\n";
		for (const auto& [key, child_info] : scp.children) {
			std::cout << indent_str << "  Child at statement index " << key.statement_index
				<< ", scope index " << key.scope_index << ":\n";
			std::cout << indent_str << "    Child assembly scope:\n";
			print_asm_scope(*child_info.child, indent + 3);
		}
	}
}

assembly::assembly_program_t parse_assembly(const std::string& source_code) {
	std::vector<assembly::assembly_token> assembly_tokens = assembly::run_lexer(source_code);

	// Clean up tokens: remove comments and join newlines
	assembly::remove_comments(assembly_tokens);
	std::vector<assembly::assembly_token> cleaned_tokens;
	assembly::join_newlines(assembly_tokens, cleaned_tokens);
	assembly_tokens = cleaned_tokens;

	std::vector<assembly::assembly_parse_component> assembly_components = assembly::run_component_parser(assembly_tokens);

	assembly::assembly_program_t assembly_program = assembly::run_parser(assembly_components);
	return assembly_program;
}

int main() {
	std::string putc_asm = R"(
out byte ptr [esp + 4]
ret
)";
	std::string puti_asm = R"(
out dword ptr [esp + 4]
ret
)";
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

int main() {
	int n = 4;
	int d = 1;
	int e = 2;
	int result = multi_fibonacci(n, d, e);
	//puts("multi_fibonacci(");
	puti(n);
	//puts(", ");
	puti(d);
	//puts(", ");
	puti(e);
	//puts(") = ");
	puti(result);
	//puts("\n");
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

	unqlang::compiler::Compiler compilr;
	compilr.analyze_program(program);
	/*auto func_scope = compilr.
		build_function_scope(std::get<unqlang::ast_statement_function_declaration>(program.body[0]));
	print_scope(*func_scope);
	std::cout << std::string(80, '=') << std::endl << std::endl;
	auto asm_scope = compilr.build_function_assembly_scope(func_scope);
	print_asm_scope(*asm_scope);*/
	unqlang::ast_statement_function_declaration multi_fib_decl =
		std::get<unqlang::ast_statement_function_declaration>(program.body[0]);
	assembly::assembly_program_t asm_program;
	compilr.register_built_in_function(
		unqlang::analysis::functions::function_info("putc",
			unqlang::analysis::types::primitive_type::VOID,
			{unqlang::analysis::types::primitive_type::CHAR}
		), parse_assembly(putc_asm)
	);
	compilr.register_built_in_function(
		unqlang::analysis::functions::function_info("puti",
			unqlang::analysis::types::primitive_type::VOID,
			{unqlang::analysis::types::primitive_type::INT}
		), parse_assembly(puti_asm)
	);
	/*try {
		compilr.compile_function(multi_fib_decl, asm_program);
	}
	catch (const std::exception& e) {
		std::cerr << "Error compiling function: " << e.what() << std::endl;
		return 1;
	}
	std::cout << "Assembly program after compiling multi_fibonacci:" << std::endl;
	for (const auto& instr : asm_program) {
		std::cout << instr << std::endl;
	}*/
	assembly::assembly_program_t full_program;
	try {
		full_program = compilr.compile("main");
	}
	catch (const std::exception& e) {
		std::cerr << "Error compiling entry function: " << e.what() << std::endl;
		return 1;
	}
	std::cout << "Full assembly program after compiling entry function 'main':" << std::endl;
	for (const auto& instr : full_program) {
		std::cout << instr << std::endl;
	}
	return 0;
}
