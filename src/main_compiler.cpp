#include <chrono>
#include <iostream>
#include <ranges>
#include <typeinfo>

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
	/*unqlang::ast_program program;
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
	auto func_scope = compilr.
		build_function_scope(std::get<unqlang::ast_statement_function_declaration>(program.body[0]));
	print_scope(*func_scope);
	std::cout << std::string(80, '=') << std::endl << std::endl;
	auto asm_scope = compilr.build_function_assembly_scope(func_scope);
	print_asm_scope(*asm_scope);*/
	std::shared_ptr<unqlang::compiler::compilation_context> global_context =
		std::make_shared<unqlang::compiler::compilation_context>();
	namespace types = unqlang::analysis::types;
	global_context->function_storage->declare_function(
		"puti",
		types::primitive_type::INT,
		{types::primitive_type::CHAR},
		true
	);
	unqlang::compiler::scoped_compilation_context context{global_context};
	context.variable_storage = std::make_shared<unqlang::analysis::variables::storage>(
		unqlang::analysis::variables::storage::storage_type_t::Block
	);
	types::type_node type_a = types::pointer_of(
		types::struct_of({
			{"field1", types::primitive_type::INT},
			{"field2", types::primitive_type::BOOL},
			{"field3", types::pointer_of(types::primitive_type::UINT)}
		})
	);
	types::type_node type_b = types::pointer_of(types::primitive_type::INT);
	types::type_node type_c = types::primitive_type::INT;
	context.variable_storage->declare_variable(
		"a",
		type_a,
		true
	);
	context.variable_storage->declare_variable(
		"b",
		type_b,
		true
	);
	context.variable_storage->declare_variable(
		"c",
		type_c,
		true
	);
	std::cout << "Types:\n";
	std::cout << std::format("a: {}\n", context.variable_storage->variables.at("a").type);
	std::cout << std::format("b: {}\n", context.variable_storage->variables.at("b").type);
	std::cout << std::format("c: {}\n", context.variable_storage->variables.at("c").type);

	namespace expressions = unqlang::analysis::expressions;
	expressions::expression_node test_expression0 =
		expressions::make_binary(
			expressions::binary_expression::operator_t::ADD,
			expressions::make_unary(
				expressions::unary_expression::operator_t::DEREFERENCE,
				expressions::make_identifier("b")
			),
			expressions::make_binary(
				expressions::binary_expression::operator_t::MUL,
				expressions::make_member(
					expressions::make_identifier("a"),
					"field1",
					true
				),
				expressions::make_binary(
					expressions::binary_expression::operator_t::SUB,
					expressions::make_identifier("c"),
					expressions::make_binary(
						expressions::binary_expression::operator_t::ARRAY_SUBSCRIPT,
						expressions::make_identifier("b"),
						expressions::make_unary(
							expressions::unary_expression::operator_t::DEREFERENCE,
							expressions::make_member(
								expressions::make_identifier("a"),
								"field3",
								true
							)
						)
					)
				)
			)
		);
	expressions::expression_node test_expression =
		expressions::make_call(
			expressions::make_identifier("puti"),
			{test_expression0}
		);
	std::cout << std::format("Test expression: {}\n", test_expression);
	unqlang::compiler::scope current_scope;
	current_scope.symbol_table.emplace("a",
		unqlang::compiler::scope::variable_scope_info{
			{
				"a",
				context.variable_storage->variables.at("a").type
			},
			1
		});
	current_scope.symbol_table.emplace("b",
		unqlang::compiler::scope::variable_scope_info{
			{
				"b",
				context.variable_storage->variables.at("b").type
			},
			2
		});
	current_scope.symbol_table.emplace("c",
		unqlang::compiler::scope::variable_scope_info{
			{
				"c",
				context.variable_storage->variables.at("c").type
			},
			2
		});
	current_scope.symbols_by_statement.emplace(1, std::vector<std::string>{"a"});
	current_scope.symbols_by_statement.emplace(2, std::vector<std::string>{"b", "c"});
	std::shared_ptr<unqlang::compiler::assembly_scope> asm_scope =
		current_scope.build_assembly_scope(*global_context, nullptr, 0);
	assembly::assembly_program_t program;
	try {
		unqlang::compiler::compile_primitive_expression(
			test_expression,
			context,
			program,
			*asm_scope,
			machine::register_t{machine::register_id::eax},
			{},
			false
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error compiling expression: " << e.what() << std::endl;
		return 1;
	}
	std::cout << "Generated assembly instructions:\n";
	for (const auto& instr : program) {
		std::cout << instr << "\n";
	}
	return 0;
}
