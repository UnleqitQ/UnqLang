#include "compiler.hpp"

namespace unqlang::compiler {
	void compile_expression(const ast_expression_node& expr, assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg) {
		switch (expr.type) {
			case ast_expression_node::type_t::Literal: {
				const auto& lit = std::get<ast_expression_literal>(expr.value);
				switch (lit.type) {
					case ast_expression_literal::type_t::Boolean: {
						bool value = std::get<bool>(lit.value);
						program.emplace_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result{target_reg},
							assembly::assembly_operand{assembly::assembly_literal{value ? 1 : 0}}
						));
						break;
					}
					case ast_expression_literal::type_t::Integer: {
						int value = std::get<int>(lit.value);
						program.emplace_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result{target_reg},
							assembly::assembly_operand{assembly::assembly_literal{value}}
						));
						break;
					}
					case ast_expression_literal::type_t::Char: {
						char value = std::get<char>(lit.value);
						program.emplace_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result{target_reg},
							assembly::assembly_operand{assembly::assembly_literal{static_cast<int>(value)}}
						));
						break;
					}
					case ast_expression_literal::type_t::Null:
						throw std::runtime_error("Not implemented: compile_expression for null literal");
					case ast_expression_literal::type_t::String:
						throw std::runtime_error("Not implemented: compile_expression for string literal");
				}
				break;
			}
			case ast_expression_node::type_t::Identifier: {
				const auto& name = std::get<std::string>(expr.value);

				break;
			}
		}
	}

	void Compiler::analyze_program(const ast_program& program) {
		for (const auto& comp : program.body) {
			if (std::holds_alternative<ast_statement_function_declaration>(comp)) {
				// implemented later
			}
			else if (std::holds_alternative<ast_statement_type_declaration>(comp)) {
				const auto& type_decl = std::get<ast_statement_type_declaration>(comp);
				const auto& name = type_decl.name;
				const auto& type_node = type_decl.aliased_type;
				m_type_system->declare_initialized_type(name, analysis::types::type_system::from_ast(*type_node));
			}
			else if (std::holds_alternative<ast_statement_variable_declaration>(comp)) {
				// global variable declaration, implemented later
			}
			else if (std::holds_alternative<ast_statement_struct_declaration>(comp)) {
				const auto& struct_decl = std::get<ast_statement_struct_declaration>(comp);
				const auto& name = struct_decl.name;

				if (struct_decl.body == nullptr) {
					// forward declaration
					m_type_system->declare_type(name, analysis::types::type_node::kind_t::STRUCT);
					continue;
				}

				analysis::types::struct_type st;
				st.members.reserve(struct_decl.body->members.size());
				for (const auto& member : struct_decl.body->members) {
					st.members.emplace_back(
						member.name,
						analysis::types::type_system::from_ast(*member.type)
					);
				}
				m_type_system->declare_initialized_type(name, analysis::types::type_node(st));
			}
			else if (std::holds_alternative<ast_statement_union_declaration>(comp)) {
				const auto& union_decl = std::get<ast_statement_union_declaration>(comp);
				const auto& name = union_decl.name;

				if (union_decl.body == nullptr) {
					// forward declaration
					m_type_system->declare_type(name, analysis::types::type_node::kind_t::UNION);
					continue;
				}

				analysis::types::union_type ut;
				ut.members.reserve(union_decl.body->members.size());
				for (const auto& member : union_decl.body->members) {
					ut.members.emplace_back(
						member.name,
						analysis::types::type_system::from_ast(*member.type)
					);
				}
				m_type_system->declare_initialized_type(name, analysis::types::type_node(ut));
			}
			else {
				throw std::runtime_error("Unknown top-level AST component");
			}
		}
	}
	std::shared_ptr<scope> Compiler::build_function_scope(const ast_statement_function_declaration& func_decl) {
		std::shared_ptr<scope> func_scope;
		build_scope(func_decl.body, func_scope, nullptr);
		return func_scope;
	}
	std::shared_ptr<assembly_scope> Compiler::build_function_assembly_scope(const std::shared_ptr<scope>& func_scope) {
		if (func_scope == nullptr) {
			throw std::runtime_error("Function scope is null");
		}
		compilation_context context;
		context.type_system = m_type_system;
		return func_scope->build_assembly_scope(context, nullptr, 0);
	}
} // unqlang::compiler
