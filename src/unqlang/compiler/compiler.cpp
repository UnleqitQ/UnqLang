#include "compiler.hpp"

namespace unqlang::compiler {
	void compile_expression(const ast_expression_node& expr, assembly::assembly_program_t& program, assembly_scope& current_scope,
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
} // unqlang::compiler
