#pragma once

#include <unordered_map>

#include "ast.hpp"

namespace compiler {
	typedef uint16_t data_type_size_t;
	typedef data_type_size_t data_type_offset_t;
	typedef uint16_t program_reference_t;
	typedef uint16_t index_t;
	class Compiler {
	public:
		ast_program m_program;
		std::unordered_map<std::string, program_reference_t> m_symbol_table; // symbol name to declaration index in program

		explicit Compiler(const ast_program& program) : m_program(program) {
			// Build symbol table
			for (size_t i = 0; i < m_program.body.size(); ++i) {
				const auto& element = m_program.body[i];
				if (std::holds_alternative<ast_statement_function_declaration>(element)) {
					const auto& [name, __, ___, ____] = std::get<ast_statement_function_declaration>(element);
					m_symbol_table[name] = static_cast<program_reference_t>(i);
				}
				else if (std::holds_alternative<ast_statement_struct_declaration>(element)) {
					const auto& [name, __] = std::get<ast_statement_struct_declaration>(element);
					m_symbol_table[name] = static_cast<program_reference_t>(i);
				}
			}
		}

		data_type_size_t deduce_type_size(const std::shared_ptr<ast_type_node>& type) const;
		data_type_size_t deduce_type_struct_size(const ast_type_members& members) const;
		data_type_size_t deduce_type_union_size(const ast_type_members& members) const;
		static index_t get_member_index(const ast_type_members& members, const std::string& name);
		data_type_offset_t get_struct_member_offset(const ast_type_members& members, index_t member_index) const;
		data_type_offset_t get_struct_member_offset(const ast_type_members& members, const std::string& name) const;
	};
} // compiler
