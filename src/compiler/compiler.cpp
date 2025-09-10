#include "compiler.hpp"

namespace compiler {
	data_type_size_t Compiler::deduce_type_size(const std::shared_ptr<ast_type_node>& type) const {
		switch (type->type) {
			case ast_type_node::type_t::Void:
				return 0;
			case ast_type_node::type_t::Int:
				return 4;
			case ast_type_node::type_t::Bool:
			case ast_type_node::type_t::Char:
				return 1;
			case ast_type_node::type_t::Pointer:
				return 4;
			case ast_type_node::type_t::Array: {
				const auto& array_info = std::get<ast_type_array>(type->value);
				data_type_size_t base_size = deduce_type_size(array_info.base);
				return base_size * (array_info.size > 0 ? array_info.size : 1);
				// if size is 0, treat as size 1 for unknown size
			}
			case ast_type_node::type_t::Function:
				return 0; // functions do not have a size
			case ast_type_node::type_t::Struct: {
				const auto& struct_info = std::get<ast_type_members>(type->value);
				return deduce_type_struct_size(struct_info);
			}
			case ast_type_node::type_t::Custom: {
				const auto& type_name = std::get<std::string>(type->value);
				// Look up the custom type in the symbol table
				if (m_symbol_table.contains(type_name)) {
					const program_reference_t ref = m_symbol_table.at(type_name);
					const auto& element = m_program.body[ref];
					if (std::holds_alternative<ast_statement_struct_declaration>(element)) {
						const auto& [name, body] = std::get<ast_statement_struct_declaration>(element);
						return 0; // deduce_type_struct_size(body);
					}
					else {
						throw std::runtime_error("Custom type is not a struct: " + type_name);
					}
				}
				throw std::runtime_error("Unknown custom type: " + std::get<std::string>(type->value));
			}
			default:
				return 0; // Unknown type
		}
	}
	data_type_size_t Compiler::deduce_type_struct_size(const ast_type_members& members) const {
		data_type_size_t total_size = 0;
		for (const auto& [name, type] : members.members) {
			total_size += deduce_type_size(type);
		}
		return total_size;
	}
	data_type_size_t Compiler::deduce_type_union_size(const ast_type_members& members) const {
		data_type_size_t max_size = 0;
		for (const auto& [name, type] : members.members) {
			data_type_size_t member_size = deduce_type_size(type);
			if (member_size > max_size) {
				max_size = member_size;
			}
		}
		return max_size;
	}
	index_t Compiler::get_member_index(const ast_type_members& members, const std::string& name) {
		for (index_t i = 0; i < static_cast<index_t>(members.members.size()); ++i) {
			if (members.members[i].name == name) {
				return i;
			}
		}
		throw std::runtime_error("Member not found: " + name);
	}
	data_type_offset_t Compiler::get_struct_member_offset(const ast_type_members& members, index_t member_index) const {
		if (member_index >= static_cast<index_t>(members.members.size())) {
			throw std::runtime_error("Member index out of bounds");
		}
		data_type_offset_t offset = 0;
		for (index_t i = 0; i < member_index; ++i) {
			offset += deduce_type_size(members.members[i].type);
		}
		return offset;
	}
	data_type_offset_t
	Compiler::get_struct_member_offset(const ast_type_members& members, const std::string& name) const {
		index_t member_index = get_member_index(members, name);
		return get_struct_member_offset(members, member_index);
	}
} // compiler
