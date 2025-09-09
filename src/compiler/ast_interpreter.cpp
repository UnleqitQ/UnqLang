#include "ast_interpreter.hpp"

#include <ranges>

namespace compiler::interpreter {
	const ast_type_node value_t::void_type = ast_type_node(ast_type_node::type_t::Void, std::monostate{});
	const std::shared_ptr<ast_type_node> value_t::void_type_ptr = std::make_shared<ast_type_node>(void_type);
	uint32_t ast_interpreter::deduce_type_size(const std::shared_ptr<ast_type_node>& type) const {
		switch (type->type) {
			case ast_type_node::type_t::Int:
				return 4;
			case ast_type_node::type_t::Char:
				return 1;
			case ast_type_node::type_t::Bool:
				return 1;
			case ast_type_node::type_t::Struct:
				return deduce_type_struct_size(std::get<ast_type_members>(type->value));
			case ast_type_node::type_t::Array: {
				const auto& array_info = std::get<ast_type_array>(type->value);
				uint32_t base_size = deduce_type_size(array_info.base);
				return base_size * (array_info.size > 0 ? array_info.size : 1);
				// if size is 0, treat as size 1 for unknown size
			}
			case ast_type_node::type_t::Pointer:
			case ast_type_node::type_t::Function:
				return 4;
			case ast_type_node::type_t::Void:
				return 0; // functions and void do not have a size
			case ast_type_node::type_t::Custom: {
				const auto& type_name = std::get<std::string>(type->value);
				// Look up the custom type in the symbol table
				if (m_types.contains(type_name)) {
					const auto& custom_type = m_types.at(type_name);
					return deduce_type_size(std::make_shared<ast_type_node>(custom_type));
				}
				throw std::runtime_error("Unknown custom type: " + std::get<std::string>(type->value));
			}
			default:
				throw std::runtime_error("Unknown type");
		}
	}
	uint32_t ast_interpreter::deduce_type_struct_size(const ast_type_members& members) const {
		uint32_t total_size = 0;
		for (const auto& [member_name, member_type] : members.members) {
			total_size += deduce_type_size(member_type);
		}
		return total_size;
	}
	uint32_t ast_interpreter::deduce_type_union_size(const ast_type_members& members) const {
		uint32_t max_size = 0;
		for (const auto& [member_name, member_type] : members.members) {
			uint32_t member_size = deduce_type_size(member_type);
			if (member_size > max_size) {
				max_size = member_size;
			}
		}
		return max_size;
	}
	uint16_t ast_interpreter::get_member_index(const ast_type_members& members, const std::string& name) {
		for (size_t i = 0; i < members.members.size(); ++i) {
			if (members.members[i].name == name) {
				return static_cast<uint16_t>(i);
			}
		}
		throw std::runtime_error("Member not found: " + name);
	}
	uint32_t ast_interpreter::get_struct_member_offset(const ast_type_members& members, uint16_t member_index) const {
		if (member_index >= static_cast<uint16_t>(members.members.size())) {
			throw std::runtime_error("Member index out of bounds");
		}
		uint32_t offset = 0;
		for (uint16_t i = 0; i < member_index; ++i) {
			offset += deduce_type_size(members.members[i].type);
		}
		return offset;
	}
	uint32_t ast_interpreter::get_struct_member_offset(const ast_type_members& members, const std::string& name) const {
		uint16_t member_index = get_member_index(members, name);
		return get_struct_member_offset(members, member_index);
	}
	bool value_t::as_bool(const ast_interpreter& interpreter) const {
		uint32_t size = interpreter.deduce_type_size(type);
		for (uint32_t i = 0; i < size; ++i) {
			if (memory->at(offset + i) != 0) {
				return true;
			}
		}
		return false;
	}
	int32_t value_t::as_int(const ast_interpreter& interpreter) const {
		switch (type->type) {
			case ast_type_node::type_t::Int: {
				int32_t int_value;
				std::memcpy(&int_value, memory->data() + offset, 4);
				return int_value;
			}
			case ast_type_node::type_t::Char: {
				uint8_t char_value;
				std::memcpy(&char_value, memory->data() + offset, 1);
				return static_cast<int32_t>(char_value);
			}
			case ast_type_node::type_t::Bool: {
				uint8_t bool_value;
				std::memcpy(&bool_value, memory->data() + offset, 1);
				return static_cast<int32_t>(bool_value != 0);
			}
			default:
				throw std::runtime_error("Cannot convert type to int");
		}
	}
	uint32_t value_t::as_uint(const ast_interpreter& interpreter) const {
		switch (type->type) {
			case ast_type_node::type_t::Int: {
				uint32_t uint_value;
				std::memcpy(&uint_value, memory->data() + offset, 4);
				return uint_value;
			}
			case ast_type_node::type_t::Char: {
				uint8_t char_value;
				std::memcpy(&char_value, memory->data() + offset, 1);
				return static_cast<uint32_t>(char_value);
			}
			case ast_type_node::type_t::Bool: {
				uint8_t bool_value;
				std::memcpy(&bool_value, memory->data() + offset, 1);
				return static_cast<uint32_t>(bool_value != 0);
			}
			default:
				throw std::runtime_error("Cannot convert type to uint");
		}
	}
	value_t value_t::get_member(const std::string& name, ast_interpreter& interpreter) const {
		ast_type_node self_type = *type;
		while (self_type.type == ast_type_node::type_t::Custom) {
			self_type = interpreter.get_type(std::get<std::string>(self_type.value));
		}
		if (self_type.type != ast_type_node::type_t::Struct) {
			throw std::runtime_error("Type is not a struct");
		}
		uint32_t member_index = interpreter.get_member_index(std::get<ast_type_members>(self_type.value), name);
		uint32_t member_offset = interpreter.get_struct_member_offset(std::get<ast_type_members>(self_type.value),
			member_index);
		const uint32_t final_offset = offset + member_offset;
		const auto& member_type = std::get<ast_type_members>(self_type.value).members[member_index].type;
		return value_t(member_type, final_offset);
	}
	value_t value_t::dereference(ast_interpreter& interpreter) const {
		if (type->type != ast_type_node::type_t::Pointer) {
			throw std::runtime_error("Type is not a pointer");
		}
		const uint32_t ptr_value = get_as<uint32_t>();
		ast_type_pointer pointer_type = std::get<ast_type_pointer>(type->value);
		return value_t(pointer_type.base, ptr_value);
	}
	bool value_t::data_equals(const value_t& other, const ast_interpreter& interpreter) const {
		if (*type != *other.type) {
			return false;
		}
		uint32_t size = interpreter.deduce_type_size(type);
		for (uint32_t i = 0; i < size; ++i) {
			if (memory->at(offset + i) != other.memory->at(other.offset + i)) {
				return false;
			}
		}
		return true;
	}
	value_t value_t::l_value(std::shared_ptr<ast_type_node> t, const ast_interpreter& interpreter) {
		uint32_t size = interpreter.deduce_type_size(t);
		std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(size);
		return value_t(t, 0, mem);
	}

	void ast_interpreter::load_program(const ast_program& program) {
		for (const auto& element : program.body) {
			if (std::holds_alternative<ast_statement_function_declaration>(element)) {
				const auto& func_decl = std::get<ast_statement_function_declaration>(element);
				if (m_functions.contains(func_decl.name)) {
					throw std::runtime_error("Function redeclaration: " + func_decl.name);
				}
				m_functions[func_decl.name] = func_decl;
				std::vector<std::shared_ptr<ast_type_node>> param_types;
				param_types.reserve(func_decl.parameters.size());
				for (const auto& param_type : func_decl.parameters | std::views::values) {
					param_types.push_back(param_type);
				}
				m_function_infos[func_decl.name] = function_info{
					func_decl.return_type,
					std::move(param_types),
					false // is_external
				};
			}
			else if (std::holds_alternative<ast_statement_struct_declaration>(element)) {
				const auto& struct_decl = std::get<ast_statement_struct_declaration>(element);
				const auto& [struct_name, __] = struct_decl;
				if (m_types.contains(struct_name)) {
					throw std::runtime_error("Struct redeclaration: " + struct_name);
				}
				m_types[struct_name] = ast_type_node(ast_type_node::type_t::Struct, struct_decl.body);
			}
			else {
				throw std::runtime_error("Unknown program element");
			}
		}
	}
	void ast_interpreter::collect_literals(const ast_statement_block& block,
		std::vector<ast_expression_literal>& literals) {
		for (const auto& stmt : block.statements) {
			collect_literals(*stmt, literals);
		}
	}
	void ast_interpreter::collect_literals(const ast_statement_node& stmt,
		std::vector<ast_expression_literal>& literals) {
		switch (stmt.type) {
			case ast_statement_node::type_t::BlockStatement:
				collect_literals(std::get<ast_statement_block>(stmt.value), literals);
				break;
			case ast_statement_node::type_t::ExpressionStatement: {
				const auto& expr = std::get<ast_statement_expression>(stmt.value);
				collect_literals(*expr.expression, literals);
				break;
			}
			case ast_statement_node::type_t::FunctionDeclaration: {
				const auto& func_decl = std::get<ast_statement_function_declaration>(stmt.value);
				collect_literals(func_decl.body, literals);
				break;
			}
			case ast_statement_node::type_t::VariableDeclaration: {
				const auto& var_decl = std::get<ast_statement_variable_declaration>(stmt.value);
				if (var_decl.initializer) {
					collect_literals(*var_decl.initializer, literals);
				}
				break;
			}
			case ast_statement_node::type_t::ReturnStatement: {
				const auto& return_stmt = std::get<ast_statement_return>(stmt.value);
				if (return_stmt.value) {
					collect_literals(*return_stmt.value, literals);
				}
				break;
			}
			case ast_statement_node::type_t::IfStatement: {
				const auto& if_stmt = std::get<ast_statement_if>(stmt.value);
				collect_literals(*if_stmt.condition, literals);
				collect_literals(*if_stmt.then_branch, literals);
				if (if_stmt.else_branch) {
					collect_literals(*if_stmt.else_branch, literals);
				}
				break;
			}
			case ast_statement_node::type_t::WhileStatement: {
				const auto& while_stmt = std::get<ast_statement_while>(stmt.value);
				collect_literals(*while_stmt.condition, literals);
				collect_literals(*while_stmt.body, literals);
				break;
			}
			default:
				throw std::runtime_error("Unknown statement type");
		}
	}
	void ast_interpreter::collect_literals(const ast_expression_node& expr,
		std::vector<ast_expression_literal>& literals) {
		switch (expr.type) {
			case ast_expression_node::type_t::Binary: {
				const auto& bin_expr = std::get<ast_expression_binary>(expr.value);
				collect_literals(*bin_expr.left, literals);
				collect_literals(*bin_expr.right, literals);
				break;
			}
			case ast_expression_node::type_t::Unary: {
				const auto& un_expr = std::get<ast_expression_unary>(expr.value);
				collect_literals(*un_expr.operand, literals);
				break;
			}
			case ast_expression_node::type_t::Literal: {
				if (const auto& lit_expr = std::get<ast_expression_literal>(expr.value); std::ranges::find(literals, lit_expr)
					== literals.end()) {
					literals.push_back(lit_expr);
				}
				break;
			}
			case ast_expression_node::type_t::Identifier:
				// Identifiers are not literals
				break;
			case ast_expression_node::type_t::FunctionCall: {
				const auto& call_expr = std::get<ast_expression_call>(expr.value);
				for (const auto& arg : call_expr.arguments) {
					collect_literals(*arg, literals);
				}
				collect_literals(*call_expr.callee, literals);
				break;
			}
			case ast_expression_node::type_t::MemberAccess: {
				const auto& mem_expr = std::get<ast_member_access>(expr.value);
				collect_literals(*mem_expr.object, literals);
				break;
			}
			case ast_expression_node::type_t::Ternary: {
				const auto& ter_expr = std::get<ast_expression_ternary>(expr.value);
				collect_literals(*ter_expr.condition, literals);
				collect_literals(*ter_expr.then, literals);
				collect_literals(*ter_expr.otherwise, literals);
				break;
			}
			default:
				throw std::runtime_error("Unknown expression type");
		}
	}
	void ast_interpreter::store_literal(const ast_expression_literal& literal) {
		if (m_literal_memory_map.contains(literal)) {
			return; // Already stored
		}
		uint32_t size = 0;
		switch (literal.type) {
			case ast_expression_literal::type_t::Integer:
				size = 4;
				break;
			case ast_expression_literal::type_t::Char:
				size = 1;
				break;
			case ast_expression_literal::type_t::Boolean:
				size = 1;
				break;
			case ast_expression_literal::type_t::String: {
				const auto& str_value = std::get<std::string>(literal.value);
				size = static_cast<uint32_t>(str_value.size() + 1); // +1 for null terminator
				break;
			}
			case ast_expression_literal::type_t::Null:
				size = 4; // null pointer
				break;
			default:
				throw std::runtime_error("Unknown literal type");
		}
		uint32_t offset = m_memory.allocate(size);
		switch (literal.type) {
			case ast_expression_literal::type_t::Integer: {
				int32_t int_value = std::get<int>(literal.value);
				std::memcpy(m_memory.data() + offset, &int_value, 4);
				break;
			}
			case ast_expression_literal::type_t::Char: {
				char char_value = std::get<char>(literal.value);
				m_memory.data()[offset] = static_cast<uint8_t>(char_value);
				break;
			}
			case ast_expression_literal::type_t::Boolean: {
				bool bool_value = std::get<bool>(literal.value);
				m_memory.data()[offset] = static_cast<uint8_t>(bool_value ? 1 : 0);
				break;
			}
			case ast_expression_literal::type_t::String: {
				const auto& str_value = std::get<std::string>(literal.value);
				std::memcpy(m_memory.data() + offset, str_value.c_str(), str_value.size() + 1);
				break;
			}
			case ast_expression_literal::type_t::Null: {
				uint32_t null_value = 0;
				std::memcpy(m_memory.data() + offset, &null_value, 4);
				break;
			}
			default:
				throw std::runtime_error("Unknown literal type");
		}
		m_literal_memory_map[literal] = offset;
	}
	uint32_t ast_interpreter::load_literal(const ast_expression_literal& literal) const {
		if (!m_literal_memory_map.contains(literal)) {
			throw std::runtime_error("Literal not found in memory");
		}
		return m_literal_memory_map.at(literal);
	}
	void ast_interpreter::initialize_literals() {
		std::vector<ast_expression_literal> literals;
		for (const auto& val : m_functions | std::views::values) {
			collect_literals(val.body, literals);
		}
		for (const auto& literal : literals) {
			if (literal.type == ast_expression_literal::type_t::String) {
				// Store string literals
				store_literal(literal);
			}
		}
	}

	value_t ast_interpreter::execute_function(const std::string& name, const std::vector<value_t>& args) {
		if (true) {
			// Debugging purpose
			std::cout << "Executing function '" << name << "' with ";
			if (args.empty()) {
				std::cout << "no arguments.\n";
			}
			else {
				std::cout << "argument" << (args.size() > 1 ? "s" : "") << ": ";
				for (size_t i = 0; i < args.size(); ++i) {
					if (i > 0) std::cout << ", ";
					const auto& arg = args[i];
					const auto& type = resolve_type(*arg.type);
					switch (type.type) {
						case ast_type_node::type_t::Int: {
							int32_t int_value = arg.get_as<int32_t>();
							std::cout << std::format("[int] {0} (0x{0:08X})", int_value);
							break;
						}
						case ast_type_node::type_t::Char: {
							char char_value = arg.get_as<char>();
							std::cout << std::format("[char] '{0}' ({1} / 0x{1:02X})", char_value,
								static_cast<uint8_t>(char_value));
							break;
						}
						case ast_type_node::type_t::Bool: {
							bool bool_value = arg.get_as<bool>();
							std::cout << std::format("[bool] {0}", bool_value ? "true" : "false");
							break;
						}
						case ast_type_node::type_t::Pointer: {
							uint32_t ptr_value = arg.get_as<uint32_t>();
							std::cout << std::format("[ptr] 0x{0:08X}", ptr_value);
							break;
						}
						case ast_type_node::type_t::Struct: {
							std::cout << "[struct] { [...] }";
							break;
						}
						case ast_type_node::type_t::Array: {
							std::cout << "[array] { [...] }";
							break;
						}
						default:
							std::cout << "[unknown type]";
							break;
					}
				}
				std::cout << "\n";
			}
		}
		if (!m_function_infos.contains(name)) {
			throw std::runtime_error("Function not found: " + name);
		}
		const auto& func_info = m_function_infos.at(name);
		if (args.size() != func_info.param_types.size()) {
			throw std::runtime_error("Function argument count mismatch");
		}
		for (size_t i = 0; i < args.size(); ++i) {
			if (*args[i].type != *func_info.param_types[i]) {
				throw std::runtime_error(
					"Function argument type mismatch for parameter " + std::to_string(i) + " in function: " + name);
			}
		}
		if (func_info.is_external) {
			if (!m_external_functions.contains(name)) {
				throw std::runtime_error("No external function handler registered for: " + name);
			}
			const auto& external_func = m_external_functions.at(name);
			value_t result = external_func.func(args, *this);
			if (*result.type != *func_info.return_type) {
				throw std::runtime_error("External function return type mismatch for function: " + name);
			}
			return result;
		}
		if (!m_functions.contains(name)) {
			throw std::runtime_error("Function not found: " + name);
		}
		const auto& func_decl = m_functions.at(name);
		auto func_scope = std::make_shared<scope>(nullptr);
		// Allocate parameters
		for (size_t i = 0; i < args.size(); ++i) {
			const auto& [param_name, param_type] = func_decl.parameters[i];
			func_scope->variables[param_name] = args[i];
		}
		value_t result;
		bool has_returned = execute_block(func_decl.body, func_scope, result);
		if (!has_returned) {
			if (func_decl.return_type->type != ast_type_node::type_t::Void) {
				throw std::runtime_error("Function did not return a value: " + name);
			}
		}
		if (*result.type != *func_decl.return_type) {
			throw std::runtime_error("Function return type mismatch: " + name);
		}
		return result;
	}
	value_t ast_interpreter::evaluate_binary_expression(const ast_expression_binary& expression,
		const std::shared_ptr<scope>& current_scope) {
		value_t left_value = evaluate_expression(expression.left, current_scope);
		if (expression.type == ast_expression_binary::type_t::LogicalAnd ||
			expression.type == ast_expression_binary::type_t::LogicalOr) {
			switch (expression.type) {
				case ast_expression_binary::type_t::LogicalAnd: {
					bool left_bool = left_value.as_bool(*this);
					bool result_bool = false;
					if (left_bool) {
						value_t right_value = evaluate_expression(expression.right, current_scope);
						bool right_bool = right_value.as_bool(*this);
						result_bool = right_bool;
					}
					auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
						std::monostate{}));
					std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
					uint8_t byte_value = result_bool ? 1 : 0;
					std::memcpy(mem->data(), &byte_value, 1);
					return value_t(bool_type, 0, mem);
				}
				case ast_expression_binary::type_t::LogicalOr: {
					bool left_bool = left_value.as_bool(*this);
					bool result_bool = true;
					if (!left_bool) {
						value_t right_value = evaluate_expression(expression.right, current_scope);
						bool right_bool = right_value.as_bool(*this);
						result_bool = right_bool;
					}
					auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
						std::monostate{}));
					std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
					uint8_t byte_value = result_bool ? 1 : 0;
					std::memcpy(mem->data(), &byte_value, 1);
					return value_t(bool_type, 0, mem);
				}
				default:
					throw std::runtime_error("Unknown logical operator");
			}
		}
		// For other binary operations, evaluate right side
		value_t right_value = evaluate_expression(expression.right, current_scope);
		if (expression.type == ast_expression_binary::type_t::Assignment) {
			if (!(
				expression.left->type == ast_expression_node::type_t::Identifier ||
				expression.left->type == ast_expression_node::type_t::MemberAccess ||
				(expression.left->type == ast_expression_node::type_t::Unary &&
					std::get<ast_expression_unary>(expression.left->value).type ==
					ast_expression_unary::type_t::Dereference)
				|| (expression.left->type == ast_expression_node::type_t::Binary &&
					std::get<ast_expression_binary>(expression.left->value).type ==
					ast_expression_binary::type_t::ArraySubscript)
			)) {
				throw std::runtime_error(
					"Left side of assignment must be a variable, member access, dereference, or array subscript");
			}
			if (*left_value.type != *right_value.type) {
				throw std::runtime_error("Assignment type mismatch");
			}
			// Copy right value to left value memory
			uint32_t size = deduce_type_size(left_value.type);
			for (uint32_t i = 0; i < size; ++i) {
				m_memory.data()[left_value.offset + i] = right_value.memory->at(right_value.offset + i);
			}
			return left_value;
		}
		if (expression.type == ast_expression_binary::type_t::ArraySubscript) {
			int32_t index = right_value.as_int(*this);
			if (left_value.type->type != ast_type_node::type_t::Array &&
				left_value.type->type != ast_type_node::type_t::Pointer) {
				throw std::runtime_error("Left side of array subscript must be an array or pointer");
			}
			std::shared_ptr<ast_type_node> element_type;
			if (left_value.type->type == ast_type_node::type_t::Array) {
				element_type = std::get<ast_type_array>(left_value.type->value).base;
			}
			else {
				// Pointer
				element_type = std::get<ast_type_pointer>(left_value.type->value).base;
			}
			uint32_t element_size = deduce_type_size(element_type);
			uint32_t element_offset = left_value.offset + index * element_size;
			return value_t(element_type, element_offset, left_value.memory);
		}
		// Handle other binary operations (arithmetic, comparison, bitwise)
		switch (expression.type) {
			case ast_expression_binary::type_t::Add:
			case ast_expression_binary::type_t::Subtract:
			case ast_expression_binary::type_t::Multiply:
			case ast_expression_binary::type_t::Divide:
			case ast_expression_binary::type_t::Modulo:
			case ast_expression_binary::type_t::BitwiseAnd:
			case ast_expression_binary::type_t::BitwiseOr:
			case ast_expression_binary::type_t::BitwiseXor:
			case ast_expression_binary::type_t::ShiftLeft:
			case ast_expression_binary::type_t::ShiftRight: {
				int32_t v1 = left_value.as_int(*this);
				int32_t v2 = right_value.as_int(*this);
				int32_t result;
				auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				switch (expression.type) {
					case ast_expression_binary::type_t::Add:
						result = v1 + v2;
						break;
					case ast_expression_binary::type_t::Subtract:
						result = v1 - v2;
						break;
					case ast_expression_binary::type_t::Multiply:
						result = v1 * v2;
						break;
					case ast_expression_binary::type_t::Divide:
						if (v2 == 0) {
							throw std::runtime_error("Division by zero");
						}
						result = v1 / v2;
						break;
					case ast_expression_binary::type_t::Modulo:
						if (v2 == 0) {
							throw std::runtime_error("Division by zero");
						}
						result = v1 % v2;
						break;
					case ast_expression_binary::type_t::BitwiseAnd:
						result = v1 & v2;
						break;
					case ast_expression_binary::type_t::BitwiseOr:
						result = v1 | v2;
						break;
					case ast_expression_binary::type_t::BitwiseXor:
						result = v1 ^ v2;
						break;
					case ast_expression_binary::type_t::ShiftLeft:
						result = v1 << v2;
						break;
					case ast_expression_binary::type_t::ShiftRight:
						result = v1 >> v2;
						break;
					default:
						throw std::runtime_error("Unknown binary operator");
				}
				std::memcpy(mem->data(), &result, 4);
				return value_t(int_type, 0, mem);
			}
			case ast_expression_binary::type_t::Equal:
			case ast_expression_binary::type_t::NotEqual: {
				bool result = left_value.data_equals(right_value, *this);
				auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
				uint8_t byte_value = result == (expression.type == ast_expression_binary::type_t::Equal) ? 1 : 0;
				std::memcpy(mem->data(), &byte_value, 1);
				return value_t(bool_type, 0, mem);
			}
			case ast_expression_binary::type_t::Less:
			case ast_expression_binary::type_t::LessEqual:
			case ast_expression_binary::type_t::Greater:
			case ast_expression_binary::type_t::GreaterEqual: {
				int32_t v1 = left_value.as_int(*this);
				int32_t v2 = right_value.as_int(*this);
				bool result = false;
				switch (expression.type) {
					case ast_expression_binary::type_t::Less:
						result = v1 < v2;
						break;
					case ast_expression_binary::type_t::LessEqual:
						result = v1 <= v2;
						break;
					case ast_expression_binary::type_t::Greater:
						result = v1 > v2;
						break;
					case ast_expression_binary::type_t::GreaterEqual:
						result = v1 >= v2;
						break;
					default:
						throw std::runtime_error("Unknown comparison operator");
				}
				auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
				uint8_t byte_value = result ? 1 : 0;
				std::memcpy(mem->data(), &byte_value, 1);
				return value_t(bool_type, 0, mem);
			}
			default:
				throw std::runtime_error("Unknown binary operator");
		}
	}
	value_t ast_interpreter::evaluate_unary_expression(const ast_expression_unary& expression,
		const std::shared_ptr<scope>& current_scope) {
		value_t operand_value = evaluate_expression(expression.operand, current_scope);
		switch (expression.type) {
			case ast_expression_unary::type_t::Negate: {
				int32_t v = operand_value.as_int(*this);
				int32_t result = -v;
				auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				std::memcpy(mem->data(), &result, 4);
				return value_t(int_type, 0, mem);
			}
			case ast_expression_unary::type_t::Positive: {
				int32_t v = operand_value.as_int(*this);
				int32_t result = +v;
				auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				std::memcpy(mem->data(), &result, 4);
				return value_t(int_type, 0, mem);
			}
			case ast_expression_unary::type_t::LogicalNot: {
				bool v = operand_value.as_bool(*this);
				bool result = !v;
				auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
				uint8_t byte_value = result ? 1 : 0;
				std::memcpy(mem->data(), &byte_value, 1);
				return value_t(bool_type, 0, mem);
			}
			case ast_expression_unary::type_t::BitwiseNot: {
				int32_t v = operand_value.as_int(*this);
				int32_t result = ~v;
				auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				std::memcpy(mem->data(), &result, 4);
				return value_t(int_type, 0, mem);
			}
			case ast_expression_unary::type_t::Dereference: {
				return operand_value.dereference(*this);
			}
			case ast_expression_unary::type_t::AddressOf: {
				auto ptr_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Pointer,
					ast_type_pointer(operand_value.type)));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				uint32_t addr = operand_value.offset;
				std::memcpy(mem->data(), &addr, 4);
				return value_t(ptr_type, 0, mem);
			}
			case ast_expression_unary::type_t::SizeOf: {
				uint32_t size = deduce_type_size(operand_value.type);
				auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
					std::monostate{}));
				std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
				std::memcpy(mem->data(), &size, 4);
				return value_t(int_type, 0, mem);
			}
			case ast_expression_unary::type_t::PostfixDecrement:
			case ast_expression_unary::type_t::PostfixIncrement:
			case ast_expression_unary::type_t::PrefixDecrement:
			case ast_expression_unary::type_t::PrefixIncrement: {
				// postfix creates a copy of the current value, then executes the operation and returns the copy
				// prefix executes the operation and returns a reference to the modified value
				bool incr = expression.type == ast_expression_unary::type_t::PostfixIncrement ||
					expression.type == ast_expression_unary::type_t::PrefixIncrement;
				bool pref = expression.type == ast_expression_unary::type_t::PrefixIncrement ||
					expression.type == ast_expression_unary::type_t::PrefixDecrement;
				value_t out_value;
				// Get current value
				const auto& resoled_type = resolve_type(*operand_value.type);
				switch (operand_value.type->type) {
					case ast_type_node::type_t::Int: {
						int32_t v = operand_value.get_as<int32_t>();
						int32_t new_value = v + (incr ? 1 : -1);
						// Update the value in memory
						operand_value.set_as<int32_t>(new_value);
						if (pref) {
							out_value = operand_value; // Return reference to modified value
						}
						else {
							// Return copy of original value
							out_value = value_t::l_value(operand_value.type, *this);
						}
						break;
					}
					case ast_type_node::type_t::Char: {
						char v = operand_value.get_as<char>();
						char new_value = v + (incr ? 1 : -1);
						// Update the value in memory
						operand_value.set_as<char>(new_value);
						if (pref) {
							out_value = operand_value; // Return reference to modified value
						}
						else {
							// Return copy of original value
							out_value = value_t::l_value(operand_value.type, *this);
						}
						break;
					}
					case ast_type_node::type_t::Bool:
						throw std::runtime_error("Increment/decrement operator not supported for bool type");
					case ast_type_node::type_t::Pointer: {
						uint32_t v = operand_value.get_as<uint32_t>();
						ast_type_pointer pointer_type = std::get<ast_type_pointer>(operand_value.type->value);
						uint32_t base_size = std::max(deduce_type_size(pointer_type.base), 1u);
						// Pointer arithmetic
						uint32_t new_value = v + (incr ? base_size : -static_cast<int32_t>(base_size));
						// Update the value in memory
						operand_value.set_as<uint32_t>(new_value);
						if (pref) {
							out_value = operand_value; // Return reference to modified value
						}
						else {
							// Return copy of original value
							out_value = value_t::l_value(operand_value.type, *this);
						}
						break;
					}
					default:
						throw std::runtime_error("Increment/decrement operator not supported for this type");
				}
				return out_value;
			}
			default:
				throw std::runtime_error("Unknown unary operator");
		}
	}

	value_t ast_interpreter::evaluate_expression(const std::shared_ptr<ast_expression_node>& expr,
		const std::shared_ptr<scope>& current_scope) {
		switch (expr->type) {
			case ast_expression_node::type_t::Literal: {
				const auto& literal = std::get<ast_expression_literal>(expr->value);
				switch (literal.type) {
					case ast_expression_literal::type_t::Integer: {
						auto int_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Int,
							std::monostate{}));
						std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
						int32_t int_value = std::get<int>(literal.value);
						std::memcpy(mem->data(), &int_value, 4);
						return value_t(int_type, 0, mem);
					}
					case ast_expression_literal::type_t::Char: {
						auto char_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Char,
							std::monostate{}));
						std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
						char char_value = std::get<char>(literal.value);
						std::memcpy(mem->data(), &char_value, 1);
						return value_t(char_type, 0, mem);
					}
					case ast_expression_literal::type_t::Boolean: {
						auto bool_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Bool,
							std::monostate{}));
						std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(1);
						bool bool_value = std::get<bool>(literal.value);
						uint8_t byte_value = bool_value ? 1 : 0;
						std::memcpy(mem->data(), &byte_value, 1);
						return value_t(bool_type, 0, mem);
					}
					case ast_expression_literal::type_t::Null: {
						auto void_ptr_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Pointer,
							ast_type_pointer(value_t::void_type_ptr)));
						std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
						uint32_t null_value = 0;
						std::memcpy(mem->data(), &null_value, 4);
						return value_t(void_ptr_type, 0, mem);
					}
					case ast_expression_literal::type_t::String: {
						/*const auto& str_value = std::get<std::string>(literal.value);
						auto char_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Char,
							std::monostate{}));
						auto array_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Array,
							ast_type_array(char_type, static_cast<uint32_t>(str_value.size() + 1))));
						std::shared_ptr<std::vector<uint8_t>> mem =
							std::make_shared<std::vector<uint8_t>>(static_cast<uint32_t>(str_value.size() + 1));
						std::memcpy(mem->data(), str_value.data(), str_value.size());
						mem->at(str_value.size()) = 0; // Null terminator
						return value_t(array_type, 0, mem);*/
						const uint32_t offset = load_literal(literal);
						auto char_ptr_type = type_helpers::pointer_to(common_types::char_type);
						return value_t::l_value(std::make_shared<ast_type_node>(char_ptr_type), offset, *this);
					}
					default:
						throw std::runtime_error("Literal type not implemented in interpreter");
				}
			}
			case ast_expression_node::type_t::Identifier: {
				const auto& var_expr = std::get<std::string>(expr->value);
				if (!current_scope->has_variable(var_expr)) {
					throw std::runtime_error("Variable not found: " + var_expr);
				}
				return current_scope->get_variable(var_expr);
			}
			case ast_expression_node::type_t::MemberAccess: {
				const auto& member_access = std::get<ast_member_access>(expr->value);
				value_t object_value = evaluate_expression(member_access.object, current_scope);
				if (member_access.pointer) {
					object_value = object_value.dereference(*this);
				}
				return object_value.get_member(member_access.property, *this);
			}
			case ast_expression_node::type_t::FunctionCall: {
				const auto& func_call = std::get<ast_expression_call>(expr->value);
				if (func_call.callee->type != ast_expression_node::type_t::Identifier) {
					throw std::runtime_error("Function call callee must be an identifier");
				}
				const auto& func_name = std::get<std::string>(func_call.callee->value);
				if (!m_function_infos.contains(func_name)) {
					throw std::runtime_error("Function not found: " + func_name);
				}
				const auto& func_info = m_function_infos.at(func_name);
				if (func_call.arguments.size() != func_info.param_types.size()) {
					throw std::runtime_error("Function argument count mismatch for function: " + func_name);
				}
				std::vector<value_t> arg_values;
				arg_values.reserve(func_call.arguments.size());
				for (size_t i = 0; i < func_call.arguments.size(); ++i) {
					value_t arg_value = evaluate_expression(func_call.arguments[i], current_scope);
					if (func_info.param_types[i]->type == ast_type_node::type_t::Pointer
						&& arg_value.type->type == ast_type_node::type_t::Array
						&& *std::get<ast_type_pointer>(func_info.param_types[i]->value).base ==
						*std::get<ast_type_array>(arg_value.type->value).base) {
						// Allow array to pointer decay
						auto ptr_type = std::make_shared<ast_type_node>(ast_type_node(ast_type_node::type_t::Pointer,
							ast_type_pointer(std::get<ast_type_array>(arg_value.type->value).base)));
						std::shared_ptr<std::vector<uint8_t>> mem = std::make_shared<std::vector<uint8_t>>(4);
						uint32_t addr = arg_value.offset;
						std::memcpy(mem->data(), &addr, 4);
						arg_value = value_t(ptr_type, 0, mem);
					}
					else if (*arg_value.type != *func_info.param_types[i]) {
						throw std::runtime_error("Function argument type mismatch for parameter " +
							std::to_string(i) + " in function: " + func_name);
					}
					arg_values.push_back(arg_value);
				}
				return execute_function(func_name, arg_values);
			}
			case ast_expression_node::type_t::Unary: {
				const auto& unary = std::get<ast_expression_unary>(expr->value);
				return evaluate_unary_expression(unary, current_scope);
			}
			case ast_expression_node::type_t::Binary: {
				const auto& binary = std::get<ast_expression_binary>(expr->value);
				return evaluate_binary_expression(binary, current_scope);
			}
			case ast_expression_node::type_t::Ternary: {
				const auto& ternary = std::get<ast_expression_ternary>(expr->value);
				value_t cond_value = evaluate_expression(ternary.condition, current_scope);
				bool cond_bool = cond_value.as_bool(*this);
				if (cond_bool) {
					return evaluate_expression(ternary.then, current_scope);
				}
				else {
					return evaluate_expression(ternary.otherwise, current_scope);
				}
			}
			case ast_expression_node::type_t::Unknown:
				throw std::runtime_error("Unknown expression type");
		}
		return value_t(); // Should not reach here
	}
	bool ast_interpreter::execute_statement(const std::shared_ptr<ast_statement_node>& stmt,
		const std::shared_ptr<scope>& current_scope, value_t& out_return_value) {
		switch (stmt->type) {
			case ast_statement_node::type_t::BlockStatement: {
				const auto& block = std::get<ast_statement_block>(stmt->value);
				return execute_block(block, current_scope, out_return_value);
			}
			case ast_statement_node::type_t::ReturnStatement: {
				const auto& return_stmt = std::get<ast_statement_return>(stmt->value);
				if (return_stmt.value) {
					out_return_value = evaluate_expression(return_stmt.value, current_scope);
				}
				else {
					out_return_value = value_t(value_t::void_type_ptr, 0);
				}
				return true; // Indicate that a return has occurred
			}
			case ast_statement_node::type_t::ExpressionStatement: {
				const auto& expr_stmt = std::get<ast_statement_expression>(stmt->value);
				evaluate_expression(expr_stmt.expression, current_scope);
				return false;
			}
			case ast_statement_node::type_t::VariableDeclaration: {
				const auto& var_decl = std::get<ast_statement_variable_declaration>(stmt->value);
				if (current_scope->has_variable(var_decl.name, false)) {
					throw std::runtime_error("Variable redeclaration: " + var_decl.name);
				}
				value_t var_value = allocate_variable(var_decl.var_type);
				if (var_decl.initializer) {
					value_t init_value = evaluate_expression(var_decl.initializer, current_scope);
					if (*init_value.type != *var_decl.var_type) {
						throw std::runtime_error("Variable initializer type mismatch for variable: " + var_decl.name);
					}
					// Copy initializer value to allocated memory
					uint32_t size = deduce_type_size(var_decl.var_type);
					for (uint32_t i = 0; i < size; ++i) {
						var_value.memory->at(var_value.offset + i) = init_value.memory->at(init_value.offset + i);
					}
				}
				current_scope->variables[var_decl.name] = var_value;
				return false;
			}
			case ast_statement_node::type_t::FunctionDeclaration:
				throw std::runtime_error("Function declarations are only allowed at the top level");
			case ast_statement_node::type_t::IfStatement: {
				const auto& if_stmt = std::get<ast_statement_if>(stmt->value);
				const auto& [condition, then_block, else_block] = if_stmt;
				value_t cond_value = evaluate_expression(condition, current_scope);
				bool cond_bool = cond_value.as_bool(*this);
				if (cond_bool) {
					return execute_block(std::get<ast_statement_block>(then_block->value), current_scope, out_return_value);
				}
				if (else_block) {
					switch (else_block->type) {
						case ast_statement_node::type_t::BlockStatement:
							return execute_block(std::get<ast_statement_block>(else_block->value), current_scope,
								out_return_value);
						case ast_statement_node::type_t::IfStatement:
							return execute_statement(else_block, current_scope, out_return_value);
						default:
							throw std::runtime_error("Else block must be a block statement or another if statement");
					}
				}
				return false;
			}
			case ast_statement_node::type_t::StructDeclaration:
				throw std::runtime_error("Struct declarations are only allowed at the top level");
			case ast_statement_node::type_t::WhileStatement: {
				const auto& while_stmt = std::get<ast_statement_while>(stmt->value);
				const auto& [condition, body_block] = while_stmt;
				while (true) {
					value_t cond_value = evaluate_expression(condition, current_scope);
					bool cond_bool = cond_value.as_bool(*this);
					if (!cond_bool) {
						break;
					}
					bool has_returned = execute_block(std::get<ast_statement_block>(body_block->value), current_scope,
						out_return_value);
					if (has_returned) {
						return true;
					}
				}
				return false;
			}
			case ast_statement_node::type_t::Unknown:
				throw std::runtime_error("Unknown statement type");
		}
		return false; // Should not reach here
	}
	bool ast_interpreter::execute_block(const ast_statement_block& block, const std::shared_ptr<scope>& current_scope,
		value_t& out_return_value) {
		auto block_scope = std::make_shared<scope>(current_scope);
		bool returned = false;
		for (const auto& stmt : block.statements) {
			bool has_returned = execute_statement(stmt, block_scope, out_return_value);
			if (has_returned) {
				returned = true;
				break;
			}
		}
		// Deallocate all variables in the block scope
		for (const auto& var_value : block_scope->variables | std::views::values) {
			deallocate_variable(var_value);
		}
		return returned;
	}
	value_t ast_interpreter::allocate_variable(const std::shared_ptr<ast_type_node>& type) {
		uint32_t size = deduce_type_size(type);
		uint32_t offset = m_memory.allocate(size);
		return value_t(type, offset, m_memory.memory);
	}
	void ast_interpreter::deallocate_variable(const value_t& var) {
		uint32_t size = deduce_type_size(var.type);
		m_memory.deallocate(var.offset, size);
	}
} // compiler::interpreter
