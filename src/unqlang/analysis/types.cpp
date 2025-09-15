#include "types.hpp"

#include <unordered_set>

namespace unqlang::analysis::types {
	void type_system::validate_type(const type_node& type, bool allow_incomplete) const {
		if (std::holds_alternative<std::monostate>(type.value)) {
			if (allow_incomplete) {
				return;
			}
			throw std::logic_error("Incomplete type used where complete type is required");
		}
		switch (type.kind) {
			case type_node::kind_t::PRIMITIVE:
				// Primitive types are always valid
				return;
			case type_node::kind_t::ARRAY: {
				const auto& arr = std::get<array_type>(type.value);
				validate_type(*arr.element_type, allow_incomplete);
				return;
			}
			case type_node::kind_t::POINTER: {
				const auto& ptr = std::get<pointer_type>(type.value);
				validate_type(*ptr.pointee_type, true);
				return;
			}
			case type_node::kind_t::FUNCTION: {
				const auto& func = std::get<function_type>(type.value);
				validate_type(*func.return_type, allow_incomplete);
				for (const auto& param_type : func.parameter_types) {
					validate_type(*param_type, allow_incomplete);
				}
				return;
			}
			case type_node::kind_t::STRUCT: {
				const auto& st = std::get<struct_type>(type.value);
				std::unordered_set<std::string> member_names;
				for (const auto& member : st.members) {
					if (member_names.contains(member.name)) {
						throw std::logic_error("Duplicate member name in struct: " + member.name);
					}
					member_names.insert(member.name);
					validate_type(*member.type, allow_incomplete);
				}
				return;
			}
			case type_node::kind_t::UNION: {
				const auto& un = std::get<union_type>(type.value);
				std::unordered_set<std::string> member_names;
				for (const auto& member : un.members) {
					if (member_names.contains(member.name)) {
						throw std::logic_error("Duplicate member name in union: " + member.name);
					}
					member_names.insert(member.name);
					validate_type(*member.type, allow_incomplete);
				}
			}
			case type_node::kind_t::CUSTOM: {
				const auto& type_name = std::get<std::string>(type.value);
				if (!is_type_declared(type_name)) {
					throw std::logic_error("Use of undeclared custom type: " + type_name);
				}
				if (!is_type_initialized(type_name) && !allow_incomplete) {
					throw std::logic_error("Use of incomplete custom type: " + type_name);
				}
				return;
			}
		}
		throw std::logic_error("Unknown type kind");
	}
	type_node type_system::unwrap_type(const type_node& type) const {
		if (std::holds_alternative<std::monostate>(type.value)) {
			throw std::logic_error("Cannot unwrap incomplete type");
		}
		switch (type.kind) {
			case type_node::kind_t::PRIMITIVE:
				return type;
			case type_node::kind_t::ARRAY: {
				const auto& arr = std::get<array_type>(type.value);
				const auto& element_type = unwrap_type(*arr.element_type);
				return type_node(array_type(std::make_shared<type_node>(element_type), arr.size));
			}
			case type_node::kind_t::POINTER:
			case type_node::kind_t::FUNCTION:
				return type;
			case type_node::kind_t::STRUCT: {
				const auto& st = std::get<struct_type>(type.value);
				std::vector<struct_type::member> unwrapped_members;
				for (const auto& member : st.members) {
					const auto& unwrapped_member_type = unwrap_type(*member.type);
					unwrapped_members.push_back({member.name, std::make_shared<type_node>(unwrapped_member_type)});
				}
				const auto unwrapped_struct = struct_type(unwrapped_members);
				return type_node(unwrapped_struct);
			}
			case type_node::kind_t::UNION: {
				const auto& un = std::get<union_type>(type.value);
				std::vector<union_type::member> unwrapped_members;
				for (const auto& member : un.members) {
					const auto& unwrapped_member_type = unwrap_type(*member.type);
					unwrapped_members.push_back({member.name, std::make_shared<type_node>(unwrapped_member_type)});
				}
				const auto unwrapped_union = union_type(unwrapped_members);
				return type_node(unwrapped_union);
			}
			case type_node::kind_t::CUSTOM: {
				const auto& type_name = std::get<std::string>(type.value);
				if (!is_type_declared(type_name)) {
					throw std::logic_error("Use of undeclared custom type: " + type_name);
				}
				if (!is_type_initialized(type_name)) {
					throw std::logic_error("Use of incomplete custom type: " + type_name);
				}
				return unwrap_type(get_type(type_name));
			}
		}
		throw std::logic_error("Unknown type kind");
	}
	size_t type_system::get_type_size(const type_node& type) const {
		if (std::holds_alternative<std::monostate>(type.value)) {
			throw std::logic_error("Cannot get size of incomplete type");
		}
		switch (type.kind) {
			case type_node::kind_t::PRIMITIVE: {
				const auto& pt = std::get<primitive_type>(type.value);
				switch (pt) {
					case primitive_type::VOID:
						return 0;
					case primitive_type::BOOL:
						return 1;
					case primitive_type::SIGNED_CHAR:
					case primitive_type::UNSIGNED_CHAR:
						return 1;
					case primitive_type::SIGNED_SHORT:
					case primitive_type::UNSIGNED_SHORT:
						return 2;
					case primitive_type::SIGNED_INT:
					case primitive_type::UNSIGNED_INT:
						return 4;
					case primitive_type::SIGNED_LONG:
					case primitive_type::UNSIGNED_LONG:
						return 8;
					case primitive_type::FLOAT:
						return 4;
					case primitive_type::DOUBLE:
						return 8;
				}
				throw std::logic_error("Unknown primitive type");
			}
			case type_node::kind_t::ARRAY: {
				const auto& arr = std::get<array_type>(type.value);
				const auto element_size = get_type_size(*arr.element_type);
				return element_size * arr.size;
			}
			case type_node::kind_t::POINTER:
				return m_arch_64bit ? 8 : 4;
			case type_node::kind_t::FUNCTION:
				return m_arch_64bit ? 8 : 4;
			case type_node::kind_t::STRUCT: {
				const auto& st = std::get<struct_type>(type.value);
				size_t total_size = 0;
				for (const auto& member : st.members) {
					total_size += get_type_size(*member.type);
				}
				return total_size;
			}
			case type_node::kind_t::UNION: {
				const auto& un = std::get<union_type>(type.value);
				size_t max_size = 0;
				for (const auto& member : un.members) {
					const auto member_size = get_type_size(*member.type);
					if (member_size > max_size) {
						max_size = member_size;
					}
				}
				return max_size;
			}
			case type_node::kind_t::CUSTOM: {
				const auto& type_name = std::get<std::string>(type.value);
				return get_type_size(type_name);
			}
		}
		throw std::logic_error("Unknown type kind");
	}
	size_t type_system::get_type_size(const std::string& name) const {
		if (m_type_info.contains(name)) {
			return m_type_info.at(name).size;
		}
		const auto type = get_type(name);
		const auto size = get_type_size(type);
		m_type_info.emplace(name, type_info{size});
		return size;
	}
	type_system::member_info type_system::get_struct_member_info(const type_node& type,
		const std::string& member_name) const {
		auto resolved_type = this->resolved_type(type);
		if (resolved_type.kind != type_node::kind_t::STRUCT) {
			throw std::logic_error("Type is not a struct");
		}
		const auto& st = std::get<struct_type>(resolved_type.value);
		return get_struct_member_info(st, member_name);
	}
	type_system::member_info type_system::get_struct_member_info(const struct_type& type,
		const std::string& member_name) const {
		size_t offset = 0;
		for (size_t i = 0; i < type.members.size(); i++) {
			const auto& member = type.members[i];
			if (member.name == member_name) {
				return member_info{i, offset, member.type};
			}
			offset += get_type_size(*member.type);
		}
		throw std::logic_error("Member not found in struct: " + member_name);
	}
	type_system::member_info type_system::get_union_member_info(const type_node& type,
		const std::string& member_name) const {
		auto resolved_type = this->resolved_type(type);
		if (resolved_type.kind != type_node::kind_t::UNION) {
			throw std::logic_error("Type is not a union");
		}
		const auto& un = std::get<union_type>(resolved_type.value);
		return get_union_member_info(un, member_name);
	}
	type_system::member_info type_system::get_union_member_info(const union_type& type,
		const std::string& member_name) {
		for (size_t i = 0; i < type.members.size(); i++) {
			const auto& member = type.members[i];
			if (member.name == member_name) {
				return member_info{i, 0, member.type}; // All members of a union have offset 0
			}
		}
		throw std::logic_error("Member not found in union: " + member_name);
	}
	type_node type_system::get_result_type_binary(ast_expression_binary::type_t op, const type_node& left,
		const type_node& right) const {
		const auto left_resolved = resolved_type(left);
		const auto right_resolved = resolved_type(right);
		if ((left_resolved.kind == type_node::kind_t::PRIMITIVE &&
				std::get<primitive_type>(left_resolved.value) == primitive_type::VOID) ||
			(right_resolved.kind == type_node::kind_t::PRIMITIVE &&
				std::get<primitive_type>(right_resolved.value) == primitive_type::VOID)) {
			throw std::logic_error("Cannot use void type in binary expression");
		}
		switch (op) {
			case ast_expression_binary::type_t::Add:
			case ast_expression_binary::type_t::Subtract:
			case ast_expression_binary::type_t::Multiply:
			case ast_expression_binary::type_t::Divide:
			case ast_expression_binary::type_t::Modulo:
			case ast_expression_binary::type_t::BitwiseAnd:
			case ast_expression_binary::type_t::BitwiseOr:
			case ast_expression_binary::type_t::BitwiseXor: {
				// check for pointer arithmetic
				if (op == ast_expression_binary::type_t::Add || op == ast_expression_binary::type_t::Subtract) {
					if (left_resolved.kind == type_node::kind_t::POINTER &&
						right_resolved.kind == type_node::kind_t::PRIMITIVE) {
						const auto right_primitive = std::get<primitive_type>(right_resolved.value);
						if (right_primitive == primitive_type::VOID) {
							throw std::logic_error("Cannot perform arithmetic on void type");
						}
						return left_resolved;
					}
					if (right_resolved.kind == type_node::kind_t::POINTER &&
						left_resolved.kind == type_node::kind_t::PRIMITIVE) {
						const auto left_primitive = std::get<primitive_type>(left_resolved.value);
						if (left_primitive == primitive_type::VOID) {
							throw std::logic_error("Cannot perform arithmetic on void type");
						}
						if (op == ast_expression_binary::type_t::Subtract) {
							throw std::logic_error("Cannot subtract pointer from integer");
						}
						return right_resolved;
					}
					if (left_resolved.kind == type_node::kind_t::POINTER &&
						right_resolved.kind == type_node::kind_t::POINTER) {
						if (op == ast_expression_binary::type_t::Add) {
							throw std::logic_error("Cannot add two pointers");
						}
						// Pointer subtraction results in an integer
						return type_node(primitive_type::INT);
					}
				}
				if (left_resolved.kind != type_node::kind_t::PRIMITIVE || right_resolved.kind != type_node::kind_t::PRIMITIVE) {
					throw std::logic_error("Binary arithmetic operators require primitive types");
				}
				const auto left_primitive = std::get<primitive_type>(left_resolved.value);
				const auto right_primitive = std::get<primitive_type>(right_resolved.value);
				// Result type is the larger of the two types
				auto up_type = upper_type(left_primitive, right_primitive);
				if (op != ast_expression_binary::type_t::BitwiseAnd && op != ast_expression_binary::type_t::BitwiseOr &&
					op != ast_expression_binary::type_t::BitwiseXor && up_type == primitive_type::BOOL) {
					// Arithmetic operations on bools result in unsigned char
					up_type = primitive_type::UCHAR;
				}
				return up_type;
			}
			case ast_expression_binary::type_t::Assignment: {
				if (is_equivalent(left_resolved, primitive_type::BOOL)) {
					return primitive_type::BOOL;
				}
				if (left_resolved.kind == type_node::kind_t::PRIMITIVE &&
					right_resolved.kind == type_node::kind_t::PRIMITIVE) {
					const auto left_primitive = std::get<primitive_type>(left_resolved.value);
					const auto right_primitive = std::get<primitive_type>(right_resolved.value);
					if (can_implicitly_convert(right_primitive, left_primitive)) {
						return left_resolved;
					}
					throw std::logic_error(std::format("Cannot implicitly convert from {} to {}",
						right_primitive, left_primitive));
				}
				if (is_equivalent(left_resolved, right_resolved)) {
					return left_resolved;
				}
				throw std::logic_error("Incompatible types for assignment");
			}
			case ast_expression_binary::type_t::Equal:
			case ast_expression_binary::type_t::NotEqual:
				return primitive_type::BOOL;
			case ast_expression_binary::type_t::Less:
			case ast_expression_binary::type_t::LessEqual:
			case ast_expression_binary::type_t::Greater:
			case ast_expression_binary::type_t::GreaterEqual: {
				if (left_resolved.kind == type_node::kind_t::POINTER &&
					right_resolved.kind == type_node::kind_t::POINTER) {
					// Pointer comparison is always possible
					return primitive_type::BOOL;
				}
				if (left_resolved.kind != type_node::kind_t::PRIMITIVE || right_resolved.kind != type_node::kind_t::PRIMITIVE) {
					throw std::logic_error("Relational operators require primitive types");
				}
				const auto left_primitive = std::get<primitive_type>(left_resolved.value);
				const auto right_primitive = std::get<primitive_type>(right_resolved.value);
				if (!is_numeric_type(left_primitive) || !is_numeric_type(right_primitive)) {
					throw std::logic_error("Relational operators require numeric types");
				}
				return primitive_type::BOOL;
			}
			case ast_expression_binary::type_t::LogicalAnd:
			case ast_expression_binary::type_t::LogicalOr: {
				// Logical operators are always possible on any type
				return primitive_type::BOOL;
			}
			case ast_expression_binary::type_t::ShiftLeft:
			case ast_expression_binary::type_t::ShiftRight: {
				if (left_resolved.kind != type_node::kind_t::PRIMITIVE || right_resolved.kind != type_node::kind_t::PRIMITIVE) {
					throw std::logic_error("Bitwise shift operators require primitive types");
				}
				const auto left_primitive = std::get<primitive_type>(left_resolved.value);
				const auto right_primitive = std::get<primitive_type>(right_resolved.value);
				if (!is_integral_type(left_primitive) || !is_integral_type(right_primitive)) {
					throw std::logic_error("Bitwise shift operators require integral types");
				}
				return left_resolved;
			}
			case ast_expression_binary::type_t::Comma: {
				return right_resolved;
			}
			case ast_expression_binary::type_t::ArraySubscript: {
				// left type must be a pointer or array
				// right type must be integral (also bool)
				if (right_resolved.kind != type_node::kind_t::PRIMITIVE ||
					!is_pseudo_integral_type(std::get<primitive_type>(right_resolved.value))) {
					throw std::logic_error("Array subscript requires integral type on right side");
				}
				if (left_resolved.kind == type_node::kind_t::ARRAY) {
					const auto& arr = std::get<array_type>(left_resolved.value);
					return *arr.element_type;
				}
				if (left_resolved.kind == type_node::kind_t::POINTER) {
					const auto& ptr = std::get<pointer_type>(left_resolved.value);
					return *ptr.pointee_type;
				}
				throw std::logic_error("Array subscript requires array or pointer type on left side");
			}
		}
		throw std::logic_error("Unknown binary operator");
	}
	type_node type_system::get_result_type_unary(ast_expression_unary::type_t op, const type_node& operand) const {
		const auto operand_resolved = resolved_type(operand);
		if (operand_resolved.kind == type_node::kind_t::PRIMITIVE &&
			std::get<primitive_type>(operand_resolved.value) == primitive_type::VOID) {
			throw std::logic_error("Cannot use void type in unary expression");
		}
		switch (op) {
			case ast_expression_unary::type_t::Negate:
			case ast_expression_unary::type_t::Positive: {
				if (operand_resolved.kind != type_node::kind_t::PRIMITIVE) {
					throw std::logic_error("Unary + and - require primitive types");
				}
				const auto operand_primitive = std::get<primitive_type>(operand_resolved.value);
				if (!is_numeric_type(operand_primitive)) {
					throw std::logic_error("Unary + and - require numeric types");
				}
				return operand_resolved;
			}
			case ast_expression_unary::type_t::LogicalNot: {
				// Logical NOT is always possible on any type
				return primitive_type::BOOL;
			}
			case ast_expression_unary::type_t::BitwiseNot: {
				if (operand_resolved.kind != type_node::kind_t::PRIMITIVE) {
					throw std::logic_error("Bitwise NOT requires primitive types");
				}
				const auto operand_primitive = std::get<primitive_type>(operand_resolved.value);
				if (!is_integral_type(operand_primitive)) {
					throw std::logic_error("Bitwise NOT requires integral types");
				}
				return operand_resolved;
			}
			case ast_expression_unary::type_t::AddressOf: {
				// Address of operator can be applied to any type except void
				return pointer_type(std::make_shared<type_node>(operand_resolved));
			}
			case ast_expression_unary::type_t::Dereference: {
				if (operand_resolved.kind != type_node::kind_t::POINTER) {
					throw std::logic_error("Dereference operator requires pointer type");
				}
				const auto& ptr = std::get<pointer_type>(operand_resolved.value);
				return *ptr.pointee_type;
			}
			case ast_expression_unary::type_t::PostfixDecrement:
			case ast_expression_unary::type_t::PostfixIncrement:
			case ast_expression_unary::type_t::PrefixDecrement:
			case ast_expression_unary::type_t::PrefixIncrement: {
				// allowed on primitive types and pointers
				if (operand_resolved.kind == type_node::kind_t::PRIMITIVE) {
					const auto operand_primitive = std::get<primitive_type>(operand_resolved.value);
					if (!is_numeric_type(operand_primitive)) {
						throw std::logic_error("Increment and decrement operators require numeric types");
					}
					return operand_resolved;
				}
				if (operand_resolved.kind == type_node::kind_t::POINTER) {
					return operand_resolved;
				}
				throw std::logic_error("Increment and decrement operators require numeric or pointer types");
			}
			case ast_expression_unary::type_t::SizeOf: {
				// sizeof operator can be applied to any type except void
				const auto size = get_type_size(operand_resolved);
				if (size > static_cast<size_t>(std::numeric_limits<unsigned int>::max())) {
					throw std::logic_error("Size of type is too large to fit in an int");
				}
				return primitive_type::UINT;
			}
		}
		throw std::logic_error("Unknown unary operator");
	}
	type_node type_system::get_result_type_literal(const ast_expression_literal& literal) {
		switch (literal.type) {
			case ast_expression_literal::type_t::Integer:
				return primitive_type::INT;
			case ast_expression_literal::type_t::Boolean:
				return primitive_type::BOOL;
			case ast_expression_literal::type_t::String:
				return pointer_type(primitive_type::CHAR);
			case ast_expression_literal::type_t::Null:
				return pointer_type(primitive_type::VOID);
			case ast_expression_literal::type_t::Char:
				return primitive_type::CHAR;
		}
		throw std::logic_error("Unknown literal type");
	}
	type_node type_system::get_result_type_member_access(const type_node& object_type, const std::string& member_name,
		bool pointer) const {
		type_node obj_type = object_type;
		type_node resolved_object_type = resolved_type(object_type);
		if (pointer) {
			if (resolved_object_type.kind != type_node::kind_t::POINTER) {
				throw std::logic_error("Member access with '->' requires pointer type on left side");
			}
			const auto& ptr = std::get<pointer_type>(resolved_object_type.value);
			const auto pointee_type = resolved_type(*ptr.pointee_type);
			obj_type = pointee_type;
			resolved_object_type = pointee_type;
		}
		if (resolved_object_type.kind == type_node::kind_t::STRUCT) {
			const auto& st = std::get<struct_type>(resolved_object_type.value);
			const auto member_info = get_struct_member_info(st, member_name);
			return *member_info.type;
		}
		if (resolved_object_type.kind == type_node::kind_t::UNION) {
			const auto& un = std::get<union_type>(resolved_object_type.value);
			const auto member_info = get_union_member_info(un, member_name);
			return *member_info.type;
		}
		if (pointer)
			throw std::logic_error("Member access with '->' requires pointer to struct or union type on left side");
		else
			throw std::logic_error("Member access requires struct or union type on left side");
	}
	type_node type_system::get_result_type_ternary(const type_node& then_type,
		const type_node& else_type) const {
		const auto then_resolved = resolved_type(then_type);
		const auto else_resolved = resolved_type(else_type);
		if (is_equivalent(then_resolved, else_resolved)) {
			return then_resolved;
		}
		if (then_resolved.kind == type_node::kind_t::PRIMITIVE &&
			else_resolved.kind == type_node::kind_t::PRIMITIVE) {
			const auto then_primitive = std::get<primitive_type>(then_resolved.value);
			const auto else_primitive = std::get<primitive_type>(else_resolved.value);
			if (can_implicitly_convert(then_primitive, else_primitive)) {
				return else_resolved;
			}
			if (can_implicitly_convert(else_primitive, then_primitive)) {
				return then_resolved;
			}
			throw std::logic_error(std::format("Cannot implicitly convert between {} and {} in ternary expression",
				then_primitive, else_primitive));
		}
		throw std::logic_error("Incompatible types in ternary expression");
	}
	bool type_system::is_equivalent(const type_node& a, const type_node& b, compare_options options) const {
		if (a.kind == type_node::kind_t::CUSTOM && b.kind == type_node::kind_t::CUSTOM) {
			const auto& name_a = std::get<std::string>(a.value);
			const auto& name_b = std::get<std::string>(b.value);
			if (name_a == name_b) {
				return true;
			}
		}
		type_node a_ = a;
		type_node b_ = b;
		while (a_.kind == type_node::kind_t::CUSTOM) {
			a_ = get_type(std::get<std::string>(a_.value));
		}
		while (b_.kind == type_node::kind_t::CUSTOM) {
			b_ = get_type(std::get<std::string>(b_.value));
		}
		if (a_.kind != b_.kind) {
			return false;
		}
		switch (a_.kind) {
			case type_node::kind_t::PRIMITIVE:
				return std::get<primitive_type>(a_.value) == std::get<primitive_type>(b_.value);
			case type_node::kind_t::ARRAY: {
				const auto& arr_a = std::get<array_type>(a_.value);
				const auto& arr_b = std::get<array_type>(b_.value);
				if (arr_a.size != arr_b.size) {
					return false;
				}
				return is_equivalent(*arr_a.element_type, *arr_b.element_type, options);
			}
			case type_node::kind_t::POINTER: {
				if (options.ignore_pointers) {
					return true;
				}
				const auto& ptr_a = std::get<pointer_type>(a_.value);
				const auto& ptr_b = std::get<pointer_type>(b_.value);
				if (ptr_a.pointee_type->kind == type_node::kind_t::CUSTOM && ptr_b.pointee_type->kind ==
					type_node::kind_t::CUSTOM) {
					if (std::get<std::string>(ptr_a.pointee_type->value) == std::get<std::string>(ptr_b.pointee_type->value)) {
						return true;
					}
				}
				return is_equivalent(*ptr_a.pointee_type, *ptr_b.pointee_type, options);
			}
			case type_node::kind_t::FUNCTION: {
				if (options.ignore_functions) {
					return true;
				}
				const auto& fn_a = std::get<function_type>(a_.value);
				const auto& fn_b = std::get<function_type>(b_.value);
				if (!is_equivalent(*fn_a.return_type, *fn_b.return_type, options)) {
					return false;
				}
				if (fn_a.parameter_types.size() != fn_b.parameter_types.size()) {
					return false;
				}
				for (size_t i = 0; i < fn_a.parameter_types.size(); i++) {
					if (!is_equivalent(*fn_a.parameter_types[i], *fn_b.parameter_types[i], options)) {
						return false;
					}
				}
				return true;
			}
			case type_node::kind_t::UNION: {
				const auto& un_a = std::get<union_type>(a_.value);
				const auto& un_b = std::get<union_type>(b_.value);
				if (un_a.members.size() != un_b.members.size()) {
					return false;
				}
				for (size_t i = 0; i < un_a.members.size(); i++) {
					const auto& member_a = un_a.members[i];
					const auto& member_b = un_b.members[i];
					if (options.check_member_names && member_a.name != member_b.name) {
						return false;
					}
					if (!is_equivalent(*member_a.type, *member_b.type, options)) {
						return false;
					}
				}
				return true;
			}
			case type_node::kind_t::STRUCT: {
				const auto& st_a = std::get<struct_type>(a_.value);
				const auto& st_b = std::get<struct_type>(b_.value);
				if (st_a.members.size() != st_b.members.size()) {
					return false;
				}
				for (size_t i = 0; i < st_a.members.size(); i++) {
					const auto& member_a = st_a.members[i];
					const auto& member_b = st_b.members[i];
					if (options.check_member_names && member_a.name != member_b.name) {
						return false;
					}
					if (!is_equivalent(*member_a.type, *member_b.type, options)) {
						return false;
					}
				}
				return true;
			}
			case type_node::kind_t::CUSTOM:
				throw std::logic_error("Unreachable code reached in type equivalence check, check your ram sticks!");
			default:
				throw std::logic_error("Unknown type kind");
		}
	}
	type_node type_system::from_ast(const unqlang::ast_type_node& ast_type) {
		switch (ast_type.type) {
			case ast_type_node::type_t::Char:
				return type_node(primitive_type::CHAR);
			case ast_type_node::type_t::Int:
				return type_node(primitive_type::INT);
			case ast_type_node::type_t::Bool:
				return type_node(primitive_type::BOOL);
			case ast_type_node::type_t::Void:
				return type_node(primitive_type::VOID);
			case ast_type_node::type_t::Array: {
				const auto& arr = std::get<ast_type_array>(ast_type.value);
				return type_node(array_type(std::make_shared<type_node>(from_ast(*arr.base)), arr.size));
			}
			case ast_type_node::type_t::Pointer: {
				const auto& ptr = std::get<ast_type_pointer>(ast_type.value);
				return type_node(pointer_type(std::make_shared<type_node>(from_ast(*ptr.base))));
			}
			case ast_type_node::type_t::Struct: {
				const auto& st = std::get<ast_type_members>(ast_type.value);
				std::vector<struct_type::member> members;
				members.reserve(st.members.size());
				for (const auto& member : st.members) {
					members.push_back({member.name, std::make_shared<type_node>(from_ast(*member.type))});
				}
				return type_node(struct_type(members));
			}
			case ast_type_node::type_t::Union: {
				const auto& un = std::get<ast_type_members>(ast_type.value);
				std::vector<union_type::member> members;
				members.reserve(un.members.size());
				for (const auto& member : un.members) {
					members.push_back({member.name, std::make_shared<type_node>(from_ast(*member.type))});
				}
				return type_node(union_type(members));
			}
			// case ast_type_node::type_t::Union: {}
			case ast_type_node::type_t::Function: {
				const auto& fn = std::get<ast_type_function>(ast_type.value);
				std::vector<std::shared_ptr<type_node>> param_types;
				for (const auto& param : fn.parameters) {
					param_types.push_back(std::make_shared<type_node>(from_ast(*param)));
				}
				return type_node(function_type(std::make_shared<type_node>(from_ast(*fn.return_type)), param_types));
			}
			case ast_type_node::type_t::Custom: {
				const auto& ct = std::get<std::string>(ast_type.value);
				return type_node(ct);
			}
		}
		throw std::logic_error("Unknown AST type node");
	}
} // namespace compiler::analysis::types
