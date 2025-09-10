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
					case primitive_type::CHAR:
						return 1;
					case primitive_type::INT:
						return 4;
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
		if (type.kind != type_node::kind_t::STRUCT) {
			throw std::logic_error("Type is not a struct");
		}
		const auto& st = std::get<struct_type>(type.value);
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
		if (type.kind != type_node::kind_t::UNION) {
			throw std::logic_error("Type is not a union");
		}
		const auto& un = std::get<union_type>(type.value);
		return get_union_member_info(un, member_name);
	}
	type_system::member_info type_system::get_union_member_info(const union_type& type,
		const std::string& member_name) const {
		for (size_t i = 0; i < type.members.size(); i++) {
			const auto& member = type.members[i];
			if (member.name == member_name) {
				return member_info{i, 0, member.type}; // All members of a union have offset 0
			}
		}
		throw std::logic_error("Member not found in union: " + member_name);
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
