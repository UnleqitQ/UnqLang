#pragma once

#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "ast.hpp"
#include "ast_helpers.hpp"
#include "analysis/types.hpp"

namespace unqlang::interpreter {
	class ast_interpreter;
	typedef uint32_t pointer_t; // 32-bit pointer
	struct memory_t {
		std::shared_ptr<std::vector<uint8_t>> memory = std::make_shared<std::vector<uint8_t>>();
		std::map<uint32_t, uint32_t> allocations; // offset -> size
		memory_t() = default;
		explicit memory_t(size_t size) : memory(std::make_shared<std::vector<uint8_t>>(size, 0)) {
		}
		uint8_t* data() {
			return memory->data();
		}
		const uint8_t* data() const {
			return memory->data();
		}
		size_t size() const {
			return memory->size();
		}
		bool find_previous_allocation(uint32_t offset, uint32_t& out_offset, uint32_t& out_size) const {
			auto it = allocations.lower_bound(offset);
			if (it != allocations.begin()) {
				--it;
				out_offset = it->first;
				out_size = it->second;
				return true;
			}
			return false;
		}
		bool find_next_allocation(uint32_t offset, uint32_t& out_offset, uint32_t& out_size) const {
			auto it = allocations.upper_bound(offset);
			if (it != allocations.end()) {
				out_offset = it->first;
				out_size = it->second;
				return true;
			}
			return false;
		}
		bool get_first_allocation(uint32_t& out_offset, uint32_t& out_size) const {
			if (!allocations.empty()) {
				auto it = allocations.begin();
				out_offset = it->first;
				out_size = it->second;
				return true;
			}
			return false;
		}
		bool get_last_allocation(uint32_t& out_offset, uint32_t& out_size) const {
			if (!allocations.empty()) {
				auto it = allocations.end();
				--it;
				out_offset = it->first;
				out_size = it->second;
				return true;
			}
			return false;
		}
		void extend(size_t new_size) {
			if (new_size > memory->size()) {
				memory->resize(new_size, 0);
			}
		}
		uint32_t allocate(size_t size) {
			if (size == 0) {
				throw std::runtime_error("Cannot allocate zero bytes");
			}
			// Simple first-fit allocation strategy
			if (allocations.empty()) {
				extend(size);
				allocations[0] = static_cast<uint32_t>(size);
				return 0;
			}
			// Check before the first allocation
			uint32_t first_offset, first_size;
			if (get_first_allocation(first_offset, first_size)) {
				if (first_offset >= size) {
					allocations[0] = static_cast<uint32_t>(size);
					return 0;
				}
			}
			// Check between allocations
			for (auto it = allocations.begin(); it != allocations.end(); ++it) {
				uint32_t current_offset = it->first;
				uint32_t current_size = it->second;
				uint32_t next_offset, next_size;
				if (find_next_allocation(current_offset, next_offset, next_size)) {
					if (next_offset > current_offset + current_size) {
						uint32_t gap_size = next_offset - (current_offset + current_size);
						if (gap_size >= size) {
							uint32_t alloc_offset = current_offset + current_size;
							allocations[alloc_offset] = static_cast<uint32_t>(size);
							return alloc_offset;
						}
					}
				}
				else {
					// No next allocation, allocate at the end
					uint32_t alloc_offset = current_offset + current_size;
					extend(alloc_offset + size);
					allocations[alloc_offset] = static_cast<uint32_t>(size);
					return alloc_offset;
				}
			}
			// Should not reach here
			throw std::runtime_error("Failed to allocate memory");
		}
		void deallocate(uint32_t offset) {
			if (allocations.contains(offset)) {
				allocations.erase(offset);
			}
			else {
				throw std::runtime_error("Invalid deallocation: no allocation at offset " + std::to_string(offset));
			}
		}
		void deallocate(uint32_t offset, size_t size) {
			if (allocations.contains(offset)) {
				if (allocations[offset] != size) {
					throw std::runtime_error("Invalid deallocation: size mismatch at offset " + std::to_string(offset));
				}
				allocations.erase(offset);
			}
			else {
				throw std::runtime_error("Invalid deallocation: no allocation at offset " + std::to_string(offset));
			}
		}
		void clear() {
			memory->clear();
			allocations.clear();
		}
	};
	inline bool is_nullptr(uint32_t ptr) {
		// In this interpreter, we define nullptr as -1 (0xFFFFFFFF)
		// i know that's not how it works in reality but for this interpreter it's better
		// as we can use 0 as a valid memory address
		return ptr == -1;
	}
	struct value_t {
		static constexpr uint32_t nullptr_value = static_cast<uint32_t>(-1);
		static const analysis::types::type_node void_type;
		static const std::shared_ptr<analysis::types::type_node> void_type_ptr;

		std::shared_ptr<analysis::types::type_node> type;
		uint32_t offset;
		std::shared_ptr<std::vector<uint8_t>> memory;

		value_t() : type(void_type_ptr), offset(nullptr_value), memory(nullptr) {
		}
		value_t(std::shared_ptr<analysis::types::type_node> t, uint32_t o,
			std::shared_ptr<std::vector<uint8_t>> mem = nullptr)
			: type(std::move(t)), offset(o), memory(std::move(mem)) {
		}

		bool as_bool(const ast_interpreter& interpreter) const;
		int32_t as_int(const ast_interpreter& interpreter) const;
		uint32_t as_uint(const ast_interpreter& interpreter) const;
		template<typename T>
		T get_as() const {
			if (offset == nullptr_value) {
				throw std::runtime_error("Dereferencing nullptr");
			}
			if (offset + sizeof(T) > memory->size()) {
				throw std::runtime_error("Memory access out of bounds");
			}
			return *reinterpret_cast<const T*>(memory->data() + offset);
		}
		template<typename T>
		void set_as(const T& value) const {
			if (offset == nullptr_value) {
				throw std::runtime_error("Dereferencing nullptr");
			}
			if (offset + sizeof(T) > memory->size()) {
				throw std::runtime_error("Memory access out of bounds");
			}
			*reinterpret_cast<T*>(memory->data() + offset) = value;
		}
		value_t get_member(const std::string& name, ast_interpreter& interpreter) const;
		value_t dereference(ast_interpreter& interpreter) const;

		bool operator==(const value_t& other) const {
			return *type == *other.type && offset == other.offset;
		}
		bool operator!=(const value_t& other) const {
			return !(*this == other);
		}
		bool data_equals(const value_t& other, const ast_interpreter& interpreter) const;

		static value_t l_value(std::shared_ptr<analysis::types::type_node> t, const ast_interpreter& interpreter);
		static value_t l_value(const analysis::types::type_node& t, const ast_interpreter& interpreter) {
			return l_value(std::make_shared<analysis::types::type_node>(t), interpreter);
		}
		template<typename T>
		static value_t l_value(std::shared_ptr<analysis::types::type_node> t, const T& initial_value,
			const ast_interpreter& interpreter);
		template<typename T>
		static value_t l_value(const T& initial_value, const ast_interpreter& interpreter) {
			return l_value(std::make_shared<analysis::types::type_node>(type_helpers::from_cpp_type<T>()), initial_value,
				interpreter);
		}

		friend std::ostream& operator<<(std::ostream& os, const value_t& value) {
			switch (value.type->kind) {
				case analysis::types::type_node::kind_t::PRIMITIVE: {
					switch (std::get<analysis::types::primitive_type>(value.type->value)) {
						case analysis::types::primitive_type::INT: {
							int32_t int_value = value.get_as<int32_t>();
							os << int_value;
							break;
						}
						case analysis::types::primitive_type::CHAR: {
							char char_value = value.get_as<char>();
							os << "'" << char_value << "'";
							break;
						}
						case analysis::types::primitive_type::BOOL: {
							bool bool_value = value.get_as<uint8_t>() != 0;
							os << (bool_value ? "true" : "false");
							break;
						}
						case analysis::types::primitive_type::VOID:
							os << "void";
							break;
						default:
							os << "[unknown primitive type]";
							break;
					}
					break;
				}
				case analysis::types::type_node::kind_t::POINTER: {
					uint32_t ptr_value = value.get_as<uint32_t>();
					if (is_nullptr(ptr_value)) {
						os << "nullptr";
					}
					else {
						os << "0x" << std::hex << ptr_value << std::dec;
					}
					break;
				}
				case analysis::types::type_node::kind_t::STRUCT: {
					os << "{...}"; // Simplified for brevity
					break;
				}
				case analysis::types::type_node::kind_t::ARRAY: {
					os << "[...]"; // Simplified for brevity
					break;
				}
				default:
					os << "[unknown type]";
			}
			return os;
		}
	};
	struct scope {
		std::unordered_map<std::string, value_t> variables;
		std::shared_ptr<scope> parent;

		explicit scope(const std::shared_ptr<scope>& parent = nullptr) : parent(parent) {
		}

		void declare_variable(const std::string& name, const value_t& value) {
			if (variables.contains(name)) {
				throw std::runtime_error("Variable already declared in this scope: " + name);
			}
			variables[name] = value;
		}
		bool has_variable(const std::string& name, bool check_parent = true) const {
			if (variables.contains(name)) {
				return true;
			}
			if (check_parent && parent) {
				return parent->has_variable(name);
			}
			return false;
		}
		value_t& get_variable(const std::string& name) {
			if (variables.contains(name)) {
				return variables[name];
			}
			if (parent) {
				return parent->get_variable(name);
			}
			throw std::runtime_error("Variable not found: " + name);
		}
		const value_t& get_variable(const std::string& name) const {
			if (variables.contains(name)) {
				return variables.at(name);
			}
			if (parent) {
				return parent->get_variable(name);
			}
			throw std::runtime_error("Variable not found: " + name);
		}
	};
	struct external_function {
		std::string name;
		std::shared_ptr<analysis::types::type_node> return_type;
		std::vector<std::shared_ptr<analysis::types::type_node>> param_types;
		std::function<value_t(const std::vector<value_t>&, ast_interpreter&)> func;

		external_function(std::string n,
			std::shared_ptr<analysis::types::type_node> ret_type,
			std::vector<std::shared_ptr<analysis::types::type_node>> param_t,
			std::function<value_t(const std::vector<value_t>&, ast_interpreter&)> f)
			: name(std::move(n)), return_type(std::move(ret_type)), param_types(std::move(param_t)), func(std::move(f)) {
		}
	};
	struct function_info {
		std::shared_ptr<analysis::types::type_node> return_type;
		std::vector<std::shared_ptr<analysis::types::type_node>> param_types;
		bool is_external;

		function_info() : return_type(nullptr), param_types(), is_external(false) {
		}
		function_info(std::shared_ptr<analysis::types::type_node> ret_type,
			std::vector<std::shared_ptr<analysis::types::type_node>> param_t,
			bool external)
			: return_type(std::move(ret_type)), param_types(std::move(param_t)), is_external(external) {
		}
	};
	class ast_interpreter {
		std::unordered_map<std::string, ast_statement_function_declaration> m_functions;
		std::unordered_map<std::string, external_function> m_external_functions;
		std::unordered_map<std::string, function_info> m_function_infos;
		std::unordered_map<ast_expression_literal, uint32_t> m_literal_memory_map;
		analysis::types::type_system m_type_system;
		std::shared_ptr<scope> m_global_scope = std::make_shared<scope>(nullptr);

		memory_t m_memory;

		bool m_debug = false;

	public:
		explicit ast_interpreter() {
		}

		void register_external_function(const external_function& func, bool allow_overwrite = false) {
			if (m_external_functions.contains(func.name)) {
				if (allow_overwrite) {
					std::cerr << "Warning: Overwriting external function: " << func.name << std::endl;
				}
				else {
					throw std::runtime_error("External function already registered: " + func.name);
				}
			}
			if (m_function_infos.contains(func.name)) {
				throw std::runtime_error("Function already registered: " + func.name);
			}
			m_function_infos[func.name] = function_info{
				func.return_type,
				func.param_types,
				true // is_external
			};
			m_external_functions.emplace(func.name, func);
		}
		void load_program(const ast_program& program);
		static void collect_literals(const ast_statement_block& block, std::vector<ast_expression_literal>& literals);
		static void collect_literals(const ast_statement_node& stmt, std::vector<ast_expression_literal>& literals);
		static void collect_literals(const ast_expression_node& expr, std::vector<ast_expression_literal>& literals);
		void store_literal(const ast_expression_literal& literal);
		uint32_t load_literal(const ast_expression_literal& literal) const;

		void initialize_literals();

		value_t execute_function(const std::string& name, const std::vector<value_t>& args);
		value_t evaluate_binary_expression(const ast_expression_binary& expression,
			const std::shared_ptr<scope>& current_scope);
		value_t evaluate_unary_expression(const ast_expression_unary& expression,
			const std::shared_ptr<scope>& current_scope);
		value_t evaluate_expression(const std::shared_ptr<ast_expression_node>& expr,
			const std::shared_ptr<scope>& current_scope);
		bool execute_statement(const std::shared_ptr<ast_statement_node>& stmt, const std::shared_ptr<scope>& current_scope,
			value_t& out_return_value);
		bool execute_block(const ast_statement_block& block, const std::shared_ptr<scope>& current_scope,
			value_t& out_return_value);

		value_t allocate_variable(const analysis::types::type_node& type);
		value_t allocate_variable(const std::shared_ptr<analysis::types::type_node>& type);
		void deallocate_variable(const value_t& var);

		analysis::types::type_node get_type(std::string name) const {
			return m_type_system.get_type(std::move(name));
		}

		// getters
		const memory_t& memory() const {
			return m_memory;
		}
		memory_t& memory() {
			return m_memory;
		}
		const analysis::types::type_system& type_system() const {
			return m_type_system;
		}
		analysis::types::type_system& type_system() {
			return m_type_system;
		}
		const std::unordered_map<std::string, ast_statement_function_declaration>& functions() const {
			return m_functions;
		}
		std::unordered_map<std::string, ast_statement_function_declaration>& functions() {
			return m_functions;
		}
	};
	template<typename T>
	value_t value_t::l_value(std::shared_ptr<analysis::types::type_node> t, const T& initial_value,
		const ast_interpreter& interpreter) {
		if (t->kind == analysis::types::type_node::kind_t::PRIMITIVE &&
			std::get<analysis::types::primitive_type>(t->value) == analysis::types::primitive_type::VOID) {
			throw std::runtime_error("Cannot create l-value of void type with initial value");
		}
		if (t->kind == analysis::types::type_node::kind_t::FUNCTION) {
			throw std::runtime_error("Cannot create l-value of function type with initial value");
		}
		if (sizeof(T) != interpreter.type_system().get_type_size(*t)) {
			throw std::runtime_error("Initial value size does not match type size");
		}
		value_t val = l_value(std::move(t), interpreter);
		val.set_as<T>(initial_value);
		return val;
	}
} // compiler
