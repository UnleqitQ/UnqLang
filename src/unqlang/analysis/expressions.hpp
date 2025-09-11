#pragma once
#include "types.hpp"
#include "variables.hpp"
#include "functions.hpp"

namespace unqlang::analysis::expressions {
	struct expression_node;

	struct literal_expression {
		enum class kind_t {
			NULLPTR, // null
			CHAR, // character literal
			UINT, // unsigned integer literal
			INT, // signed integer literal
			ULONG, // unsigned long integer literal
			LONG, // signed long integer literal
			FLOAT, // float literal
			DOUBLE, // double literal
			STRING, // string literal
			BOOL, // boolean literal
		} kind;
		std::variant<
			std::monostate, // NULLPTR
			char, // CHAR
			unsigned int, // UINT
			int, // INT
			unsigned long, // ULONG
			long, // LONG
			float, // FLOAT
			double, // DOUBLE
			std::string, // STRING
			bool // BOOL
		> value;
		literal_expression() : kind(kind_t::NULLPTR), value(std::monostate{}) {
		}
		literal_expression(kind_t k, auto&& v) : kind(k), value(std::forward<decltype(v)>(v)) {
		}

		types::type_node get_type() const {
			switch (kind) {
				case kind_t::NULLPTR:
					return types::pointer_type(types::primitive_type::VOID);
				case kind_t::CHAR:
					return types::type_node(types::primitive_type::SIGNED_CHAR);
				case kind_t::UINT:
					return types::type_node(types::primitive_type::UNSIGNED_INT);
				case kind_t::INT:
					return types::type_node(types::primitive_type::SIGNED_INT);
				case kind_t::ULONG:
					return types::type_node(types::primitive_type::UNSIGNED_LONG);
				case kind_t::LONG:
					return types::type_node(types::primitive_type::SIGNED_LONG);
				case kind_t::FLOAT:
					return types::type_node(types::primitive_type::FLOAT);
				case kind_t::DOUBLE:
					return types::type_node(types::primitive_type::DOUBLE);
				case kind_t::STRING:
					return types::pointer_type(types::primitive_type::SIGNED_CHAR);
				case kind_t::BOOL:
					return types::type_node(types::primitive_type::BOOL);
			}
			throw std::runtime_error("Unknown literal type");
		}

		bool operator==(const literal_expression& other) const {
			if (kind != other.kind) {
				return false;
			}
			return value == other.value;
		}
		bool operator!=(const literal_expression& other) const {
			return !(*this == other);
		}

		static literal_expression make_nullptr() {
			return literal_expression(kind_t::NULLPTR, std::monostate{});
		}
		static literal_expression make_char(char c) {
			return literal_expression(kind_t::CHAR, c);
		}
		static literal_expression make_uint(unsigned int u) {
			return literal_expression(kind_t::UINT, u);
		}
		static literal_expression make_int(int i) {
			return literal_expression(kind_t::INT, i);
		}
		static literal_expression make_ulong(unsigned long ul) {
			return literal_expression(kind_t::ULONG, ul);
		}
		static literal_expression make_long(long l) {
			return literal_expression(kind_t::LONG, l);
		}

		static literal_expression from_ast(const ast_expression_literal& ast_lit);
	};

	struct identifier_expression {
		std::string name;
		identifier_expression() : name("") {
		}
		explicit identifier_expression(std::string n) : name(std::move(n)) {
		}

		types::type_node get_type(const variables::storage& storage) const {
			auto var_info = storage.get_variable(name);
			return var_info.type;
		}

		bool operator==(const identifier_expression& other) const {
			return name == other.name;
		}
		bool operator!=(const identifier_expression& other) const {
			return !(*this == other);
		}

		static identifier_expression from_ast(const std::string& ast_id) {
			return identifier_expression(ast_id);
		}
	};

	struct binary_expression {
		enum class operator_t {
			// Arithmetic
			ADD, // +
			SUB, // -
			MUL, // *
			DIV, // /
			MOD, // %

			// Bitwise
			AND, // &
			OR, // |
			XOR, // ^
			SHL, // <<
			SHR, // >>

			// Logical
			LAND, // &&
			LOR, // ||

			// Comparison
			EQ, // ==
			NEQ, // !=
			LT, // <
			GT, // >
			LTE, // <=
			GTE, // >=

			// Assignment
			ASSIGN, // =

			// Other
			ARRAY_SUBSCRIPT, // []
		} op;

		std::shared_ptr<expression_node> left;
		std::shared_ptr<expression_node> right;
		binary_expression() : op(operator_t::ADD), left(nullptr), right(nullptr) {
		}
		binary_expression(operator_t o, std::shared_ptr<expression_node> l, std::shared_ptr<expression_node> r)
			: op(o), left(std::move(l)), right(std::move(r)) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const;

		bool operator==(const binary_expression& other) const;
		bool operator!=(const binary_expression& other) const {
			return !(*this == other);
		}

		static binary_expression from_ast(const ast_expression_binary& ast_bin);
	};

	ast_expression_binary::type_t op_to_ast(binary_expression::operator_t op);
	binary_expression::operator_t op_from_ast(ast_expression_binary::type_t op);

	struct unary_expression {
		enum class operator_t {
			// Arithmetic
			PLUS, // +
			MINUS, // -

			// Increment/Decrement
			PRE_INC, // ++i
			PRE_DEC, // --i
			POST_INC, // i++
			POST_DEC, // i--

			// Bitwise
			NOT, // ~

			// Logical
			LNOT, // !

			// Other
			DEREFERENCE, // *ptr
			ADDRESS_OF, // &var
			SIZEOF, // sizeof expr or type
		} op;
		std::shared_ptr<expression_node> operand;
		unary_expression() : op(operator_t::PLUS), operand(nullptr) {
		}
		unary_expression(operator_t o, std::shared_ptr<expression_node> opd) : op(o), operand(std::move(opd)) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const;

		bool operator==(const unary_expression& other) const;
		bool operator!=(const unary_expression& other) const {
			return !(*this == other);
		}

		static unary_expression from_ast(const ast_expression_unary& ast_un);
	};

	ast_expression_unary::type_t op_to_ast(unary_expression::operator_t op);
	unary_expression::operator_t op_from_ast(ast_expression_unary::type_t op);

	struct call_expression {
		std::shared_ptr<expression_node> callee;
		std::vector<std::shared_ptr<expression_node>> arguments;
		call_expression() : callee(nullptr), arguments() {
		}
		call_expression(std::shared_ptr<expression_node> c, std::vector<std::shared_ptr<expression_node>> args)
			: callee(std::move(c)), arguments(std::move(args)) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const;

		bool operator==(const call_expression& other) const;
		bool operator!=(const call_expression& other) const {
			return !(*this == other);
		}

		static call_expression from_ast(const ast_expression_call& ast_call);
	};

	struct member_expression {
		std::shared_ptr<expression_node> object;
		std::string member;
		bool pointer; // true if '->', false if '.'
		member_expression() : object(nullptr), member(""), pointer(false) {
		}
		member_expression(std::shared_ptr<expression_node> obj, std::string mem, bool ptr)
			: object(std::move(obj)), member(std::move(mem)), pointer(ptr) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const;

		bool operator==(const member_expression& other) const;
		bool operator!=(const member_expression& other) const {
			return !(*this == other);
		}

		static member_expression from_ast(const ast_member_access& ast_mem);
	};

	struct ternary_expression {
		std::shared_ptr<expression_node> condition;
		std::shared_ptr<expression_node> then_branch;
		std::shared_ptr<expression_node> else_branch;
		ternary_expression()
			: condition(nullptr), then_branch(nullptr), else_branch(nullptr) {
		}
		ternary_expression(std::shared_ptr<expression_node> cond, std::shared_ptr<expression_node> then_br,
			std::shared_ptr<expression_node> else_br)
			: condition(std::move(cond)), then_branch(std::move(then_br)), else_branch(std::move(else_br)) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const;

		bool operator==(const ternary_expression& other) const;
		bool operator!=(const ternary_expression& other) const {
			return !(*this == other);
		}

		static ternary_expression from_ast(const ast_expression_ternary& ast_ter);
	};

	struct expression_node {
		enum class kind_t {
			LITERAL,
			IDENTIFIER,
			BINARY,
			UNARY,
			CALL,
			MEMBER,
			TERNARY,

			UNKNOWN
		} kind;
		std::variant<
			literal_expression, // LITERAL
			identifier_expression, // IDENTIFIER
			binary_expression, // BINARY
			unary_expression, // UNARY
			call_expression, // CALL
			member_expression, // MEMBER
			ternary_expression, // TERNARY

			std::monostate // UNKNOWN
		> value;
		expression_node() : kind(kind_t::UNKNOWN), value(std::monostate{}) {
		}
		expression_node(kind_t k, auto&& v) : kind(k), value(std::forward<decltype(v)>(v)) {
		}
		expression_node(literal_expression lit) : kind(kind_t::LITERAL), value(std::move(lit)) {
		}
		expression_node(identifier_expression id) : kind(kind_t::IDENTIFIER), value(std::move(id)) {
		}
		expression_node(binary_expression bin) : kind(kind_t::BINARY), value(std::move(bin)) {
		}
		expression_node(unary_expression un) : kind(kind_t::UNARY), value(std::move(un)) {
		}
		expression_node(call_expression call) : kind(kind_t::CALL), value(std::move(call)) {
		}
		expression_node(member_expression mem) : kind(kind_t::MEMBER), value(std::move(mem)) {
		}
		expression_node(ternary_expression ter) : kind(kind_t::TERNARY), value(std::move(ter)) {
		}

		types::type_node get_type(
			const variables::storage& storage,
			const functions::storage& func_storage,
			const types::type_system& type_sys
		) const {
			switch (kind) {
				case kind_t::LITERAL:
					return std::get<literal_expression>(value).get_type();
				case kind_t::IDENTIFIER:
					return std::get<identifier_expression>(value).get_type(storage);
				case kind_t::BINARY:
					return std::get<binary_expression>(value).get_type(storage, func_storage, type_sys);
				case kind_t::UNARY:
					return std::get<unary_expression>(value).get_type(storage, func_storage, type_sys);
				case kind_t::CALL:
					return std::get<call_expression>(value).get_type(storage, func_storage, type_sys);
				case kind_t::MEMBER:
					return std::get<member_expression>(value).get_type(storage, func_storage, type_sys);
				case kind_t::TERNARY:
					return std::get<ternary_expression>(value).get_type(storage, func_storage, type_sys);
				case kind_t::UNKNOWN:
					throw std::runtime_error("Cannot get type of unknown expression");
			}
			throw std::runtime_error("Unknown expression type");
		}

		bool operator==(const expression_node& other) const {
			if (kind != other.kind) {
				return false;
			}
			return value == other.value;
		}
		bool operator!=(const expression_node& other) const {
			return !(*this == other);
		}

		static expression_node from_ast(const ast_expression_node& ast_expr);
	};

} // unqlang::analysis::expressions
