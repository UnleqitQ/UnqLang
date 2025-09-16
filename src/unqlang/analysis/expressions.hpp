#pragma once
#include <optional>

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
			uint32_t, // UINT
			int32_t, // INT
			uint64_t, // ULONG
			int64_t, // LONG
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
					return types::pointer_type(types::primitive_type::CHAR);
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

		uint32_t as_uint32() const {
			switch (kind) {
				case kind_t::CHAR:
					return static_cast<uint32_t>(std::get<char>(value));
				case kind_t::UINT:
					return std::get<uint32_t>(value);
				case kind_t::INT:
					return static_cast<uint32_t>(std::get<int32_t>(value));
				case kind_t::ULONG:
					return static_cast<uint32_t>(std::get<uint64_t>(value));
				case kind_t::LONG:
					return static_cast<uint32_t>(std::get<int64_t>(value));
				case kind_t::BOOL:
					return std::get<bool>(value) ? 1 : 0;
				case kind_t::NULLPTR:
					return 0;
				default:
					throw std::runtime_error("Cannot convert literal to uint32");
			}
		}
		int32_t as_int32() const {
			switch (kind) {
				case kind_t::CHAR:
					return static_cast<int32_t>(std::get<char>(value));
				case kind_t::UINT:
					return static_cast<int32_t>(std::get<uint32_t>(value));
				case kind_t::INT:
					return std::get<int32_t>(value);
				case kind_t::ULONG:
					return static_cast<int32_t>(std::get<uint64_t>(value));
				case kind_t::LONG:
					return static_cast<int32_t>(std::get<int64_t>(value));
				case kind_t::BOOL:
					return std::get<bool>(value) ? 1 : 0;
				case kind_t::NULLPTR:
					return 0;
				default:
					throw std::runtime_error("Cannot convert literal to int32");
			}
		}

		bool get_truthiness() const {
			switch (kind) {
				case kind_t::NULLPTR:
					return false;
				case kind_t::CHAR:
					return std::get<char>(value) != 0;
				case kind_t::UINT:
					return std::get<uint32_t>(value) != 0;
				case kind_t::INT:
					return std::get<int32_t>(value) != 0;
				case kind_t::ULONG:
					return std::get<uint64_t>(value) != 0;
				case kind_t::LONG:
					return std::get<int64_t>(value) != 0;
				case kind_t::FLOAT:
					return std::get<float>(value) != 0.0f;
				case kind_t::DOUBLE:
					return std::get<double>(value) != 0.0;
				case kind_t::STRING:
					return !std::get<std::string>(value).empty();
				case kind_t::BOOL:
					return std::get<bool>(value);
			}
			throw std::runtime_error("Unknown literal type");
		}
		uint32_t as_matching(types::primitive_type pt) const {
			switch (pt) {
				case types::primitive_type::BOOL:
					return get_truthiness() ? 1 : 0;
				case types::primitive_type::SIGNED_CHAR:
					switch (kind) {
						case kind_t::CHAR:
							return static_cast<uint32_t>(std::get<char>(value));
						case kind_t::UINT:
							return static_cast<uint32_t>(std::get<uint32_t>(value));
						case kind_t::INT: {
							bool is_negative = std::get<int32_t>(value) < 0;
							return static_cast<uint32_t>(std::get<int32_t>(value) & 0x7F | (is_negative ? 0x80 : 0x00));
						}
						case kind_t::ULONG:
							return static_cast<uint32_t>(std::get<uint64_t>(value));
						case kind_t::LONG: {
							bool is_negative = std::get<int64_t>(value) < 0;
							return static_cast<uint32_t>(std::get<int64_t>(value) & 0x7F | (is_negative ? 0x80 : 0x00));
						}
						case kind_t::BOOL:
							return std::get<bool>(value) ? 1 : 0;
						case kind_t::NULLPTR:
							return 0;
						default:
							throw std::runtime_error("Cannot convert literal to signed char");
					}
				case types::primitive_type::UNSIGNED_CHAR:
					switch (kind) {
						case kind_t::CHAR:
							return static_cast<uint32_t>(static_cast<unsigned char>(std::get<char>(value)));
						case kind_t::UINT:
							return static_cast<uint32_t>(std::get<uint32_t>(value));
						case kind_t::INT:
							return static_cast<uint32_t>(std::get<int32_t>(value) & 0xFF);
						case kind_t::ULONG:
							return static_cast<uint32_t>(std::get<uint64_t>(value));
						case kind_t::LONG:
							return static_cast<uint32_t>(std::get<int64_t>(value) & 0xFF);
						case kind_t::BOOL:
							return std::get<bool>(value) ? 1 : 0;
						case kind_t::NULLPTR:
							return 0;
						default:
							throw std::runtime_error("Cannot convert literal to unsigned char");
					}
				case types::primitive_type::SHORT:
					switch (kind) {
						case kind_t::CHAR:
							return static_cast<uint32_t>(std::get<char>(value));
						case kind_t::UINT:
							return static_cast<uint32_t>(std::get<uint32_t>(value));
						case kind_t::INT: {
							bool is_negative = std::get<int32_t>(value) < 0;
							return static_cast<uint32_t>(std::get<int32_t>(value) & 0x7FFF | (is_negative ? 0x8000 : 0x0000));
						}
						case kind_t::ULONG:
							return static_cast<uint32_t>(std::get<uint64_t>(value));
						case kind_t::LONG: {
							bool is_negative = std::get<int64_t>(value) < 0;
							return static_cast<uint32_t>(std::get<int64_t>(value) & 0x7FFF | (is_negative ? 0x8000 : 0x0000));
						}
						case kind_t::BOOL:
							return std::get<bool>(value) ? 1 : 0;
						case kind_t::NULLPTR:
							return 0;
						default:
							throw std::runtime_error("Cannot convert literal to short");
					}
				case types::primitive_type::UNSIGNED_SHORT:
					switch (kind) {
						case kind_t::CHAR:
							return static_cast<uint32_t>(static_cast<unsigned char>(std::get<char>(value)));
						case kind_t::UINT:
							return static_cast<uint32_t>(std::get<uint32_t>(value));
						case kind_t::INT:
							return static_cast<uint32_t>(std::get<int32_t>(value) & 0xFFFF);
						case kind_t::ULONG:
							return static_cast<uint32_t>(std::get<uint64_t>(value));
						case kind_t::LONG:
							return static_cast<uint32_t>(std::get<int64_t>(value) & 0xFFFF);
						case kind_t::BOOL:
							return std::get<bool>(value) ? 1 : 0;
						case kind_t::NULLPTR:
							return 0;
						default:
							throw std::runtime_error("Cannot convert literal to unsigned short");
					}
				case types::primitive_type::SIGNED_INT:
					return as_int32();
				case types::primitive_type::UNSIGNED_INT:
					return as_uint32();
				case types::primitive_type::SIGNED_LONG:
					return static_cast<uint32_t>(as_int32());
				case types::primitive_type::UNSIGNED_LONG:
					return static_cast<uint32_t>(as_uint32());
				case types::primitive_type::FLOAT:
					return static_cast<uint32_t>(std::get<float>(value));
				case types::primitive_type::DOUBLE:
					return static_cast<uint32_t>(std::get<double>(value));
				case types::primitive_type::VOID:
					return 0;
				default:
					throw std::runtime_error("Cannot convert literal to specified primitive type");
			}
		}

		static literal_expression make_nullptr() {
			return literal_expression(kind_t::NULLPTR, std::monostate{});
		}
		static literal_expression make_char(char c) {
			return literal_expression(kind_t::CHAR, c);
		}
		static literal_expression make_uint(uint32_t u) {
			return literal_expression(kind_t::UINT, u);
		}
		static literal_expression make_int(int32_t i) {
			return literal_expression(kind_t::INT, i);
		}
		static literal_expression make_ulong(uint64_t ul) {
			return literal_expression(kind_t::ULONG, ul);
		}
		static literal_expression make_long(int64_t l) {
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

	inline expression_node make_literal(const literal_expression& lit) {
		return expression_node(literal_expression(lit));
	}
	inline expression_node make_identifier(const std::string& id) {
		return expression_node(identifier_expression(id));
	}
	inline unary_expression make_unary(unary_expression::operator_t op, const expression_node& operand) {
		return unary_expression(op, std::make_shared<expression_node>(operand));
	}
	inline binary_expression make_binary(binary_expression::operator_t op, const expression_node& left,
		const expression_node& right) {
		return binary_expression(op, std::make_shared<expression_node>(left),
			std::make_shared<expression_node>(right));
	}
	inline call_expression make_call(const expression_node& callee,
		const std::vector<expression_node>& args) {
		std::vector<std::shared_ptr<expression_node>> arg_ptrs;
		for (const auto& arg : args) {
			arg_ptrs.push_back(std::make_shared<expression_node>(arg));
		}
		return call_expression(std::make_shared<expression_node>(callee), std::move(arg_ptrs));
	}
	inline member_expression make_member(const expression_node& object, const std::string& member, bool pointer) {
		return member_expression(std::make_shared<expression_node>(object), member, pointer);
	}

	bool has_side_effects(const expression_node& expr);
	expression_node optimize_unary_expression(
		const unary_expression& un
	);
	expression_node optimize_binary_expression(
		const binary_expression& bin
	);
	expression_node optimize_expression(
		const expression_node& expr
	);
} // unqlang::analysis::expressions

template<>
struct std::formatter<
		unqlang::analysis::expressions::expression_node,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::expression_node& expr, auto& ctx) const;
};

template<>
struct std::formatter<
		unqlang::analysis::expressions::literal_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::literal_expression& lit, auto& ctx) const {
		std::string repr;
		switch (lit.kind) {
			case unqlang::analysis::expressions::literal_expression::kind_t::NULLPTR:
				repr = "nullptr";
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::CHAR:
				repr = std::format("'{}'", std::get<char>(lit.value));
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::UINT:
				repr = std::to_string(std::get<unsigned int>(lit.value)) + "u";
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::INT:
				repr = std::to_string(std::get<int>(lit.value));
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::ULONG:
				repr = std::to_string(std::get<uint64_t>(lit.value)) + "ul";
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::LONG:
				repr = std::to_string(std::get<int64_t>(lit.value)) + "l";
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::FLOAT:
				repr = std::to_string(std::get<float>(lit.value)) + "f";
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::DOUBLE:
				repr = std::to_string(std::get<double>(lit.value));
				break;
			case unqlang::analysis::expressions::literal_expression::kind_t::STRING: {
				std::string s = std::get<std::string>(lit.value);
				std::string escaped;
				escaped.reserve(s.size());
				for (char c : s) {
					switch (c) {
						case '\n':
							escaped += "\\n";
							break;
						case '\t':
							escaped += "\\t";
							break;
						case '\r':
							escaped += "\\r";
							break;
						case '\"':
							escaped += "\\\"";
							break;
						case '\\':
							escaped += "\\\\";
							break;
						default:
							escaped += c;
							break;
					}
				}
				repr = std::format("\"{}\"", escaped);
				break;
			}
			case unqlang::analysis::expressions::literal_expression::kind_t::BOOL:
				repr = std::get<bool>(lit.value) ? "true" : "false";
				break;
			default:
				repr = "<unknown literal>";
				break;
		}
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};

template<>
struct std::formatter<
		unqlang::analysis::expressions::identifier_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::identifier_expression& id, auto& ctx) const {
		return std::formatter<std::string, char>::format(id.name, ctx);
	}
};

template<>
struct std::formatter<
		unqlang::analysis::expressions::binary_expression::operator_t,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::binary_expression::operator_t& op, auto& ctx) const {
		std::string repr;
		switch (op) {
			case unqlang::analysis::expressions::binary_expression::operator_t::ADD:
				repr = "+";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::SUB:
				repr = "-";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::MUL:
				repr = "*";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::DIV:
				repr = "/";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::MOD:
				repr = "%";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::AND:
				repr = "&";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::OR:
				repr = "|";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::XOR:
				repr = "^";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::SHL:
				repr = "<<";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::SHR:
				repr = ">>";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::LAND:
				repr = "&&";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::LOR:
				repr = "||";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::EQ:
				repr = "==";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::NEQ:
				repr = "!=";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::LT:
				repr = "<";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::GT:
				repr = ">";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::LTE:
				repr = "<=";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::GTE:
				repr = ">=";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::ASSIGN:
				repr = "=";
				break;
			case unqlang::analysis::expressions::binary_expression::operator_t::ARRAY_SUBSCRIPT:
				repr = "[]";
				break;
			default:
				repr = "<unknown binary operator>";
				break;
		}
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};

template<>
struct std::formatter<
		unqlang::analysis::expressions::binary_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::binary_expression& bin, auto& ctx) const {
		std::string repr;
		if (bin.op == unqlang::analysis::expressions::binary_expression::operator_t::ARRAY_SUBSCRIPT) {
			repr = std::format("{}[{}]", *bin.left, *bin.right);
		}
		else {
			repr = std::format("({} {} {})", *bin.left, bin.op, *bin.right);
		}
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};

template<>
struct std::formatter<
		unqlang::analysis::expressions::unary_expression::operator_t,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::unary_expression::operator_t& op, auto& ctx) const {
		std::string repr;
		switch (op) {
			case unqlang::analysis::expressions::unary_expression::operator_t::PLUS:
				repr = "+";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::MINUS:
				repr = "-";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::PRE_INC:
				repr = "++";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::PRE_DEC:
				repr = "--";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::POST_INC:
				repr = "++";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::POST_DEC:
				repr = "--";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::NOT:
				repr = "~";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::LNOT:
				repr = "!";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::DEREFERENCE:
				repr = "*";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::ADDRESS_OF:
				repr = "&";
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::SIZEOF:
				repr = "sizeof";
				break;
			default:
				repr = "<unknown unary operator>";
				break;
		}
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};
template<>
struct std::formatter<
		unqlang::analysis::expressions::unary_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::unary_expression& un, auto& ctx) const {
		std::string repr;
		switch (un.op) {
			case unqlang::analysis::expressions::unary_expression::operator_t::ADDRESS_OF:
			case unqlang::analysis::expressions::unary_expression::operator_t::DEREFERENCE:
			case unqlang::analysis::expressions::unary_expression::operator_t::LNOT:
			case unqlang::analysis::expressions::unary_expression::operator_t::NOT:
			case unqlang::analysis::expressions::unary_expression::operator_t::PLUS:
			case unqlang::analysis::expressions::unary_expression::operator_t::MINUS:
			case unqlang::analysis::expressions::unary_expression::operator_t::PRE_INC:
			case unqlang::analysis::expressions::unary_expression::operator_t::PRE_DEC:
				repr = std::format("({}{})", un.op, *un.operand);
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::POST_INC:
			case unqlang::analysis::expressions::unary_expression::operator_t::POST_DEC:
				repr = std::format("({}{})", *un.operand, un.op);
				break;
			case unqlang::analysis::expressions::unary_expression::operator_t::SIZEOF:
				repr = std::format("({} {})", un.op, *un.operand);
				break;
			default:
				repr = std::format("({}{})", un.op, *un.operand);
				break;
		}
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};
template<>
struct std::formatter<
		unqlang::analysis::expressions::call_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::call_expression& call, auto& ctx) const {
		std::string args_repr;
		for (size_t i = 0; i < call.arguments.size(); ++i) {
			args_repr += std::format("{}", *call.arguments[i]);
			if (i < call.arguments.size() - 1) {
				args_repr += ", ";
			}
		}
		std::string repr = std::format("{}({})", *call.callee, args_repr);
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};
template<>
struct std::formatter<
		unqlang::analysis::expressions::member_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::member_expression& mem, auto& ctx) const {
		std::string repr = std::format("{}{}{}", *mem.object, mem.pointer ? "->" : ".", mem.member);
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};
template<>
struct std::formatter<
		unqlang::analysis::expressions::ternary_expression,
		char> : std::formatter<std::string, char> {
	auto format(const unqlang::analysis::expressions::ternary_expression& ter, auto& ctx) const {
		std::string repr = std::format("({} ? {} : {})", *ter.condition, *ter.then_branch, *ter.else_branch);
		return std::formatter<std::string, char>::format(repr, ctx);
	}
};
auto std::formatter<
	unqlang::analysis::expressions::expression_node,
	char>::format(const unqlang::analysis::expressions::expression_node& expr, auto& ctx) const {
	std::string repr;
	switch (expr.kind) {
		case unqlang::analysis::expressions::expression_node::kind_t::LITERAL:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::literal_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::IDENTIFIER:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::identifier_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::BINARY:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::binary_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::UNARY:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::unary_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::CALL:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::call_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::MEMBER:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::member_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::TERNARY:
			repr = std::format("{}", std::get<unqlang::analysis::expressions::ternary_expression>(expr.value));
			break;
		case unqlang::analysis::expressions::expression_node::kind_t::UNKNOWN:
			repr = "<unknown expression>";
			break;
		default:
			repr = "<unknown expression>";
			break;
	}
	return std::formatter<std::string, char>::format(repr, ctx);
}
