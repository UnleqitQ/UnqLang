#pragma once

#include <string>
#include <vector>
#include <variant>
#include <memory>

#include "lexer.hpp"

namespace unqlang {
	// type system AST
	struct ast_type_node;
	struct ast_type_pointer {
		std::shared_ptr<ast_type_node> base;
		void print(int indent = 0) const;
	};
	struct ast_type_array {
		std::shared_ptr<ast_type_node> base;
		size_t size; // 0 if unknown size
		void print(int indent = 0) const;
	};
	struct ast_type_function {
		std::shared_ptr<ast_type_node> return_type;
		std::vector<std::shared_ptr<ast_type_node>> parameters;
		void print(int indent = 0) const;
	};
	struct ast_type_member {
		std::string name;
		std::shared_ptr<ast_type_node> type;
		void print(int indent = 0) const;
	};
	struct ast_type_members {
		std::vector<ast_type_member> members;
		void print(int indent = 0) const;
	};
	struct ast_type_node {
		enum class type_t {
			Void,
			Int,
			// Float,
			Char,
			Bool,
			Pointer,
			Array,
			Function,
			Struct,
			Union,
			Custom // typedef or reference to named type
		} type;
		std::variant<
			std::monostate, // Void, Int, Float, Char, Bool
			ast_type_pointer, // Pointer
			ast_type_array, // Array
			ast_type_function, // Function
			ast_type_members, // Struct, Union
			std::string // Custom
		> value;
		ast_type_node() : type(type_t::Void), value(std::monostate{}) {
		}
		ast_type_node(type_t t, std::monostate) : type(t) {
			if (t == type_t::Pointer || t == type_t::Array || t == type_t::Function || t == type_t::Struct ||
				t == type_t::Union || t == type_t::Custom) {
				throw std::invalid_argument(
					"Type must not be Pointer, Array, Function, Struct, Union or Custom for ast_type_node with monostate");
			}
			value = std::monostate{};
		}
		ast_type_node(type_t type, const ast_type_pointer& p) : type(type), value(p) {
			if (type != type_t::Pointer) {
				throw std::invalid_argument("Type must be Pointer for ast_type_pointer");
			}
		}
		ast_type_node(type_t type, const ast_type_array& a) : type(type), value(a) {
			if (type != type_t::Array) {
				throw std::invalid_argument("Type must be Array for ast_type_array");
			}
		}
		ast_type_node(type_t type, const ast_type_function& f) : type(type), value(f) {
			if (type != type_t::Function) {
				throw std::invalid_argument("Type must be Function for ast_type_function");
			}
		}
		ast_type_node(type_t type, const ast_type_members& m) : type(type), value(m) {
			if (type != type_t::Struct && type != type_t::Union) {
				throw std::invalid_argument("Type must be Struct or Union for ast_type_members");
			}
		}
		ast_type_node(type_t type, const std::string& name) : type(type), value(name) {
			if (type != type_t::Custom) {
				throw std::invalid_argument("Type must be Custom for string name");
			}
		}

		friend std::ostream& operator<<(std::ostream& stream, const ast_type_node& n);
		void print(int indent = 0) const;

		bool operator==(const ast_type_node& other) const {
			if (type != other.type) {
				return false;
			}
			switch (type) {
				case type_t::Void:
				case type_t::Int:
				case type_t::Char:
				case type_t::Bool:
					return true; // No additional data to compare
				case type_t::Pointer: {
					const auto& p1 = std::get<ast_type_pointer>(value);
					const auto& p2 = std::get<ast_type_pointer>(other.value);
					return *p1.base == *p2.base;
				}
				case type_t::Array: {
					const auto& a1 = std::get<ast_type_array>(value);
					const auto& a2 = std::get<ast_type_array>(other.value);
					return a1.size == a2.size && *a1.base == *a2.base;
				}
				case type_t::Function: {
					const auto& f1 = std::get<ast_type_function>(value);
					const auto& f2 = std::get<ast_type_function>(other.value);
					if (*f1.return_type != *f2.return_type || f1.parameters.size() != f2.parameters.size()) {
						return false;
					}
					for (size_t i = 0; i < f1.parameters.size(); ++i) {
						if (*f1.parameters[i] != *f2.parameters[i]) {
							return false;
						}
					}
					return true;
				}
				case type_t::Struct: {
					const auto& s1 = std::get<ast_type_members>(value);
					const auto& s2 = std::get<ast_type_members>(other.value);
					if (s1.members.size() != s2.members.size()) {
						return false;
					}
					for (size_t i = 0; i < s1.members.size(); ++i) {
						if (*s1.members[i].type != *s2.members[i].type) {
							return false;
						}
					}
					return true;
				}
				case type_t::Union: {
					const auto& u1 = std::get<ast_type_members>(value);
					const auto& u2 = std::get<ast_type_members>(other.value);
					if (u1.members.size() != u2.members.size()) {
						return false;
					}
					for (size_t i = 0; i < u1.members.size(); ++i) {
						if (*u1.members[i].type != *u2.members[i].type) {
							return false;
						}
					}
					return true;
				}
				case type_t::Custom: {
					const auto& name1 = std::get<std::string>(value);
					const auto& name2 = std::get<std::string>(other.value);
					return name1 == name2;
				}
			}
			return false; // Should not reach here
		}
		bool operator!=(const ast_type_node& other) const {
			return !(*this == other);
		}
	};

	// expression AST
	struct ast_expression_node;
	struct ast_expression_literal {
		enum class type_t {
			Integer,
			// Float,
			String,
			Char,
			Boolean,
			Null,
		} type;
		std::variant<
			int, // Integer
			// double, // Float
			std::string, // String
			char, // Char
			bool, // Boolean
			std::monostate // Null
		> value;
		ast_expression_literal() : type(type_t::Null), value(std::monostate{}) {
		}
		ast_expression_literal(type_t t, auto&& v) : type(t), value(std::forward<decltype(v)>(v)) {
		}

		bool operator==(const ast_expression_literal& other) const {
			if (type != other.type) {
				return false;
			}
			return value == other.value;
		}
		bool operator!=(const ast_expression_literal& other) const {
			return !(*this == other);
		}

		ast_type_node get_type() const {
			switch (type) {
				case type_t::Integer:
					return ast_type_node(ast_type_node::type_t::Int, std::monostate{});
				case type_t::String:
					return ast_type_node(ast_type_node::type_t::Pointer, ast_type_pointer{
						std::make_shared<ast_type_node>(ast_type_node::type_t::Char, std::monostate{})
					});
				case type_t::Char:
					return ast_type_node(ast_type_node::type_t::Char, std::monostate{});
				case type_t::Boolean:
					return ast_type_node(ast_type_node::type_t::Bool, std::monostate{});
				case type_t::Null:
					return ast_type_node(ast_type_node::type_t::Pointer, ast_type_pointer{
						std::make_shared<ast_type_node>(ast_type_node::type_t::Void, std::monostate{})
					});
				default:
					throw std::runtime_error("Unknown literal type");
			}
		}

		void print(int indent = 0) const;
	};
	struct ast_member_access {
		std::shared_ptr<ast_expression_node> object;
		std::string property;
		bool pointer; // true if '->', false if '.'
		void print(int indent = 0) const;
	};
	struct ast_expression_ternary {
		std::shared_ptr<ast_expression_node> condition;
		std::shared_ptr<ast_expression_node> then;
		std::shared_ptr<ast_expression_node> otherwise;
		void print(int indent = 0) const;
	};
	struct ast_expression_binary {
		enum class type_t {
			Add,
			Subtract,
			Multiply,
			Divide,
			Modulo,
			BitwiseAnd,
			BitwiseOr,
			BitwiseXor,
			ShiftLeft,
			ShiftRight,
			Assignment,
			Equal,
			NotEqual,
			Less,
			LessEqual,
			Greater,
			GreaterEqual,
			LogicalAnd,
			LogicalOr,
			ArraySubscript,
			Comma,
		} type;
		std::shared_ptr<ast_expression_node> left;
		std::shared_ptr<ast_expression_node> right;
		void print(int indent = 0) const;
	};
	inline std::ostream& operator<<(std::ostream& os, const ast_expression_binary::type_t& type) {
		switch (type) {
			case ast_expression_binary::type_t::Add: os << "+";
				break;
			case ast_expression_binary::type_t::Subtract: os << "-";
				break;
			case ast_expression_binary::type_t::Multiply: os << "*";
				break;
			case ast_expression_binary::type_t::Divide: os << "/";
				break;
			case ast_expression_binary::type_t::Modulo: os << "%";
				break;
			case ast_expression_binary::type_t::BitwiseAnd: os << "&";
				break;
			case ast_expression_binary::type_t::BitwiseOr: os << "|";
				break;
			case ast_expression_binary::type_t::BitwiseXor: os << "^";
				break;
			case ast_expression_binary::type_t::ShiftLeft: os << "<<";
				break;
			case ast_expression_binary::type_t::ShiftRight: os << ">>";
				break;
			case ast_expression_binary::type_t::Assignment: os << "=";
				break;
			case ast_expression_binary::type_t::Equal: os << "==";
				break;
			case ast_expression_binary::type_t::NotEqual: os << "!=";
				break;
			case ast_expression_binary::type_t::Less: os << "<";
				break;
			case ast_expression_binary::type_t::LessEqual: os << "<=";
				break;
			case ast_expression_binary::type_t::Greater: os << ">";
				break;
			case ast_expression_binary::type_t::GreaterEqual: os << ">=";
				break;
			case ast_expression_binary::type_t::LogicalAnd: os << "&&";
				break;
			case ast_expression_binary::type_t::LogicalOr: os << "||";
				break;
			case ast_expression_binary::type_t::ArraySubscript: os << "[]";
				break;
			case ast_expression_binary::type_t::Comma: os << ",";
		}
		return os;
	}
	struct ast_expression_unary {
		enum class type_t {
			Negate, // - (arithmetic negation)
			Positive, // + (unary plus)
			LogicalNot, // !
			BitwiseNot, // ~
			PostfixIncrement, // ++ (postfix)
			PostfixDecrement, // -- (postfix)
			PrefixIncrement, // ++ (prefix)
			PrefixDecrement, // -- (prefix)
			Dereference, // *
			AddressOf, // &
			SizeOf, // sizeof
		} type;
		std::shared_ptr<ast_expression_node> operand;
		void print(int indent = 0) const;
	};
	inline std::ostream& operator<<(std::ostream& os, const ast_expression_unary::type_t& type) {
		switch (type) {
			case ast_expression_unary::type_t::Negate: os << "-";
				break;
			case ast_expression_unary::type_t::Positive: os << "+";
				break;
			case ast_expression_unary::type_t::LogicalNot: os << "!";
				break;
			case ast_expression_unary::type_t::BitwiseNot: os << "~";
				break;
			case ast_expression_unary::type_t::PostfixIncrement: os << "[]++";
				break;
			case ast_expression_unary::type_t::PostfixDecrement: os << "[]--";
				break;
			case ast_expression_unary::type_t::PrefixIncrement: os << "++[]";
				break;
			case ast_expression_unary::type_t::PrefixDecrement: os << "--[]";
				break;
			case ast_expression_unary::type_t::Dereference: os << "*";
				break;
			case ast_expression_unary::type_t::AddressOf: os << "&";
				break;
			case ast_expression_unary::type_t::SizeOf: os << "sizeof";
				break;
		}
		return os;
	}
	struct ast_expression_call {
		std::shared_ptr<ast_expression_node> callee;
		std::vector<std::shared_ptr<ast_expression_node>> arguments;
		void print(int indent = 0) const;
	};

	struct ast_expression_node {
		enum class type_t {
			Literal,
			Identifier,
			MemberAccess,
			Ternary,
			Unary,
			Binary,
			FunctionCall,

			Unknown,
		} type;
		std::variant<
			ast_expression_literal, // Literal
			std::string, // Identifier
			ast_expression_binary, // Binary
			ast_expression_unary, // Unary
			ast_member_access, // MemberAccess
			ast_expression_ternary, // Ternary
			ast_expression_call, // FunctionCall
			std::monostate // Unknown
		> value;
		ast_expression_node() : type(type_t::Unknown), value(std::monostate{}) {
		}
		ast_expression_node(type_t t, auto&& v) : type(t), value(std::forward<decltype(v)>(v)) {
		}

		void print(int indent = 0) const;
	};

	// statement AST
	struct ast_statement_node;

	struct ast_statement_if {
		std::shared_ptr<ast_expression_node> condition;
		std::shared_ptr<ast_statement_node> then_branch;
		std::shared_ptr<ast_statement_node> else_branch; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_while {
		std::shared_ptr<ast_expression_node> condition;
		std::shared_ptr<ast_statement_node> body;
		void print(int indent = 0) const;
	};
	struct ast_statement_return {
		std::shared_ptr<ast_expression_node> value; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_expression {
		std::shared_ptr<ast_expression_node> expression;
		void print(int indent = 0) const;
	};
	struct ast_statement_block {
		std::vector<std::shared_ptr<ast_statement_node>> statements;
		void print(int indent = 0) const;
	};
	struct ast_statement_function_declaration {
		std::string name;
		std::vector<std::pair<std::string, std::shared_ptr<ast_type_node>>> parameters; // (name, type)
		std::shared_ptr<ast_type_node> return_type; // For now must be specified
		std::shared_ptr<ast_statement_block> body; // Can be null (for forward declarations)
		void print(int indent = 0) const;
	};
	struct ast_statement_variable_declaration {
		std::string name;
		std::shared_ptr<ast_type_node> var_type; // For now must be specified
		std::shared_ptr<ast_expression_node> initializer; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_struct_declaration {
		std::string name;
		std::shared_ptr<ast_type_members> body;
		void print(int indent = 0) const;
	};
	struct ast_statement_union_declaration {
		std::string name;
		std::shared_ptr<ast_type_members> body;
		void print(int indent = 0) const;
	};
	struct ast_statement_type_declaration {
		std::string name;
		std::shared_ptr<ast_type_node> aliased_type;
		void print(int indent = 0) const;
	};

	struct ast_statement_node {
		enum class type_t {
			VariableDeclaration,
			FunctionDeclaration,
			StructDeclaration,
			UnionDeclaration,
			TypeDeclaration, // typedef
			IfStatement,
			WhileStatement,
			ReturnStatement,
			ExpressionStatement,
			BlockStatement,

			Unknown,
		} type;
		std::variant<
			ast_statement_if, // IfStatement
			ast_statement_while, // WhileStatement
			ast_statement_return, // ReturnStatement
			ast_statement_expression, // ExpressionStatement
			ast_statement_block, // BlockStatement

			ast_statement_variable_declaration, // VariableDeclaration
			ast_statement_function_declaration, // FunctionDeclaration
			ast_statement_struct_declaration, // StructDeclaration
			ast_statement_union_declaration, // UnionDeclaration
			ast_statement_type_declaration, // TypeDeclaration

			std::monostate // Unknown
		> value;
		ast_statement_node() : type(type_t::Unknown), value(std::monostate{}) {
		}
		ast_statement_node(type_t t, auto&& v) : type(t), value(std::forward<decltype(v)>(v)) {
		}

		void print(int indent = 0) const;
	};

	struct ast_program {
		typedef std::variant<
			ast_statement_function_declaration, // Function declarations
			ast_statement_struct_declaration, // Struct declarations
			ast_statement_union_declaration, // Union declarations
			ast_statement_type_declaration, // Type declarations (typedefs)
			ast_statement_variable_declaration // Global variable declarations
		> program_element_t;
		std::vector<program_element_t> body;

		ast_program() {
		}
		explicit ast_program(std::vector<program_element_t> elements) : body(std::move(elements)) {
		}

		void print(int indent = 0) const;
	};

	std::shared_ptr<ast_type_node> parse_ast_type(const std::vector<lexer_token>& tokens);
	std::shared_ptr<ast_expression_node> parse_ast_expression(const std::vector<lexer_token>& tokens);
	std::shared_ptr<ast_statement_node> parse_ast_statement(const std::vector<lexer_token>& tokens);
	ast_program parse_ast_program(const std::vector<lexer_token>& tokens);
} // compiler

template<>
struct std::hash<unqlang::ast_expression_literal> {
	size_t operator()(const unqlang::ast_expression_literal& lit) const noexcept {
		size_t h1 = std::hash<int>()(static_cast<int>(lit.type));
		size_t h2 = 0;
		switch (lit.type) {
			case unqlang::ast_expression_literal::type_t::Integer:
				h2 = std::hash<int>()(std::get<int>(lit.value));
				break;
			case unqlang::ast_expression_literal::type_t::String:
				h2 = std::hash<std::string>()(std::get<std::string>(lit.value));
				break;
			case unqlang::ast_expression_literal::type_t::Char:
				h2 = std::hash<char>()(std::get<char>(lit.value));
				break;
			case unqlang::ast_expression_literal::type_t::Boolean:
				h2 = std::hash<bool>()(std::get<bool>(lit.value));
				break;
			case unqlang::ast_expression_literal::type_t::Null:
				h2 = 0; // No additional data
				break;
		}
		return h1 ^ (h2 << 1); // Combine hashes
	}
};
