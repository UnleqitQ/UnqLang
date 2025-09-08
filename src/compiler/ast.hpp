#pragma once

#include <string>
#include <vector>
#include <variant>
#include <memory>
#include "lexer.hpp"

namespace compiler {
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
			// Char,
			Bool,
			Pointer,
			Array,
			Function,
			Struct,
			Custom // typedef or user-defined type
		} type;
		std::variant<
			std::monostate, // Void, Int, Float, Char, Bool
			ast_type_pointer, // Pointer
			ast_type_array, // Array
			ast_type_function, // Function
			ast_type_members, // Struct
			std::string // Custom
		> value;
		ast_type_node() : type(type_t::Void), value(std::monostate{}) {
		}
		ast_type_node(type_t t, auto&& v) : type(t), value(std::forward<decltype(v)>(v)) {
		}

		friend std::ostream& operator<<(std::ostream& os, const ast_type_node& node);
		void print(int indent = 0) const;
	};

	// main AST
	struct ast_node;
	struct ast_member_access {
		std::shared_ptr<ast_node> object;
		std::string property;
		bool pointer; // true if '->', false if '.'
		void print(int indent = 0) const;
	};
	struct ast_expression_ternary {
		std::shared_ptr<ast_node> condition;
		std::shared_ptr<ast_node> then_branch;
		std::shared_ptr<ast_node> else_branch;
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
		std::shared_ptr<ast_node> left;
		std::shared_ptr<ast_node> right;
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
		std::shared_ptr<ast_node> operand;
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
		std::shared_ptr<ast_node> callee;
		std::vector<std::shared_ptr<ast_node>> arguments;
		void print(int indent = 0) const;
	};
	struct ast_statement_variable_declaration {
		std::string name;
		std::shared_ptr<ast_type_node> var_type; // For now must be specified
		std::shared_ptr<ast_node> initializer; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_function_declaration {
		std::string name;
		std::vector<std::pair<std::string, std::shared_ptr<ast_type_node>>> parameters; // (name, type)
		std::shared_ptr<ast_type_node> return_type; // For now must be specified
		std::shared_ptr<ast_node> body; // Must be a BlockStatement
		void print(int indent = 0) const;
	};
	struct ast_statement_struct_declaration {
		std::string name;
		ast_type_members body;
		void print(int indent = 0) const;
	};
	struct ast_statement_if {
		std::shared_ptr<ast_node> condition;
		std::shared_ptr<ast_node> then_branch;
		std::shared_ptr<ast_node> else_branch; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_while {
		std::shared_ptr<ast_node> condition;
		std::shared_ptr<ast_node> body;
		void print(int indent = 0) const;
	};
	struct ast_statement_return {
		std::shared_ptr<ast_node> value; // Can be null
		void print(int indent = 0) const;
	};
	struct ast_statement_expression {
		std::shared_ptr<ast_node> expression;
		void print(int indent = 0) const;
	};
	struct ast_statement_block {
		std::vector<std::shared_ptr<ast_node>> statements;
		void print(int indent = 0) const;
	};

	struct ast_node {
		enum class type_t {
			IntegerLiteral,
			// FloatLiteral,
			// StringLiteral,
			Identifier,
			MemberAccess,
			TernaryExpression,
			UnaryExpression,
			BinaryExpression,
			FunctionCall,
			IfStatement,
			WhileStatement,
			// ForStatement,
			ReturnStatement,
			ExpressionStatement,
			BlockStatement,

			VariableDeclaration,
			FunctionDeclaration,
			StructDeclaration,

			Unknown,
		} type;
		std::variant<
			int, // IntegerLiteral
			// double, // FloatLiteral
			std::string, // (StringLiteral), Identifier
			ast_expression_binary, // BinaryExpression
			ast_expression_unary, // UnaryExpression
			ast_member_access, // MemberAccess
			ast_expression_ternary, // TernaryExpression
			ast_expression_call, // FunctionCall
			ast_statement_if, // IfStatement
			ast_statement_while, // WhileStatement
			ast_statement_return, // ReturnStatement
			ast_statement_expression, // ExpressionStatement
			ast_statement_block, // BlockStatement

			ast_statement_variable_declaration, // VariableDeclaration
			ast_statement_function_declaration, // FunctionDeclaration
			ast_statement_struct_declaration, // StructDeclaration

			std::monostate // Unknown
		> value;
		ast_node() : type(type_t::Unknown), value(std::monostate{}) {
		}
		ast_node(type_t t, auto&& v) : type(t), value(std::forward<decltype(v)>(v)) {
		}

		friend std::ostream& operator<<(std::ostream& os, const ast_node& node);
		void print(int indent = 0) const;
	};

	struct ast_program {
		typedef std::variant<
			ast_statement_function_declaration, // Function declarations
			ast_statement_struct_declaration // Struct declarations
		> program_element_t;
		std::vector<program_element_t> body;

		ast_program() {
		}
		explicit ast_program(std::vector<program_element_t> elements) : body(std::move(elements)) {
		}

		friend std::ostream& operator<<(std::ostream& os, const ast_program& program);

		void print(int indent = 0) const;
	};

	std::shared_ptr<ast_type_node> parse_ast_type(const std::vector<lexer_token>& tokens);
	std::shared_ptr<ast_node> parse_ast(const std::vector<lexer_token>& tokens);
	ast_program parse_ast_program(const std::vector<lexer_token>& tokens);
} // compiler
