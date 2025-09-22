#include "ast.hpp"
#include <iostream>
#include <numeric>

#include "../parser.hpp"
#include "../shift_reduce_parser.hpp"

namespace unqlang {
	// utility functions
	namespace util {
		std::string lexer_token_type_to_string(const lexer_token::type_t type) {
			switch (type) {
				case lexer_token::type_t::Identifier: return "IDENTIFIER";
				case lexer_token::type_t::Integer: return "INTEGER";
				case lexer_token::type_t::UnsignedInteger: return "UNSIGNED_INTEGER";
				case lexer_token::type_t::String: return "STRING";
				case lexer_token::type_t::Operator: return "OPERATOR";
				case lexer_token::type_t::Punctuation: return "PUNCTUATION";
				case lexer_token::type_t::Keyword: return "KEYWORD";
				case lexer_token::type_t::Comment: return "COMMENT";
				default: return "UNKNOWN";
			}
		}

		template<typename T>
		std::shared_ptr<ast_expression_node> make_ast_expression_node(ast_expression_node::type_t type, T value) {
			return std::make_shared<ast_expression_node>(type, value);
		}
		template<typename T>
		std::shared_ptr<ast_statement_node> make_ast_statement_node(ast_statement_node::type_t type, T value) {
			return std::make_shared<ast_statement_node>(type, value);
		}

		Parser<lexer_token, lexer_token> token_type(lexer_token::type_t type) {
			return Parser<lexer_token, lexer_token>(
				[type](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output,
				ParserTable&) {
					if (!input.empty() && input[0].type == type) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(token_type {})", lexer_token_type_to_string(type))
			);
		}

		Parser<lexer_token, lexer_token> keyword(const std::string& kw) {
			return Parser<lexer_token, lexer_token>(
				[kw](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Keyword &&
						std::get<std::string>(input[0].value) == kw) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(keyword \"{}\")", kw)
			);
		}
		Parser<lexer_token, lexer_token> identifier() {
			return Parser<lexer_token, lexer_token>(
				[](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Identifier) {
						output.emplace_back(input[0], 1);
					}
				},
				"(identifier)"
			);
		}
		Parser<lexer_token, lexer_token> integer() {
			return token_type(lexer_token::type_t::Integer);
		}
		Parser<lexer_token, lexer_token> op(const operator_type_t o) {
			return Parser<lexer_token, lexer_token>(
				[o](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Operator &&
						std::get<operator_type_t>(input[0].value) == o) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(operator '{}')", o)
			);
		}
		Parser<lexer_token, lexer_token> op(const std::string_view o) {
			return op(lexer_parse_operator_type(std::string(o)));
		}
		Parser<lexer_token, lexer_token> op(const std::vector<operator_type_t> ops) {
			return Parser<lexer_token, lexer_token>(
				[ops](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output,
				ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Operator) {
						operator_type_t o = std::get<operator_type_t>(input[0].value);
						if (std::ranges::find(ops, o) != ops.end()) {
							output.emplace_back(input[0], 1);
						}
					}
				},
				std::format("(operator [{}])", std::accumulate(std::next(ops.begin()), ops.end(),
					std::format("{}", *ops.begin()),
					[](const std::string& a, const operator_type_t b) { return a + ", " + std::format("{}", b); }))
			);
		}
		Parser<lexer_token, lexer_token> op(const std::vector<std::string_view> ops) {
			std::vector<operator_type_t> op_types;
			for (const auto& op : ops) {
				op_types.push_back(lexer_parse_operator_type(std::string(op)));
			}
			return op(op_types);
		}
		Parser<lexer_token, lexer_token> op(const std::initializer_list<std::string_view> ops) {
			return op(std::vector<std::string_view>(ops));
		}
		Parser<lexer_token, lexer_token> punctuation(const punctuation_type_t p) {
			return Parser<lexer_token, lexer_token>(
				[p](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Punctuation &&
						std::get<punctuation_type_t>(input[0].value) == p) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(punctuation '{}')", p)
			);
		}
		Parser<lexer_token, lexer_token> punctuation(char p) {
			return punctuation(lexer_parse_punctuation_type(p));
		}
	} // util

	namespace type_parser {
		typedef Parser<lexer_token, std::shared_ptr<ast_type_node>> ast_type_parser_t;

		// Forward declarations for recursive parsers
		const ast_type_parser_t ref_ast_type_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_type_node>>("ast_type_parser");

		const Parser<lexer_token, lexer_token> ast_type_builtin_raw_integral_parser =
			util::keyword("int") || util::keyword("char") ||
			util::keyword("short") < ~util::keyword("int");
		const ast_type_parser_t ast_type_builtin_integral_parser =
			(~(util::keyword("signed") || util::keyword("unsigned")) +
				~ast_type_builtin_raw_integral_parser)
			.filter(
				[](const auto& p) { return p.first.has_value() || p.second.has_value(); },
				"IntegralTypeFilter"
			)
			.map<std::shared_ptr<ast_type_node>>(
				[](const auto& p) {
					if (!p.second.has_value()) {
						if (!p.first.has_value()) {
							throw std::runtime_error("Invalid integral type");
						}
						// Only signed/unsigned specified, default to int
						bool is_unsigned = std::get<std::string>(p.first->value) == "unsigned";
						return std::make_shared<ast_type_node>(
							is_unsigned ? ast_type_node::type_t::UnsignedInt : ast_type_node::type_t::Int,
							std::monostate{}
						);
					}
					std::string type_str = std::get<std::string>(p.second->value);
					bool is_unsigned;
					if (p.first.has_value()) {
						is_unsigned = std::get<std::string>(p.first->value) == "unsigned";
					}
					else {
						is_unsigned = type_str == "char"; // char is unsigned by default
					}
					if (type_str == "int") {
						return std::make_shared<ast_type_node>(
							is_unsigned ? ast_type_node::type_t::UnsignedInt : ast_type_node::type_t::Int,
							std::monostate{}
						);
					}
					if (type_str == "char") {
						return std::make_shared<ast_type_node>(
							is_unsigned ? ast_type_node::type_t::Char : ast_type_node::type_t::SignedChar,
							std::monostate{}
						);
					}
					if (type_str == "short") {
						return std::make_shared<ast_type_node>(
							is_unsigned ? ast_type_node::type_t::UnsignedShort : ast_type_node::type_t::Short,
							std::monostate{}
						);
					}
					throw std::runtime_error("Unknown integral type: " + type_str);
				},
				"IntegralType"
			).rename("IntegralType");

		const ast_type_parser_t ast_type_builtin_void_parser =
			util::keyword("void").map<std::shared_ptr<ast_type_node>>(
				[](const lexer_token&) {
					return std::make_shared<ast_type_node>(ast_type_node::type_t::Void, std::monostate{});
				},
				"VoidType"
			).rename("VoidType");
		const ast_type_parser_t ast_type_builtin_bool_parser =
			util::keyword("bool").map<std::shared_ptr<ast_type_node>>(
				[](const lexer_token&) {
					return std::make_shared<ast_type_node>(ast_type_node::type_t::Bool, std::monostate{});
				},
				"BoolType"
			).rename("BoolType");
		const ast_type_parser_t ast_type_builtin_parser = (
			ast_type_builtin_void_parser ||
			ast_type_builtin_bool_parser ||
			ast_type_builtin_integral_parser
		).rename("BuiltinType");
		const ast_type_parser_t ast_type_custom_parser =
			util::identifier().map<std::shared_ptr<ast_type_node>>(
				[](const lexer_token& tok) {
					return std::make_shared<ast_type_node>(
						ast_type_node::type_t::Custom,
						std::get<std::string>(tok.value)
					);
				},
				"CustomType"
			).rename("CustomType");
		const Parser<lexer_token, std::variant<std::monostate, unsigned int>> ast_type_suffix_parser =
			(util::punctuation('[') >
				~util::integer()
				< util::punctuation(']'))
			.map<std::variant<std::monostate, unsigned int>>(
				[](const auto& tok) {
					if (tok.has_value()) {
						// sized array
						return std::variant<std::monostate, unsigned int>{
							static_cast<unsigned int>(std::get<int>(tok->value))
						};
					}
					// an unsized array is treated as a pointer
					return std::variant<std::monostate, unsigned int>{std::monostate{}};
				},
				"ArrayType"
			).rename("ArrayType") ||
			util::op("*").map<std::variant<std::monostate, unsigned int>>(
				[](const lexer_token&) {
					return std::variant<std::monostate, unsigned int>{std::monostate{}};
				},
				"PointerType"
			).rename("PointerType");
		const ast_type_parser_t ast_type_simple_parser = ast_type_builtin_parser ||
			ast_type_custom_parser;
		const Parser<lexer_token, ast_type_member> ast_type_member_parser =
			(ref_ast_type_parser + util::identifier() < util::punctuation(';'))
			.map<ast_type_member>(
				[](const auto& p) {
					ast_type_member member;
					member.name = std::get<std::string>(p.second.value);
					member.type = p.first;
					return member;
				},
				"CompositeMember"
			).rename("CompositeMember");
		const Parser<lexer_token, ast_type_members> ast_type_members_parser =
			(util::punctuation('{') >
				*ast_type_member_parser
				< util::punctuation('}'))
			.map<ast_type_members>(
				[](const std::vector<ast_type_member>& members) {
					ast_type_members mems;
					mems.members = members;
					return mems;
				},
				"CompositeMembers"
			).rename("CompositeMembers");
		const ast_type_parser_t ast_type_struct_parser = (
			util::keyword("struct") > ast_type_members_parser
		).map<std::shared_ptr<ast_type_node>>(
			[](const auto& p) {
				return std::make_shared<ast_type_node>(
					ast_type_node::type_t::Struct,
					p
				);
			},
			"StructType"
		).rename("StructType");
		const ast_type_parser_t ast_type_union_parser = (
			util::keyword("union") > ast_type_members_parser
		).map<std::shared_ptr<ast_type_node>>(
			[](const auto& p) {
				return std::make_shared<ast_type_node>(
					ast_type_node::type_t::Union,
					p
				);
			},
			"UnionType"
		).rename("UnionType");
		const ast_type_parser_t ast_type_parser =
			((ast_type_simple_parser ||
					ast_type_struct_parser ||
					ast_type_union_parser)
				+ *(ast_type_suffix_parser))
			.map<std::shared_ptr<ast_type_node>>(
				[](const auto& p) {
					std::shared_ptr<ast_type_node> type = p.first;
					for (const auto& suffix : p.second) {
						if (std::holds_alternative<std::monostate>(suffix)) {
							// pointer
							type = std::make_shared<ast_type_node>(
								ast_type_node::type_t::Pointer,
								ast_type_pointer{type}
							);
						}
						else {
							// array
							type = std::make_shared<ast_type_node>(
								ast_type_node::type_t::Array,
								ast_type_array{type, std::get<unsigned int>(suffix)}
							);
						}
					}
					return type;
				},
				"TypeWithSuffixes"
			).rename("TypeWithSuffixes")
			.rename("Type");

		void register_type_parsers(ParserTable& table) {
			table["ast_type_parser"] = std::make_shared<ast_type_parser_t>(ast_type_parser);
		}
	} // type_parser

	namespace expression_parser {
		typedef Parser<lexer_token, std::shared_ptr<ast_expression_node>> ast_expression_parser_t;

		// Forward declarations for recursive parsers
		const ast_expression_parser_t ref_ast_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_expression_parser");
		const ast_expression_parser_t ref_ast_l0_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l0_expression_parser");
		const ast_expression_parser_t ref_ast_l1_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l1_expression_parser");
		const ast_expression_parser_t ref_ast_l2_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l2_expression_parser");
		const ast_expression_parser_t ref_ast_l3_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l3_expression_parser");
		const ast_expression_parser_t ref_ast_l4_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l4_expression_parser");
		const ast_expression_parser_t ref_ast_l5_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l5_expression_parser");
		const ast_expression_parser_t ref_ast_l6_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l6_expression_parser");
		const ast_expression_parser_t ref_ast_l7_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l7_expression_parser");
		const ast_expression_parser_t ref_ast_l8_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l8_expression_parser");
		const ast_expression_parser_t ref_ast_l9_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l9_expression_parser");
		const ast_expression_parser_t ref_ast_l10_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l10_expression_parser");
		const ast_expression_parser_t ref_ast_l11_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l11_expression_parser");
		const ast_expression_parser_t ref_ast_l12_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l12_expression_parser");
		const ast_expression_parser_t ref_ast_l13_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l13_expression_parser");
		const ast_expression_parser_t ref_ast_l14_expression_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_expression_node>>("ast_l14_expression_parser");

		const ast_expression_parser_t ast_integer_parser =
			util::integer().map<std::shared_ptr<ast_expression_node>>(
				[](const lexer_token& tok) {
					return util::make_ast_expression_node(ast_expression_node::type_t::Literal, ast_expression_literal(
						ast_expression_literal::type_t::Integer,
						std::get<int>(tok.value)
					));
				},
				"IntegerLiteral"
			);
		const ast_expression_parser_t ast_boolean_parser =
			(util::keyword("true") || util::keyword("false")).map<std::shared_ptr<ast_expression_node>>(
				[](const lexer_token& tok) {
					return util::make_ast_expression_node(ast_expression_node::type_t::Literal, ast_expression_literal(
						ast_expression_literal::type_t::Boolean,
						std::get<std::string>(tok.value) == "true"
					));
				},
				"BooleanLiteral"
			);
		const ast_expression_parser_t ast_string_parser =
			util::token_type(lexer_token::type_t::String).map<std::shared_ptr<ast_expression_node>>(
				[](const lexer_token& tok) {
					return util::make_ast_expression_node(ast_expression_node::type_t::Literal, ast_expression_literal(
						ast_expression_literal::type_t::String,
						std::get<std::string>(tok.value)
					));
				},
				"StringLiteral"
			);

		const ast_expression_parser_t ast_identifier_parser =
			util::identifier().map<std::shared_ptr<ast_expression_node>>(
				[](const lexer_token& tok) {
					return util::make_ast_expression_node(ast_expression_node::type_t::Identifier,
						std::get<std::string>(tok.value));
				},
				"Identifier"
			);

		// I need to have this split into multiple levels to handle precedence and associativity correctly
		/*
		 * Order:
		 * 0:
		 *  - parenthesized expressions
		 *  - identifiers
		 *  - literals
		 * 1: (left associative)
		 *  - postfix increment/decrement
		 *  - function calls
		 *  - array subscripting
		 *  - member access (.), pointer to member access (->)
		 * 2: (right associative)
		 *  - prefix increment/decrement
		 *  - unary +/-, logical not (!), bitwise not (~), dereference (*), address-of (&)
		 *  - sizeof
		 *  - cast
		 * 3: (left associative)
		 *  - multiplicative (*, /, %)
		 * 4: (left associative)
		 *  - additive (+, -)
		 * 5: (left associative)
		 *  - shift (<<, >>)
		 * 6: (left associative)
		 *  - relational (<, <=, >, >=)
		 * 7: (left associative)
		 *  - equality (==, !=)
		 * 8: (left associative)
		 *  - bitwise AND (&)
		 * 9: (left associative)
		 *  - bitwise XOR (^)
		 * 10: (left associative)
		 *  - bitwise OR (|)
		 * 11: (left associative)
		 *  - logical AND (&&)
		 * 12: (left associative)
		 *  - logical OR (||)
		 * 13: (right associative)
		 *  - ternary (?:)
		 * 14: (right associative)
		 *  - assignment (=, (+=, -=, *=, /=, %=, <<=, >>=, &=, ^=, |=)) for now only =
		 * 15: (left associative)
		 *  - comma operator (,)
		 */

		// Level 0
		const ast_expression_parser_t ast_l0_parenthesized_expression_parser =
			(util::punctuation('(') > ref_ast_expression_parser < util::punctuation(')')).rename("ParenthesizedExpression");
		const ast_expression_parser_t ast_l0_identifier_parser = ast_identifier_parser.rename("Identifier");
		const ast_expression_parser_t ast_l0_integer_parser = ast_integer_parser.rename("IntegerLiteral");
		const ast_expression_parser_t ast_l0_boolean_parser = ast_boolean_parser.rename("BooleanLiteral");
		const ast_expression_parser_t ast_l0_expression_parser = (
			ast_l0_parenthesized_expression_parser ||
			ast_l0_identifier_parser ||
			ast_l0_boolean_parser ||
			ast_l0_integer_parser ||
			ast_string_parser
		).rename("ExpressionLevel0");

		// Level 1
		struct ast_l1_element {
			enum class type_t {
				FunctionCall,
				PostfixIncrement,
				PostfixDecrement,
				ArraySubscript,
				MemberAccess
			} type;
			std::variant<
				std::vector<std::shared_ptr<ast_expression_node>>, // FunctionCall
				std::shared_ptr<ast_expression_node>, // ArraySubscript
				std::monostate, // PostfixIncrement, PostfixDecrement
				std::pair<bool, std::string> // MemberAccess (bool is pointer access)
			> value;
		};
		typedef Parser<lexer_token, ast_l1_element> ast_l1_element_parser_t;
		const ast_l1_element_parser_t ast_l1_function_call_element_parser =
			(util::punctuation('(') >
				(ref_ast_expression_parser % util::punctuation(',')) <
				util::punctuation(')')
			)
			.map<ast_l1_element>(
				[](const auto& args) {
					ast_l1_element elem;
					elem.type = ast_l1_element::type_t::FunctionCall;
					elem.value = args;
					return elem;
				},
				"FunctionCallElement"
			).rename("FunctionCallElement");
		const ast_l1_element_parser_t ast_l1_postfix_element_parser =
			(util::op({"++", "--"}))
			.map<ast_l1_element>(
				[](const lexer_token& tok) {
					ast_l1_element elem;
					operator_type_t op_type = std::get<operator_type_t>(tok.value);
					switch (op_type) {
						case operator_type_t::PlusPlus:
							elem.type = ast_l1_element::type_t::PostfixIncrement;
							break;
						case operator_type_t::MinusMinus:
							elem.type = ast_l1_element::type_t::PostfixDecrement;
							break;
						default:
							throw std::runtime_error("Unknown postfix operator");
					}
					elem.value = std::monostate{};
					return elem;
				},
				"PostfixElement"
			).rename("PostfixElement");
		const ast_l1_element_parser_t ast_l1_array_subscript_element_parser =
			(util::punctuation('[') > ref_ast_expression_parser < util::punctuation(']'))
			.map<ast_l1_element>(
				[](const std::shared_ptr<ast_expression_node>& index) {
					ast_l1_element elem;
					elem.type = ast_l1_element::type_t::ArraySubscript;
					elem.value = index;
					return elem;
				},
				"ArraySubscriptElement"
			).rename("ArraySubscriptElement");
		const ast_l1_element_parser_t ast_l1_member_access_element_parser =
		((util::punctuation('.').map<bool>([](const lexer_token&) {
					return false;
				}, "dot") ||
				util::op("->").map<bool>([](const lexer_token&) {
					return true;
				}, "arrow")) +
			ast_identifier_parser
		).map<ast_l1_element>(
			[](const auto& p) {
				ast_l1_element elem;
				elem.type = ast_l1_element::type_t::MemberAccess;
				elem.value = std::make_pair(p.first, std::get<std::string>(p.second->value));
				return elem;
			},
			"MemberAccessElement"
		).rename("MemberAccessElement");
		const ast_expression_parser_t ast_l1_expression_parser =
		(ref_ast_l0_expression_parser +
			*(ast_l1_postfix_element_parser ||
				ast_l1_array_subscript_element_parser ||
				ast_l1_member_access_element_parser ||
				ast_l1_function_call_element_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> base = p.first;
				for (const auto& elem : p.second) {
					switch (elem.type) {
						case ast_l1_element::type_t::FunctionCall: {
							ast_expression_call expr;
							expr.callee = base;
							expr.arguments = std::get<std::vector<std::shared_ptr<ast_expression_node>>>(elem.value);
							base = util::make_ast_expression_node(ast_expression_node::type_t::FunctionCall, expr);
							break;
						}
						case ast_l1_element::type_t::PostfixIncrement: {
							ast_expression_unary expr;
							expr.type = ast_expression_unary::type_t::PostfixIncrement;
							expr.operand = base;
							base = util::make_ast_expression_node(ast_expression_node::type_t::Unary, expr);
							break;
						}
						case ast_l1_element::type_t::PostfixDecrement: {
							ast_expression_unary expr;
							expr.type = ast_expression_unary::type_t::PostfixDecrement;
							expr.operand = base;
							base = util::make_ast_expression_node(ast_expression_node::type_t::Unary, expr);
							break;
						}
						case ast_l1_element::type_t::ArraySubscript: {
							ast_expression_binary expr;
							expr.type = ast_expression_binary::type_t::ArraySubscript;
							expr.left = base;
							expr.right = std::get<std::shared_ptr<ast_expression_node>>(elem.value);
							base = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
							break;
						}
						case ast_l1_element::type_t::MemberAccess: {
							ast_member_access expr;
							expr.object = base;
							auto [is_pointer, member_name] = std::get<std::pair<bool, std::string>>(elem.value);
							expr.property = member_name;
							expr.pointer = is_pointer;
							base = util::make_ast_expression_node(ast_expression_node::type_t::MemberAccess, expr);
							break;
						}
						default:
							throw std::runtime_error("Unknown L1 element type");
					}
				}
				return base;
			},
			"ExpressionLevel1"
		).rename("ExpressionLevel1");

		// Level 2
		const ast_expression_parser_t ast_l2_prefix_parser =
			(+util::op({"++", "--", "+", "-", "!", "~", "*", "&"}) +
				ref_ast_l1_expression_parser)
			.map<std::shared_ptr<ast_expression_node>>(
				[](const auto& p) {
					std::shared_ptr<ast_expression_node> right = p.second;
					// Apply operators in reverse order (right associative)
					const auto& ops = p.first;
					for (auto it = ops.rbegin(); it != ops.rend(); ++it) {
						ast_expression_unary expr;
						operator_type_t op_type = std::get<operator_type_t>(it->value);
						expr.operand = right;
						switch (op_type) {
							case operator_type_t::PlusPlus:
								expr.type = ast_expression_unary::type_t::PrefixIncrement;
								break;
							case operator_type_t::MinusMinus:
								expr.type = ast_expression_unary::type_t::PrefixDecrement;
								break;
							case operator_type_t::Plus:
								expr.type = ast_expression_unary::type_t::Positive;
								break;
							case operator_type_t::Minus:
								expr.type = ast_expression_unary::type_t::Negate;
								break;
							case operator_type_t::Exclamation:
								expr.type = ast_expression_unary::type_t::LogicalNot;
								break;
							case operator_type_t::Tilde:
								expr.type = ast_expression_unary::type_t::BitwiseNot;
								break;
							case operator_type_t::Asterisk:
								expr.type = ast_expression_unary::type_t::Dereference;
								break;
							case operator_type_t::Ampersand:
								expr.type = ast_expression_unary::type_t::AddressOf;
								break;
							default:
								// Should not happen
								throw std::runtime_error("Unknown unary operator");
						}
						right = util::make_ast_expression_node(ast_expression_node::type_t::Unary, expr);
					}
					return right;
				}, "PrefixExpression"
			).rename("PrefixExpression");
		const ast_expression_parser_t ast_l2_sizeof_parser =
		(util::keyword("sizeof") >
			(ref_ast_l1_expression_parser || (util::punctuation('(') > ast_identifier_parser < util::punctuation(')')))
		).map<std::shared_ptr<ast_expression_node>>(
			[](const std::shared_ptr<ast_expression_node>& operand) {
				ast_expression_unary expr;
				expr.type = ast_expression_unary::type_t::SizeOf;
				expr.operand = operand;
				return util::make_ast_expression_node(ast_expression_node::type_t::Unary, expr);
			},
			"SizeOfExpression"
		).rename("SizeOfExpression");
		const ast_expression_parser_t ast_l2_cast_parser =
		((util::punctuation('(') >
				type_parser::ref_ast_type_parser <
				util::punctuation(')')) +
			ref_ast_l1_expression_parser
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				ast_expression_cast expr;
				expr.target_type = p.first;
				expr.expression = p.second;
				return util::make_ast_expression_node(ast_expression_node::type_t::Cast, expr);
			},
			"CastExpression"
		).rename("CastExpression");
		const ast_expression_parser_t ast_l2_expression_parser = (
			ast_l2_prefix_parser ||
			ast_l2_cast_parser ||
			ast_l2_sizeof_parser ||
			ref_ast_l1_expression_parser
		).rename("ExpressionLevel2");

		// Level 3
		const ast_expression_parser_t ast_l3_multiplicative_parser =
		(ref_ast_l2_expression_parser +
			*(util::op({"*", "/", "%"}) + ref_ast_l2_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::Asterisk:
							expr.type = ast_expression_binary::type_t::Multiply;
							break;
						case operator_type_t::Slash:
							expr.type = ast_expression_binary::type_t::Divide;
							break;
						case operator_type_t::Percent:
							expr.type = ast_expression_binary::type_t::Modulo;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown multiplicative operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"MultiplicativeExpression"
		).rename("MultiplicativeExpression");
		const ast_expression_parser_t ast_l3_expression_parser = ast_l3_multiplicative_parser.rename("ExpressionLevel3");

		// Level 4
		const ast_expression_parser_t ast_l4_additive_parser =
		(ref_ast_l3_expression_parser +
			*(util::op({"+", "-"}) + ref_ast_l3_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::Plus:
							expr.type = ast_expression_binary::type_t::Add;
							break;
						case operator_type_t::Minus:
							expr.type = ast_expression_binary::type_t::Subtract;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown additive operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"AdditiveExpression"
		).rename("AdditiveExpression");
		const ast_expression_parser_t ast_l4_expression_parser = ast_l4_additive_parser.rename("ExpressionLevel4");

		// Level 5
		const ast_expression_parser_t ast_l5_shift_parser =
		(ref_ast_l4_expression_parser +
			*(util::op({"<<", ">>"}) + ref_ast_l4_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::ShiftLeft:
							expr.type = ast_expression_binary::type_t::ShiftLeft;
							break;
						case operator_type_t::ShiftRight:
							expr.type = ast_expression_binary::type_t::ShiftRight;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown shift operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"ShiftExpression"
		).rename("ShiftExpression");
		const ast_expression_parser_t ast_l5_expression_parser = ast_l5_shift_parser.rename("ExpressionLevel5");

		// Level 6
		const ast_expression_parser_t ast_l6_relational_parser =
		(ref_ast_l5_expression_parser +
			*(util::op({"<", "<=", ">", ">="}) + ref_ast_l5_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				if (p.second.empty()) {
					return left;
				}
				std::vector<std::shared_ptr<ast_expression_node>> terms;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::LessThan:
							expr.type = ast_expression_binary::type_t::Less;
							break;
						case operator_type_t::LessEqual:
							expr.type = ast_expression_binary::type_t::LessEqual;
							break;
						case operator_type_t::GreaterThan:
							expr.type = ast_expression_binary::type_t::Greater;
							break;
						case operator_type_t::GreaterEqual:
							expr.type = ast_expression_binary::type_t::GreaterEqual;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown relational operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					terms.push_back(util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr));
					left = op_pair.second;
				}
				if (terms.size() == 1) {
					return terms[0];
				}
				else {
					// Chain relational expressions into a series of logical ANDs
					std::shared_ptr<ast_expression_node> result = terms[0];
					for (size_t i = 1; i < terms.size(); ++i) {
						ast_expression_binary expr;
						expr.type = ast_expression_binary::type_t::LogicalAnd;
						expr.left = result;
						expr.right = terms[i];
						result = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
					}
					return result;
				}
			},
			"RelationalExpression"
		).rename("RelationalExpression");
		const ast_expression_parser_t ast_l6_expression_parser = ast_l6_relational_parser.rename("ExpressionLevel6");

		// Level 7
		const ast_expression_parser_t ast_l7_equality_parser =
		(ref_ast_l6_expression_parser +
			*(util::op({"==", "!="}) + ref_ast_l6_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::EqualEqual:
							expr.type = ast_expression_binary::type_t::Equal;
							break;
						case operator_type_t::NotEqual:
							expr.type = ast_expression_binary::type_t::NotEqual;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown equality operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"EqualityExpression"
		).rename("EqualityExpression");
		const ast_expression_parser_t ast_l7_expression_parser = ast_l7_equality_parser.rename("ExpressionLevel7");

		// Level 8
		const ast_expression_parser_t ast_l8_bitwise_and_parser =
		(ref_ast_l7_expression_parser +
			*(util::op("&") + ref_ast_l7_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::BitwiseAnd;
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"BitwiseAndExpression"
		).rename("BitwiseAndExpression");
		const ast_expression_parser_t ast_l8_expression_parser = ast_l8_bitwise_and_parser.rename("ExpressionLevel8");

		// Level 9
		const ast_expression_parser_t ast_l9_bitwise_xor_parser =
		(ref_ast_l8_expression_parser +
			*(util::op("^") + ref_ast_l8_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::BitwiseXor;
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"BitwiseXorExpression"
		).rename("BitwiseXorExpression");
		const ast_expression_parser_t ast_l9_expression_parser = ast_l9_bitwise_xor_parser.rename("ExpressionLevel9");

		// Level 10
		const ast_expression_parser_t ast_l10_bitwise_or_parser =
		(ref_ast_l9_expression_parser +
			*(util::op("|") + ref_ast_l9_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::BitwiseOr;
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"BitwiseOrExpression"
		).rename("BitwiseOrExpression");
		const ast_expression_parser_t ast_l10_expression_parser = ast_l10_bitwise_or_parser.rename("ExpressionLevel10");

		// Level 11 (left associative)
		const ast_expression_parser_t ast_l11_logical_and_parser =
		(ref_ast_l10_expression_parser +
			*(util::op("&&") + ref_ast_l10_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::LogicalAnd;
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"LogicalAndExpression"
		).rename("LogicalAndExpression");
		const ast_expression_parser_t ast_l11_expression_parser = ast_l11_logical_and_parser.rename("ExpressionLevel11");

		// Level 12 (left associative)
		const ast_expression_parser_t ast_l12_logical_or_parser =
		(ref_ast_l11_expression_parser +
			*(util::op("||") + ref_ast_l11_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::LogicalOr;
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"LogicalOrExpression"
		).rename("LogicalOrExpression");
		const ast_expression_parser_t ast_l12_expression_parser = ast_l12_logical_or_parser.rename("ExpressionLevel12");

		// Level 13 (right associative)
		const ast_expression_parser_t ast_l13_ternary_parser =
		(ref_ast_l12_expression_parser +
			~((util::op("?") > ref_ast_expression_parser) +
				(util::punctuation(':') > ref_ast_expression_parser))
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				if (!p.second.has_value()) {
					return p.first;
				}
				ast_expression_ternary expr;
				expr.condition = p.first;
				expr.then = p.second.value().first;
				expr.otherwise = p.second.value().second;
				return util::make_ast_expression_node(ast_expression_node::type_t::Ternary, expr);
			},
			"TernaryExpression"
		).rename("TernaryExpression");
		const ast_expression_parser_t ast_l13_expression_parser = ast_l13_ternary_parser.rename("ExpressionLevel13");

		// Level 14 (right associative)
		const ast_expression_parser_t ast_l14_assignment_parser =
		(ref_ast_l13_expression_parser +
			*(util::op({"="}) + ref_ast_expression_parser)
		).map<std::shared_ptr<ast_expression_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_expression_node> left = p.first;
				for (const auto& op_pair : p.second) {
					ast_expression_binary expr;
					operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
					switch (op_type) {
						case operator_type_t::Equal:
							expr.type = ast_expression_binary::type_t::Assignment;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown assignment operator");
					}
					expr.left = left;
					expr.right = op_pair.second;
					left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
				}
				return left;
			},
			"AssignmentExpression"
		).rename("AssignmentExpression");
		const ast_expression_parser_t ast_l14_expression_parser = ast_l14_assignment_parser.rename("ExpressionLevel14");

		// Level 15 (left associative)
		const ast_expression_parser_t ast_l15_comma_parser =
			(ref_ast_l14_expression_parser % util::punctuation(',')
			).filter(
				[](const std::vector<std::shared_ptr<ast_expression_node>>& exprs) {
					return !exprs.empty();
				},
				"NonEmptyCommaExpression"
			)
			.map<std::shared_ptr<ast_expression_node>>(
				[](const auto& p) {
					if (p.size() == 1) {
						return p[0];
					}
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::Comma;
					std::shared_ptr<ast_expression_node> left = p[0];
					for (size_t i = 1; i < p.size(); ++i) {
						expr.left = left;
						expr.right = p[i];
						left = util::make_ast_expression_node(ast_expression_node::type_t::Binary, expr);
					}
					return left;
				},
				"CommaExpression"
			).rename("CommaExpression");

		// Expression parser
		const ast_expression_parser_t ast_expression_parser = ast_l14_expression_parser.rename("Expression");

		void register_expression_parsers(ParserTable& table) {
			table["ast_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_expression_parser);
			table["ast_l0_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l0_expression_parser);
			table["ast_l1_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l1_expression_parser);
			table["ast_l2_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l2_expression_parser);
			table["ast_l3_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l3_expression_parser);
			table["ast_l4_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l4_expression_parser);
			table["ast_l5_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l5_expression_parser);
			table["ast_l6_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l6_expression_parser);
			table["ast_l7_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l7_expression_parser);
			table["ast_l8_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l8_expression_parser);
			table["ast_l9_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l9_expression_parser);
			table["ast_l10_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l10_expression_parser);
			table["ast_l11_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l11_expression_parser);
			table["ast_l12_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l12_expression_parser);
			table["ast_l13_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l13_expression_parser);
			table["ast_l14_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l14_expression_parser);
			table["ast_l15_expression_parser"] = std::make_shared<ast_expression_parser_t>(ast_l15_comma_parser);
		}
	}

	namespace statement_parser {
		typedef Parser<lexer_token, std::shared_ptr<ast_statement_node>> ast_statement_parser_t;

		// Forward declarations for recursive structures
		const ast_statement_parser_t ref_ast_statement_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_statement_node>>("ast_statement_parser");
		const ast_statement_parser_t ref_ast_block_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_statement_node>>("ast_block_parser");

		// Statements
		const ast_statement_parser_t ast_variable_declaration_parser =
			(type_parser::ast_type_parser +
				util::identifier() +
				~(util::op("=") > expression_parser::ref_ast_expression_parser) < util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_variable_declaration var_decl;
					var_decl.var_type = p.first.first;
					var_decl.name = std::get<std::string>(p.first.second.value);
					if (p.second.has_value()) {
						var_decl.initializer = p.second.value();
					}
					else {
						var_decl.initializer = nullptr;
					}
					return util::make_ast_statement_node(ast_statement_node::type_t::VariableDeclaration, var_decl);
				},
				"VariableDeclaration"
			).rename("VariableDeclaration");

		const ast_statement_parser_t ref_ast_if_statement_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_statement_node>>("ast_if_statement_parser");
		const Parser<lexer_token, std::pair<std::shared_ptr<ast_expression_node>, std::shared_ptr<ast_statement_node>>>
		ast_if_clause_parser =
			((util::keyword("if") >
					util::punctuation('(') > expression_parser::ref_ast_expression_parser < util::punctuation(')')) +
				ref_ast_block_parser)
			.rename("IfStatement");
		const Parser<lexer_token, std::shared_ptr<ast_statement_node>> ast_else_clause_parser =
			(util::keyword("else") > (ref_ast_if_statement_parser || ref_ast_block_parser))
			.rename("ElseClause");
		const ast_statement_parser_t ast_if_statement_parser =
			(ast_if_clause_parser + ~ast_else_clause_parser)
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_if if_stmt;
					if_stmt.condition = p.first.first;
					if_stmt.then_branch = p.first.second;
					if (p.second.has_value()) {
						if_stmt.else_branch = p.second.value();
					}
					else {
						if_stmt.else_branch = nullptr;
					}
					return util::make_ast_statement_node(ast_statement_node::type_t::IfStatement, if_stmt);
				},
				"IfStatement"
			).rename("IfStatement");

		const ast_statement_parser_t ast_while_statement_parser =
			((util::keyword("while") >
					util::punctuation('(') > expression_parser::ref_ast_expression_parser < util::punctuation(')')) +
				ref_ast_block_parser)
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_while while_stmt;
					while_stmt.condition = p.first;
					while_stmt.body = p.second;
					return util::make_ast_statement_node(ast_statement_node::type_t::WhileStatement, while_stmt);
				},
				"WhileStatement"
			).rename("WhileStatement");
		const ast_statement_parser_t ast_return_statement_parser =
			(util::keyword("return") > ~expression_parser::ref_ast_expression_parser < util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& expr_opt) {
					ast_statement_return return_stmt;
					if (expr_opt.has_value()) {
						return_stmt.value = expr_opt.value();
					}
					else {
						return_stmt.value = nullptr;
					}
					return util::make_ast_statement_node(ast_statement_node::type_t::ReturnStatement, return_stmt);
				},
				"ReturnStatement"
			).rename("ReturnStatement");
		const ast_statement_parser_t ast_expression_statement_parser =
			(expression_parser::ref_ast_expression_parser < util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const std::shared_ptr<ast_expression_node>& expr) {
					ast_statement_expression expr_stmt;
					expr_stmt.expression = expr;
					return util::make_ast_statement_node(ast_statement_node::type_t::ExpressionStatement, expr_stmt);
				},
				"ExpressionStatement"
			).rename("ExpressionStatement");
		const Parser<lexer_token, ast_statement_block> ast_statement_block_parser =
			(util::punctuation('{') > *(ref_ast_statement_parser) < util::punctuation('}'))
			.map<ast_statement_block>(
				[](const auto& statements) {
					ast_statement_block block;
					block.statements = statements;
					return block;
				},
				"StatementBlock"
			).rename("StatementBlock");
		const ast_statement_parser_t ast_block_parser =
			ast_statement_block_parser
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& block_statements) {
					return util::make_ast_statement_node(ast_statement_node::type_t::BlockStatement, block_statements);
				},
				"Block"
			).rename("Block");

		const Parser<lexer_token, std::pair<std::string, std::shared_ptr<ast_type_node>>> ast_function_parameter_parser =
			(type_parser::ast_type_parser + util::identifier())
			.map<std::pair<std::string, std::shared_ptr<ast_type_node>>>(
				[](const auto& p) {
					return std::make_pair(std::get<std::string>(p.second.value), p.first);
				},
				"FunctionParameter"
			).rename("FunctionParameter");
		const ast_statement_parser_t ast_function_declaration_parser =
			(type_parser::ast_type_parser +
				util::identifier() +
				(util::punctuation('(') >
					(ast_function_parameter_parser % util::punctuation(',')) < util::punctuation(')')) + (
					ast_statement_block_parser.map<std::optional<ast_statement_block>>(
						[](const ast_statement_block& block) {
							return std::optional(block);
						},
						"FunctionBodyOptional"
					) || (util::punctuation(';').map<std::optional<ast_statement_block>>(
						[](const auto&) {
							return std::optional<ast_statement_block>();
						},
						"FunctionBodyEmpty"
					))
				))
			.map<std::tuple<std::shared_ptr<ast_type_node>, std::string, std::vector<std::pair<std::string, std::shared_ptr<
				ast_type_node>>>, std::optional<ast_statement_block>>>(
				[](const auto& p) {
					return std::make_tuple(
						p.first.first.first, std::get<std::string>(p.first.first.second.value), p.first.second, p.second
					);
				},
				"FunctionDeclarationTuple"
			).rename("FunctionDeclarationTuple")
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_function_declaration func_decl;
					func_decl.return_type = std::get<0>(p);
					func_decl.name = std::get<1>(p);
					func_decl.parameters = std::get<2>(p);
					auto body_opt = std::get<3>(p);
					func_decl.body = body_opt.has_value() ? std::make_shared<ast_statement_block>(body_opt.value()) : nullptr;
					return util::make_ast_statement_node(ast_statement_node::type_t::FunctionDeclaration, func_decl);
				},
				"FunctionDeclaration"
			).rename("FunctionDeclaration");

		const ast_statement_parser_t ast_struct_declaration_parser =
			(util::keyword("struct") >
				util::identifier() + ~type_parser::ast_type_members_parser
				< util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_struct_declaration struct_decl;
					struct_decl.name = std::get<std::string>(p.first.value);
					if (p.second.has_value()) {
						struct_decl.body = std::make_shared<ast_type_members>(p.second.value());
					}
					else {
						struct_decl.body = nullptr;
					}
					return util::make_ast_statement_node(ast_statement_node::type_t::StructDeclaration, struct_decl);
				},
				"StructDeclaration"
			).rename("StructDeclaration");

		const ast_statement_parser_t ast_union_declaration_parser =
			(util::keyword("union") >
				util::identifier() + ~type_parser::ast_type_members_parser
				< util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_struct_declaration union_decl;
					union_decl.name = std::get<std::string>(p.first.value);
					if (p.second.has_value()) {
						union_decl.body = std::make_shared<ast_type_members>(p.second.value());
					}
					else {
						union_decl.body = nullptr;
					}
					return util::make_ast_statement_node(ast_statement_node::type_t::UnionDeclaration, union_decl);
				},
				"UnionDeclaration"
			).rename("UnionDeclaration");

		const ast_statement_parser_t ast_typedef_declaration_parser =
			(util::keyword("typedef") >
				type_parser::ast_type_parser +
				util::identifier() < util::punctuation(';'))
			.map<std::shared_ptr<ast_statement_node>>(
				[](const auto& p) {
					ast_statement_type_declaration typedef_decl;
					typedef_decl.aliased_type = p.first;
					typedef_decl.name = std::get<std::string>(p.second.value);
					return util::make_ast_statement_node(ast_statement_node::type_t::TypeDeclaration, typedef_decl);
				},
				"TypedefDeclaration"
			).rename("TypedefDeclaration");

		const ast_statement_parser_t ast_statement_parser = (
			ast_variable_declaration_parser ||
			ast_if_statement_parser ||
			ast_while_statement_parser ||
			ast_return_statement_parser ||
			ast_expression_statement_parser ||
			ref_ast_block_parser
		).rename("Statement");

		void register_statement_parsers(ParserTable& table) {
			table["ast_statement_parser"] = std::make_shared<ast_statement_parser_t>(ast_statement_parser);
			table["ast_block_parser"] = std::make_shared<ast_statement_parser_t>(ast_block_parser);
			table["ast_if_statement_parser"] = std::make_shared<ast_statement_parser_t>(ast_if_statement_parser);
			table["ast_function_declaration_parser"] = std::make_shared<ast_statement_parser_t>(
				ast_function_declaration_parser);
			table["ast_variable_declaration_parser"] = std::make_shared<ast_statement_parser_t>(
				ast_variable_declaration_parser);
		}
	}


	ParserTable get_ast_parsers() {
		ParserTable table;
		type_parser::register_type_parsers(table);
		expression_parser::register_expression_parsers(table);
		statement_parser::register_statement_parsers(table);
		return table;
	}

	// Program
	typedef Parser<lexer_token, ast_program::program_element_t> ast_program_element_parser_t;


	const ast_program_element_parser_t ast_program_function_declaration_parser =
		statement_parser::ast_function_declaration_parser.map<ast_statement_function_declaration>(
			[](const std::shared_ptr<ast_statement_node>& node) {
				const auto& func_decl = std::get<ast_statement_function_declaration>(node->value);
				return func_decl;
			},
			"FunctionDeclarationElement"
		).map<ast_program::program_element_t>(
			[](const ast_statement_function_declaration& func_decl) {
				return ast_program::program_element_t(func_decl);
			},
			"FunctionDeclarationVariant"
		);
	const ast_program_element_parser_t ast_program_struct_declaration_parser =
		statement_parser::ast_struct_declaration_parser.map<ast_statement_struct_declaration>(
			[](const std::shared_ptr<ast_statement_node>& node) {
				const auto& struct_decl = std::get<ast_statement_struct_declaration>(node->value);
				return struct_decl;
			},
			"StructDeclarationElement"
		).map<ast_program::program_element_t>(
			[](const ast_statement_struct_declaration& struct_decl) {
				return ast_program::program_element_t(struct_decl);
			},
			"StructDeclarationVariant"
		);
	const ast_program_element_parser_t ast_program_union_declaration_parser =
		statement_parser::ast_union_declaration_parser.map<ast_statement_struct_declaration>(
			[](const std::shared_ptr<ast_statement_node>& node) {
				const auto& union_decl = std::get<ast_statement_struct_declaration>(node->value);
				return union_decl;
			},
			"UnionDeclarationElement"
		).map<ast_program::program_element_t>(
			[](const ast_statement_struct_declaration& union_decl) {
				return ast_program::program_element_t(union_decl);
			},
			"UnionDeclarationVariant"
		);
	const ast_program_element_parser_t ast_program_typedef_declaration_parser =
		statement_parser::ast_typedef_declaration_parser.map<ast_statement_type_declaration>(
			[](const std::shared_ptr<ast_statement_node>& node) {
				const auto& typedef_decl = std::get<ast_statement_type_declaration>(node->value);
				return typedef_decl;
			},
			"TypedefDeclarationElement"
		).map<ast_program::program_element_t>(
			[](const ast_statement_type_declaration& typedef_decl) {
				return ast_program::program_element_t(typedef_decl);
			},
			"TypedefDeclarationVariant"
		);
	const ast_program_element_parser_t ast_program_variable_declaration_parser =
		statement_parser::ast_variable_declaration_parser.map<ast_statement_variable_declaration>(
			[](const std::shared_ptr<ast_statement_node>& node) {
				const auto& var_decl = std::get<ast_statement_variable_declaration>(node->value);
				return var_decl;
			},
			"VariableDeclarationElement"
		).map<ast_program::program_element_t>(
			[](const ast_statement_variable_declaration& var_decl) {
				return ast_program::program_element_t(var_decl);
			},
			"VariableDeclarationVariant"
		);

	const ast_program_element_parser_t ast_program_element_parser = (
		ast_program_function_declaration_parser ||
		ast_program_struct_declaration_parser ||
		ast_program_union_declaration_parser ||
		ast_program_typedef_declaration_parser ||
		ast_program_variable_declaration_parser
	);

	const Parser<lexer_token, ast_program> ast_program_parser =
		(*ast_program_element_parser)
		.map<ast_program>(
			[](const auto& elements) {
				ast_program program;
				program.body = elements;
				return program;
			},
			"ASTProgram"
		);

	std::shared_ptr<ast_type_node> parse_ast_type(const std::vector<lexer_token>& tokens) {
		ParserTable table;
		auto result = type_parser::ast_type_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse type" << std::endl;
			return nullptr;
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for type" << std::endl;
		}
		return result[0].first;
	}
	std::shared_ptr<ast_expression_node> parse_ast_expression(const std::vector<lexer_token>& tokens) {
		ParserTable table = get_ast_parsers();
		auto result = expression_parser::ast_expression_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse AST Expression" << std::endl;
			return nullptr;
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for AST Expression" << std::endl;
		}
		return result[0].first;
	}
	std::shared_ptr<ast_statement_node> parse_ast_statement(const std::vector<lexer_token>& tokens) {
		ParserTable table = get_ast_parsers();
		auto result = statement_parser::ast_statement_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse AST Statement" << std::endl;
			return nullptr;
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for AST Statement" << std::endl;
		}
		return result[0].first;
	}
	ast_program parse_ast_program(const std::vector<lexer_token>& tokens) {
		auto table = get_ast_parsers();
		auto result = ast_program_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse AST Program" << std::endl;
			return ast_program{};
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for AST Program" << std::endl;
		}
		return result[0].first;
	}

	void ast_type_pointer::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[PointerType] Base Type:\n";
		base->print(indent + 1);
	}
	void ast_type_array::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[ArrayType] Size: " << size << "\n";
		std::cout << std::string(indent, ' ') << "Base Type:\n";
		base->print(indent + 1);
	}
	void ast_type_function::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[FunctionType] Return Type:\n";
		return_type->print(indent + 1);
		std::cout << std::string(indent, ' ') << "Parameters:\n";
		for (const auto& param : parameters) {
			param->print(indent + 1);
		}
	}
	void ast_type_member::print(int indent) const {
		std::cout << std::string(indent, ' ') << name << ":\n";
		type->print(indent + 1);
	}
	void ast_type_members::print(int indent) const {
		for (const auto& member : members) {
			member.print(indent);
		}
	}
	void ast_type_node::print(int indent) const {
		switch (type) {
			case type_t::Int:
				std::cout << std::string(indent, ' ') << "[Type] int\n";
				break;
			case type_t::UnsignedInt:
				std::cout << std::string(indent, ' ') << "[Type] unsigned int\n";
				break;
			case type_t::Short:
				std::cout << std::string(indent, ' ') << "[Type] short\n";
				break;
			case type_t::UnsignedShort:
				std::cout << std::string(indent, ' ') << "[Type] unsigned short\n";
				break;
			case type_t::Void:
				std::cout << std::string(indent, ' ') << "[Type] void\n";
				break;
			case type_t::Bool:
				std::cout << std::string(indent, ' ') << "[Type] bool\n";
				break;
			case type_t::Char:
				std::cout << std::string(indent, ' ') << "[Type] char\n";
				break;
			case type_t::SignedChar:
				std::cout << std::string(indent, ' ') << "[Type] signed char\n";
				break;
			case type_t::Array:
				std::get<ast_type_array>(value).print(indent);
				break;
			case type_t::Pointer:
				std::get<ast_type_pointer>(value).print(indent);
				break;
			case type_t::Function:
				std::get<ast_type_function>(value).print(indent);
				break;
			case type_t::Struct:
				std::cout << std::string(indent, ' ') << "[StructType] Members:\n";
				std::get<ast_type_members>(value).print(indent + 1);
				break;
			case type_t::Union:
				std::cout << std::string(indent, ' ') << "[UnionType] Members:\n";
				std::get<ast_type_members>(value).print(indent + 1);
				break;
			case type_t::Custom:
				std::cout << std::string(indent, ' ') << "[Type] Custom: " << std::get<std::string>(value) << "\n";
				break;
		}
	}

	std::string escape_string(const std::string& str) {
		std::string escaped;
		for (char c : str) {
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
			}
		}
		return escaped;
	}
	void ast_expression_literal::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[Literal] Type: ";
		switch (type) {
			case type_t::Integer:
				std::cout << "int, Value: " << std::get<int>(value);
				break;
			case type_t::Boolean:
				std::cout << "bool, Value: " << (std::get<bool>(value) ? "true" : "false");
				break;
			case type_t::Null:
				std::cout << "null";
				break;
			case type_t::Char:
				std::cout << "char, Value: '" << escape_string(std::string(1, std::get<char>(value))) << "'";
				break;
			case type_t::String:
				std::cout << "string, Value: \"" << escape_string(std::get<std::string>(value)) << "\"";
				break;
		};
		std::cout << "\n";
	}
	void ast_member_access::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[MemberAccess] Type: " << (pointer ? "->" : ".") << " Property: " <<
			property << "\n";
		object->print(indent + 1);
	}
	void ast_expression_ternary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[TernaryExpression] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Then:\n";
		then->print(indent + 1);
		std::cout << indent_str << "Otherwise:\n";
		otherwise->print(indent + 1);
	}
	void ast_expression_binary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[BinaryExpression] Operator: '" << type << "'\n";
		std::cout << indent_str << "Left:\n";
		left->print(indent + 1);
		std::cout << indent_str << "Right:\n";
		right->print(indent + 1);
	}
	void ast_expression_unary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[UnaryExpression] Operator: '" << type << "'\n";
		std::cout << indent_str << "Operand:\n";
		operand->print(indent + 1);
	}
	void ast_expression_call::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[FunctionCall] Callee:\n";
		callee->print(indent + 1);
		std::cout << indent_str << "Arguments:\n";
		for (const auto& arg : arguments) {
			arg->print(indent + 1);
		}
	}
	void ast_expression_cast::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[CastExpression] Target Type:\n";
		target_type->print(indent + 1);
		std::cout << indent_str << "Expression:\n";
		expression->print(indent + 1);
	}
	void ast_expression_node::print(int indent) const {
		switch (type) {
			case type_t::Literal:
				std::get<ast_expression_literal>(value).print(indent);
				break;
			case type_t::Identifier:
				std::cout << std::string(indent, ' ') << "[Identifier] Name: " << std::get<std::string>(value) << "\n";
				break;
			case type_t::Binary:
				std::get<ast_expression_binary>(value).print(indent);
				break;
			case type_t::Unary:
				std::get<ast_expression_unary>(value).print(indent);
				break;
			case type_t::Cast:
				std::get<ast_expression_cast>(value).print(indent);
				break;
			case type_t::FunctionCall:
				std::get<ast_expression_call>(value).print(indent);
				break;
			case type_t::MemberAccess:
				std::get<ast_member_access>(value).print(indent);
				break;
			case type_t::Ternary:
				std::get<ast_expression_ternary>(value).print(indent);
				break;
			case type_t::Unknown:
				std::cout << std::string(indent, ' ') << "[Unknown Expression]\n";
				break;
		}
	}

	void ast_statement_variable_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[VariableDeclaration] Name: " << name << "\n";
		std::cout << indent_str << "Type: \n";
		var_type->print(indent + 1);
		if (initializer) {
			std::cout << indent_str << "Initializer:\n";
			initializer->print(indent + 1);
		}
		else {
			std::cout << indent_str << "No Initializer\n";
		}
	}
	void ast_statement_function_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[FunctionDeclaration] Name: " << name << "\n";
		std::cout << indent_str << "Return Type:\n";
		return_type->print(indent + 1);
		std::cout << indent_str << "Parameters:\n";
		for (const auto& param : parameters) {
			std::cout << indent_str << " " << param.first << ": \n";
			param.second->print(indent + 2);
		}
		std::cout << indent_str << "Body:\n";
		body->print(indent + 1);
	}
	void ast_statement_if::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[IfStatement] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Then Branch:\n";
		then_branch->print(indent + 1);
		if (else_branch) {
			std::cout << indent_str << "Else Branch:\n";
			else_branch->print(indent + 1);
		}
		else {
			std::cout << indent_str << "No Else Branch\n";
		}
	}
	void ast_statement_while::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[WhileStatement] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Body:\n";
		body->print(indent + 1);
	}
	void ast_statement_return::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[ReturnStatement]";
		if (value) {
			std::cout << " Value:\n";
			value->print(indent + 1);
		}
		else {
			std::cout << " No Value\n";
		}
	}
	void ast_statement_expression::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[ExpressionStatement] Expression:\n";
		expression->print(indent + 1);
	}
	void ast_statement_block::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[BlockStatement] Statements:\n";
		for (const auto& stmt : statements) {
			stmt->print(indent + 1);
		}
	}
	void ast_statement_node::print(int indent) const {
		switch (type) {
			case type_t::VariableDeclaration:
				std::get<ast_statement_variable_declaration>(value).print(indent);
				break;
			case type_t::FunctionDeclaration:
				std::get<ast_statement_function_declaration>(value).print(indent);
				break;
			case type_t::StructDeclaration:
				std::get<ast_statement_struct_declaration>(value).print(indent);
				break;
			case type_t::UnionDeclaration:
				std::get<ast_statement_struct_declaration>(value).print(indent);
				break;
			case type_t::TypeDeclaration:
				std::get<ast_statement_type_declaration>(value).print(indent);
				break;
			case type_t::IfStatement:
				std::get<ast_statement_if>(value).print(indent);
				break;
			case type_t::WhileStatement:
				std::get<ast_statement_while>(value).print(indent);
				break;
			case type_t::ReturnStatement:
				std::get<ast_statement_return>(value).print(indent);
				break;
			case type_t::ExpressionStatement:
				std::get<ast_statement_expression>(value).print(indent);
				break;
			case type_t::BlockStatement:
				std::get<ast_statement_block>(value).print(indent);
				break;
			case type_t::Unknown:
				std::cout << std::string(indent, ' ') << "[Unknown Node]\n";
				break;
		}
	}

	void ast_statement_struct_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[StructDeclaration] Name: " << name << "\n";
		if (!body) {
			std::cout << indent_str << "Incomplete struct (no body)\n";
			return;
		}
		std::cout << indent_str << "Members:\n";
		body->print(indent + 1);
	}
	void ast_statement_union_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[UnionDeclaration] Name: " << name << "\n";
		if (!body) {
			std::cout << indent_str << "Incomplete union (no body)\n";
			return;
		}
		std::cout << indent_str << "Members:\n";
		body->print(indent + 1);
	}
	void ast_statement_type_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[TypeDeclaration] Name: " << name << "\n";
		std::cout << indent_str << "Aliased Type:\n";
		aliased_type->print(indent + 1);
	}
	void ast_program::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[Program] Elements:\n" << std::flush;
		for (const auto& elem : body) {
			std::visit([&indent, indent_str]<typename T0>(const T0& node) {
				if constexpr (std::is_same_v<T0, ast_statement_function_declaration>) {
					node.print(indent + 1);
				}
				else if constexpr (std::is_same_v<T0, ast_statement_struct_declaration>) {
					node.print(indent + 1);
				}
				else if constexpr (std::is_same_v<T0, ast_statement_union_declaration>) {
					node.print(indent + 1);
				}
				else if constexpr (std::is_same_v<T0, ast_statement_type_declaration>) {
					node.print(indent + 1);
				}
				else if constexpr (std::is_same_v<T0, ast_statement_variable_declaration>) {
					node.print(indent + 1);
				}
				else {
					std::cout << indent_str << "  [Unknown Program Element]\n";
				}
			}, elem);
		}
	}
	std::ostream& operator<<(std::ostream& stream, const ast_type_node& n) {
		switch (n.type) {
			case ast_type_node::type_t::Int:
				stream << "int";
				break;
			case ast_type_node::type_t::UnsignedInt:
				stream << "unsigned int";
				break;
			case ast_type_node::type_t::Short:
				stream << "short";
				break;
			case ast_type_node::type_t::UnsignedShort:
				stream << "unsigned short";
				break;
			case ast_type_node::type_t::Void:
				stream << "void";
				break;
			case ast_type_node::type_t::Bool:
				stream << "bool";
				break;
			case ast_type_node::type_t::Char:
				stream << "char";
				break;
			case ast_type_node::type_t::SignedChar:
				stream << "signed char";
				break;
			case ast_type_node::type_t::Array: {
				const auto& arr = std::get<ast_type_array>(n.value);
				stream << "array[" << arr.size << "] of ";
				stream << *arr.base;
				break;
			}
			case ast_type_node::type_t::Pointer: {
				const auto& ptr = std::get<ast_type_pointer>(n.value);
				stream << "pointer to ";
				stream << *ptr.base;
				break;
			}
			case ast_type_node::type_t::Function: {
				const auto& func = std::get<ast_type_function>(n.value);
				stream << "function(";
				for (size_t i = 0; i < func.parameters.size(); ++i) {
					if (i > 0) {
						stream << ", ";
					}
					stream << *func.parameters[i];
				}
				stream << ") -> ";
				stream << *func.return_type;
				break;
			}
			case ast_type_node::type_t::Struct:
				stream << "struct { ... }";
				break;
			case ast_type_node::type_t::Union:
				stream << "union { ... }";
				break;
			case ast_type_node::type_t::Custom:
				stream << std::get<std::string>(n.value);
				break;
		}
		return stream;
	}
} // compiler
