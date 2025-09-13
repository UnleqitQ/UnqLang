#include "assembly_parser.hpp"

#include "../parser.hpp"

namespace assembly {
	namespace lexer {
		const std::vector<std::string> instructions = {
			"nop", "mov", "push", "pop", "lea",
			"add", "sub", "mul", "imul", "div", "idiv", "mod", "imod", "inc", "dec", "neg", "adc",
			"sbb",
			"cmp",
			"and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror", "rcl", "rcr",
			"test",
			"jmp", "jz", "je", "jnz", "jne", "jc", "jnc", "jo", "jno", "jp", "jnp", "js", "jns",
			"jg", "jl", "jge", "jle", "ja", "jae", "jb", "jbe",
			"call", "ret",
			"pusba", "popa", "pushf", "popf",
			"clc", "stc", "hlt", "end",
			"in", "out"
		};
		const std::vector<std::string> registers = {
			"eax", "ax", "ah", "al",
			"ebx", "bx", "bh", "bl",
			"ecx", "cx", "ch", "cl",
			"edx", "dx", "dh", "dl",
			"esi", "si",
			"edi", "di",
			"esp", "sp",
			"ebp", "bp",
		};
		bool is_separator(char c) {
			return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ':' || c == '[' || c == ']' || c == '('
				|| c == ')' || c == ';';
		}
		const Parser<char, assembly_token> instruction_parser =
			Parser<char, assembly_token>([](const std::vector<char>& input,
				std::vector<std::pair<assembly_token, size_t>>& output, ParserTable&) {
					for (const auto& instr : instructions) {
						if (input.size() >= instr.size()) {
							bool match = true;
							for (size_t i = 0; i < instr.size(); ++i) {
								if (std::tolower(static_cast<unsigned char>(input[i])) != std::tolower(
									static_cast<unsigned char>(instr[i]))) {
									match = false;
									break;
								}
							}
							// Ensure the instruction is not part of a longer identifier
							if (match && (input.size() == instr.size() || is_separator(input[instr.size()]))) {
								output.emplace_back(assembly_token{assembly_token::type::INSTRUCTION, instr}, instr.size());
								return;
							}
						}
					}
				}, "(instruction)");

		const Parser<char, assembly_token> register_parser =
			Parser<char, assembly_token>([](const std::vector<char>& input,
				std::vector<std::pair<assembly_token, size_t>>& output, ParserTable&) {
					for (const auto& reg : registers) {
						if (input.size() >= reg.size()) {
							bool match = true;
							for (size_t i = 0; i < reg.size(); ++i) {
								if (std::tolower(static_cast<unsigned char>(input[i])) != std::tolower(
									static_cast<unsigned char>(reg[i]))) {
									match = false;
									break;
								}
							}
							// Ensure the register is not part of a longer identifier
							if (match && (input.size() == reg.size() || is_separator(input[reg.size()]))) {
								output.emplace_back(assembly_token{assembly_token::type::REGISTER, reg}, reg.size());
								return;
							}
						}
					}
				}, "(register)");
		const Parser<char, assembly_token> data_size_parser =
			tokens<char>({"dword"_t, "word"_t, "byte"_t}, "data_size")
			.map<assembly_token>([](const std::vector<char>& text) {
				return assembly_token{assembly_token::type::DATA_SIZE, std::string(text.begin(), text.end())};
			}, "to_token");
		const Parser<char, assembly_token> ptr_parser =
			token("ptr").map<assembly_token>([](const std::vector<char>& text) {
				return assembly_token{assembly_token::type::PTR, std::string(text.begin(), text.end())};
			}, "to_token");
		const Parser<char, char> escape_char_parser =
			(symbol<char>('\\') > satisfy<char>([](char c) { return true; }, "any_char"))
			.map<char>(
				[](const char& c) {
					switch (c) {
						case 'n':
							return '\n';
						case 'r':
							return '\r';
						case 't':
							return '\t';
						case '\\':
							return '\\';
						case '\'':
							return '\'';
						default:
							return c;
					}
				}, "escape_char");
		const Parser<char, assembly_token> string_parser =
			(symbol<char>('\'') >
				*(
					escape_char_parser ||
					satisfy<char>([](char c) { return c != '\''; }, "not_quote")
				)
				< symbol<char>('\''))
			.map<assembly_token>([](const std::vector<char>& chars) {
				return assembly_token{assembly_token::type::STRING, std::string(chars.begin(), chars.end())};
			}, "to_token");
		const Parser<char, assembly_token> meta_parser =
			tokens<char>({"db"_t, "dw"_t, "dd"_t}, "meta")
			.map<assembly_token>([](const std::vector<char>& text) {
				return assembly_token{assembly_token::type::META, std::string(text.begin(), text.end())};
			}, "to_token");
		const Parser<char, assembly_token> decimal_number_parser =
			(+satisfy<char>([](char c) { return c >= '0' && c <= '9'; }, "is_dec")).map<assembly_token>(
				[](const std::vector<char>& digits) {
					return assembly_token{assembly_token::type::NUMBER, std::string(digits.begin(), digits.end())};
				}, "to_token");
		const Parser<char, assembly_token> hex_number_parser =
		(token("0x"_t) > +satisfy<char>([](char c) {
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
		}, "is_hex")).map<assembly_token>([](const std::vector<char>& parts) {
			std::string text = "0x";
			text += std::string(parts.begin(), parts.end());
			return assembly_token{assembly_token::type::NUMBER, text};
		}, "to_token");
		const Parser<char, assembly_token> number_parser =
			hex_number_parser || decimal_number_parser;
		const Parser<char, assembly_token> operator_parser =
			symbols<char>({'+', '-', '*'}, "op").map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::OPERATOR, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> left_paren_parser =
			symbol<char>('(').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::LEFT_PAREN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> right_paren_parser =
			symbol<char>(')').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::RIGHT_PAREN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> left_bracket_parser =
			symbol<char>('[').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::LEFT_BRACKET, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> right_bracket_parser =
			symbol<char>(']').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::RIGHT_BRACKET, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> comma_parser =
			symbol<char>(',').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::COMMA, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> colon_parser =
			symbol<char>(':').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::COLON, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> identifier_parser =
		(satisfy<char>([](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }, "is_id_start") +
			*(satisfy<char>([](char c) {
				return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
			}, "is_id_part"))).map<assembly_token>(
			[](const std::pair<char, std::vector<char>>& parts) {
				std::string text;
				text += parts.first;
				text += std::string(parts.second.begin(), parts.second.end());
				return assembly_token{assembly_token::type::IDENTIFIER, text};
			}, "to_token");
		const Parser<char, assembly_token> comment_parser =
			(symbol<char>(';') > *(satisfy<char>([](char c) { return c != '\n' && c != '\r'; }, "is_not_newline"))).map<
				assembly_token>([](const std::vector<char>& chars) {
				return assembly_token{assembly_token::type::COMMENT, std::string(chars.begin(), chars.end())};
			}, "to_token");
		const Parser<char, assembly_token> space_parser =
			symbols<char>({' ', '\t'}, "space").map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::UNKNOWN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> newline_parser =
			(tokens<char>({"\r\n"_t, "\n"_t, "\r"_t}, "newline")).map<assembly_token>(
				[](const std::vector<char>& chars) {
					return assembly_token{assembly_token::type::NEWLINE, std::string(chars.begin(), chars.end())};
				}, "to_token");
		const Parser<char, assembly_token> end_of_file_parser =
			!succeed<char, assembly_token>(assembly_token{assembly_token::type::END_OF_FILE, ""});

		const Parser<char, assembly_token> assembly_token_parser =
		(instruction_parser || register_parser || data_size_parser || ptr_parser
			|| string_parser || meta_parser
			|| number_parser || operator_parser || left_paren_parser ||
			right_paren_parser || left_bracket_parser || right_bracket_parser || comma_parser || colon_parser ||
			identifier_parser || comment_parser || space_parser || newline_parser);
		const Parser<char, std::vector<assembly_token>> assembly_tokenization_parser =
		((*(space_parser || newline_parser)) > (+(assembly_token_parser < (*space_parser)) < *(space_parser ||
			newline_parser))).map<std::vector<assembly_token>>(
			[](const std::vector<assembly_token>& p) {
				return p;
			}, "collect_tokens");
	} // namespace lexer

	std::vector<assembly_token> run_lexer(const std::string& input) {
		std::vector<char> chars(input.begin(), input.end());
		ParserTable empty_table;
		auto result = lexer::assembly_tokenization_parser.parse(chars, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				size_t limit = std::min(result[0].first.size(), result[1].first.size());
				for (size_t i = 0; i < limit; ++i) {
					if (result[0].first[i] != result[1].first[i]) {
						std::cerr << "  Difference at position " << i << ": '" << result[0].first[i] << "' vs '"
							<< result[1].first[i] << "'" << std::endl;
						break;
					}
				}
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			return result[0].first;
		}
		return {};
	}
	void remove_comments(std::vector<assembly_token>& tokens) {
		std::erase_if(tokens, [](const assembly_token& tok) {
			return tok.token_type == assembly_token::type::COMMENT;
		});
	}
	void join_newlines(const std::vector<assembly_token>& tokens, std::vector<assembly_token>& result) {
		bool last_was_newline = false;
		for (const auto& tok : tokens) {
			if (tok.token_type == assembly_token::type::NEWLINE) {
				if (!last_was_newline) {
					result.push_back(tok);
					last_was_newline = true;
				}
			}
			else {
				result.push_back(tok);
				last_was_newline = false;
			}
		}
	}

	namespace component_parser {
		Parser<assembly_token, assembly_token> is_token_type(assembly_token::type type) {
			auto type_parse_func = [type](const std::vector<assembly_token>& input,
				std::vector<std::pair<assembly_token, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].token_type == type) {
					output.emplace_back(input[0], 1);
				}
			};
			std::string type_name;
			switch (type) {
				case assembly_token::type::INSTRUCTION:
					type_name = "INSTRUCTION";
					break;
				case assembly_token::type::REGISTER:
					type_name = "REGISTER";
					break;
				case assembly_token::type::DATA_SIZE:
					type_name = "DATA_SIZE";
					break;
				case assembly_token::type::NUMBER:
					type_name = "NUMBER";
					break;
				case assembly_token::type::OPERATOR:
					type_name = "OPERATOR";
					break;
				case assembly_token::type::LEFT_PAREN:
					type_name = "LEFT_PAREN";
					break;
				case assembly_token::type::RIGHT_PAREN:
					type_name = "RIGHT_PAREN";
					break;
				case assembly_token::type::LEFT_BRACKET:
					type_name = "LEFT_BRACKET";
					break;
				case assembly_token::type::RIGHT_BRACKET:
					type_name = "RIGHT_BRACKET";
					break;
				case assembly_token::type::COMMA:
					type_name = "COMMA";
					break;
				case assembly_token::type::COLON:
					type_name = "COLON";
					break;
				case assembly_token::type::IDENTIFIER:
					type_name = "IDENTIFIER";
					break;
				case assembly_token::type::NEWLINE:
					type_name = "NEWLINE";
					break;
				case assembly_token::type::COMMENT:
					type_name = "COMMENT";
					break;
				case assembly_token::type::END_OF_FILE:
					type_name = "END_OF_FILE";
					break;
				case assembly_token::type::PTR:
					type_name = "PTR";
					break;
				case assembly_token::type::META:
					type_name = "META";
					break;
				case assembly_token::type::STRING:
					type_name = "STRING";
					break;
				case assembly_token::type::UNKNOWN:
					type_name = "UNKNOWN";
					break;
			}
			return Parser<assembly_token, assembly_token>(type_parse_func, std::format("(is_token_type {})", type_name));
		};
		const Parser<assembly_token, assembly_parse_component> instruction_parser =
			is_token_type(assembly_token::type::INSTRUCTION).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{machine::operation_from_string(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> register_parser =
			is_token_type(assembly_token::type::REGISTER).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{machine::register_t::from_string(tok.text)};
			}, "to_component");
		const Parser<assembly_token, machine::data_size_t> data_size_parser =
			is_token_type(assembly_token::type::DATA_SIZE).map<machine::data_size_t>([](const assembly_token& tok) {
				return machine::data_size_from_string(tok.text);
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> number_literal_parser =

			(is_token_type(assembly_token::type::OPERATOR).filter([](assembly_token tok) {
				return tok.text == "-" || tok.text == "+";
			}) + is_token_type(assembly_token::type::NUMBER)).map<assembly_parse_component>(
				[](const std::pair<assembly_token, assembly_token>& parts) {
					assembly_token sign_token = parts.first;
					assembly_token number_token = parts.second;
					int32_t value = 0;
					if (number_token.text.size() > 2 && number_token.text[0] == '0' && (number_token.text[1] == 'x' ||
						number_token.text[1] == 'X')) {
						value = std::stoi(number_token.text, nullptr, 16);
					}
					else {
						value = std::stoi(number_token.text, nullptr, 10);
					}
					if (sign_token.text == "-") {
						value = -value;
					}
					return assembly_parse_component{assembly_literal(value)};
				}, "to_component") ||
			is_token_type(assembly_token::type::NUMBER).map<assembly_parse_component>([](const assembly_token& tok) {
				int32_t value = 0;
				if (tok.text.size() > 2 && tok.text[0] == '0' && (tok.text[1] == 'x' || tok.text[1] == 'X')) {
					value = std::stoi(tok.text, nullptr, 16);
				}
				else {
					value = std::stoi(tok.text, nullptr, 10);
				}
				return assembly_parse_component{assembly_literal(value)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> label_parser =
			(is_token_type(assembly_token::type::IDENTIFIER) < is_token_type(assembly_token::type::COLON)).map<
				assembly_parse_component>(
				[](const assembly_token& tok) {
					return assembly_parse_component{tok.text};
				}, "to_component");
		const Parser<assembly_token, assembly_parse_component> label_literal_parser =
			is_token_type(assembly_token::type::IDENTIFIER).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{assembly_literal(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> literal_parser =
			number_literal_parser || label_literal_parser;
		const Parser<assembly_token, assembly_parse_component> label_definition_parser =
			(is_token_type(assembly_token::type::IDENTIFIER) < is_token_type(assembly_token::type::COLON)).map<
				assembly_parse_component>(
				[](const assembly_token& tok) {
					return assembly_parse_component{tok.text};
				}, "to_component");
		const Parser<assembly_token, assembly_memory> direct_memory_parser =
			literal_parser.map<assembly_memory>([](const assembly_parse_component& comp) {
				return assembly_memory(std::get<assembly_literal>(comp.value));
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> register_memory_parser =
			register_parser.map<assembly_memory>([](const assembly_parse_component& comp) {
				return assembly_memory(std::get<machine::register_t>(comp.value));
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> displacement_memory_parser =
		(register_parser + is_token_type(assembly_token::type::OPERATOR).filter(
			[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; }) + literal_parser).filter(
			[](const std::pair<std::pair<assembly_parse_component, assembly_token>, assembly_parse_component>& p) {
				// Disallow negative displacement for labels
				return !(p.first.second.text == "-" && std::get<assembly_literal>(p.second.value).literal_type
					==
					assembly_literal::type::LABEL);
			}).map<assembly_memory>(
			[](const std::pair<std::pair<assembly_parse_component, assembly_token>, assembly_parse_component>& parts) {
				assembly_parse_component base_comp = parts.first.first;
				assembly_token sign_token = parts.first.second;
				assembly_parse_component disp_comp = parts.second;
				assembly_literal disp_lit = std::get<assembly_literal>(disp_comp.value);
				if (sign_token.text == "-") {
					if (disp_lit.literal_type == assembly_literal::type::NUMBER) {
						disp_lit.value = -std::get<int32_t>(disp_lit.value);
					}
					else {
						throw std::invalid_argument("Negative displacement for labels is not allowed");
					}
				}
				return assembly_memory(std::get<machine::register_t>(base_comp.value), disp_lit);
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> scaled_index_memory_parser =
			(register_parser
				+ is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; })
				+ register_parser
				+ is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "*"; })
				+ number_literal_parser)
			.map<std::tuple<assembly_parse_component, assembly_token, assembly_parse_component, assembly_token,
				assembly_parse_component>>(
				[](const auto& p) {
					return std::make_tuple(p.first.first.first.first, p.first.first.first.second, p.first.first.second,
						p.first.second, p.second);
				})
			.map<assembly_memory>(
				[](const std::tuple<assembly_parse_component, assembly_token, assembly_parse_component, assembly_token,
				assembly_parse_component>& parts) {
					assembly_parse_component base_comp = std::get<0>(parts);
					assembly_token sign_token = std::get<1>(parts);
					assembly_parse_component index_comp = std::get<2>(parts);
					assembly_token mul_token = std::get<3>(parts);
					assembly_parse_component scale_comp = std::get<4>(parts);
					int8_t scale = static_cast<int8_t>(std::get<int32_t>(std::get<assembly_literal>(
						scale_comp.value).value));
					if (sign_token.text == "-") {
						scale = -scale;
					}
					return assembly_memory(std::get<machine::register_t>(base_comp.value),
						std::get<machine::register_t>(index_comp.value), scale);
				}, "to_memory");
		const Parser<assembly_token, assembly_memory> scaled_index_displacement_memory_parser =
		(scaled_index_memory_parser +
			(is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; })
				+ literal_parser).filter(
				[](const std::pair<assembly_token, assembly_parse_component>& p) {
					// Disallow negative displacement for labels
					return !(p.first.text == "-" && std::get<assembly_literal>(p.second.value).literal_type ==
						assembly_literal::type::LABEL);
				})).map<assembly_memory>(
			[](const std::pair<assembly_memory, std::pair<assembly_token, assembly_parse_component>>& parts) {
				assembly_memory base_mem = parts.first;
				assembly_token sign_token = parts.second.first;
				assembly_parse_component disp_comp = parts.second.second;
				assembly_literal disp_lit = std::get<assembly_literal>(
					disp_comp.value);
				if (sign_token.text == "-" && disp_lit.literal_type == assembly_literal::type::NUMBER) {
					disp_lit.value = -std::get<int32_t>(disp_lit.value);
				}
				const assembly_memory::scaled_index& si = std::get<assembly_memory::scaled_index>(
					base_mem.value);
				return assembly_memory(si.base, si.index, si.scale, disp_lit);
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> memory_parser_raw =
		(is_token_type(assembly_token::type::LEFT_BRACKET) >
			(scaled_index_displacement_memory_parser || scaled_index_memory_parser || displacement_memory_parser ||
				register_memory_parser || direct_memory_parser) <
			is_token_type(assembly_token::type::RIGHT_BRACKET));
		const Parser<assembly_token, assembly_parse_component> memory_parser =
			memory_parser_raw.map<assembly_parse_component>([](const assembly_memory& mem) {
				return assembly_parse_component{mem};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> memory_ptr_parser =
			((data_size_parser < is_token_type(assembly_token::type::PTR)) + memory_parser_raw).map<
				assembly_parse_component>([](const std::pair<machine::data_size_t, assembly_memory>& parts) {
				assembly_memory mem = parts.second;
				machine::data_size_t size = parts.first;
				return assembly_parse_component{assembly_memory_pointer{size, mem}};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> newline_parser =
			(+is_token_type(assembly_token::type::NEWLINE)).map<assembly_parse_component>([](const auto& /*nls*/) {
				return assembly_parse_component{assembly_parse_component::type::NEWLINE};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> end_of_file_parser =
			!is_token_type(assembly_token::type::END_OF_FILE).map<assembly_parse_component>(
				[](const auto& /*c*/) {
					return assembly_parse_component{assembly_parse_component::type::END_OF_FILE};
				}, "to_component");
		const Parser<assembly_token, assembly_parse_component> comma_parser =
			is_token_type(assembly_token::type::COMMA).map<assembly_parse_component>([](const auto& /*c*/) {
				return assembly_parse_component{assembly_parse_component::type::COMMA};
			}, "to_component");

		const Parser<assembly_token, assembly_parse_component> meta_parser =
			is_token_type(assembly_token::type::META).map<assembly_parse_component>([](const assembly_token& tok) {
				meta_type mt;
				if (tok.text == "db") {
					mt = meta_type::DB;
				}
				else if (tok.text == "dw") {
					mt = meta_type::DW;
				}
				else if (tok.text == "dd") {
					mt = meta_type::DD;
				}
				else {
					throw std::invalid_argument("Invalid meta type: " + tok.text);
				}
				return assembly_parse_component{mt};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> string_parser =
			is_token_type(assembly_token::type::STRING).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{assembly_parse_component::type::STRING, tok.text};
			}, "to_component");

		const Parser<assembly_token, assembly_parse_component> assembly_component_parser =
		(instruction_parser || register_parser || label_parser || literal_parser ||
			label_definition_parser || memory_parser || memory_ptr_parser || newline_parser ||
			end_of_file_parser || comma_parser || meta_parser || string_parser);
		const Parser<assembly_token, std::vector<assembly_parse_component>> component_list_parser =
			+assembly_component_parser;
	} // namespace component_parser

	std::vector<assembly_parse_component> run_component_parser(const std::vector<assembly_token>& tokens) {
		ParserTable empty_table;
		auto result = component_parser::component_list_parser.parse(tokens, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			return result[0].first;
		}
		return {};
	}

	namespace parser {
		Parser<assembly_parse_component, assembly_parse_component> is_component_type(assembly_parse_component::type type) {
			auto type_parse_func = [type](const std::vector<assembly_parse_component>& input,
				std::vector<std::pair<assembly_parse_component, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].component_type == type) {
					output.emplace_back(input[0], 1);
				}
			};
			std::string type_name;
			switch (type) {
				case assembly_parse_component::type::INSTRUCTION:
					type_name = "INSTRUCTION";
					break;
				case assembly_parse_component::type::REGISTER:
					type_name = "REGISTER";
					break;
				case assembly_parse_component::type::LITERAL:
					type_name = "LITERAL";
					break;
				case assembly_parse_component::type::LABEL:
					type_name = "LABEL";
					break;
				case assembly_parse_component::type::MEMORY:
					type_name = "MEMORY";
					break;
				case assembly_parse_component::type::MEMORY_POINTER:
					type_name = "MEMORY_POINTER";
					break;
				case assembly_parse_component::type::NEWLINE:
					type_name = "NEWLINE";
					break;
				case assembly_parse_component::type::END_OF_FILE:
					type_name = "END_OF_FILE";
					break;
				case assembly_parse_component::type::UNKNOWN:
					type_name = "UNKNOWN";
					break;
				case assembly_parse_component::type::COMMA:
					type_name = "COMMA";
					break;
				default:
					type_name = "INVALID";
					break;
			}
			return Parser<assembly_parse_component, assembly_parse_component>(type_parse_func,
				std::format("(is_component_type {})", type_name));
		};
		const Parser<assembly_parse_component, assembly_operand> operand_parser =
			is_component_type(assembly_parse_component::type::REGISTER).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<machine::register_t>(comp.value)};
				}, "to_operand") ||
			is_component_type(assembly_parse_component::type::LITERAL).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<assembly_literal>(comp.value)};
				}, "to_operand") ||
			is_component_type(assembly_parse_component::type::MEMORY_POINTER).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<assembly_memory_pointer>(comp.value)};
				}, "to_operand");
		const Parser<assembly_parse_component, assembly_result> result_parser =
			is_component_type(assembly_parse_component::type::REGISTER).map<assembly_result>(
				[](const assembly_parse_component& comp) {
					return assembly_result{std::get<machine::register_t>(comp.value)};
				}, "to_result") ||
			is_component_type(assembly_parse_component::type::MEMORY_POINTER).map<assembly_result>(
				[](const assembly_parse_component& comp) {
					return assembly_result{
						std::get<assembly_memory_pointer>(comp.value)
					};
				}, "to_result");


		// Parsers for different argument patterns (0-2 operands, with/without result, and memory-result)

		const Parser<assembly_parse_component, assembly_instruction::args_t<0, false>> args_0n_parser =
			succeed<assembly_parse_component, assembly_instruction::args_t<0, false>>(
				assembly_instruction::args_t<0, false>{});

		const Parser<assembly_parse_component, assembly_instruction::args_t<0, true>> args_0r_parser =
			result_parser
			.map<assembly_instruction::args_t<0, true>>(
				[](const auto& parts) {
					return assembly_instruction::args_t<0, true>{{}, parts};
				}, "to_args");

		const Parser<assembly_parse_component, assembly_instruction::args_t<1, false>> args_1n_parser =
			operand_parser
			.map<assembly_instruction::args_t<1, false>>(
				[](const auto& parts) {
					return assembly_instruction::args_t<1, false>{{parts}};
				}, "to_args");

		const Parser<assembly_parse_component, assembly_instruction::args_t<1, true>> args_1r_parser =
			(result_parser + (is_component_type(assembly_parse_component::type::COMMA) >
				operand_parser))
			.map<assembly_instruction::args_t<1, true>>(
				[](const auto& parts) {
					return assembly_instruction::args_t<1, true>{{parts.second}, parts.first};
				}, "to_args");

		const Parser<assembly_parse_component, assembly_instruction::args_t<2, false>> args_2n_parser =
			(operand_parser + (is_component_type(assembly_parse_component::type::COMMA) >
				operand_parser))
			.map<assembly_instruction::args_t<2, false>>(
				[](const auto& parts) {
					return assembly_instruction::args_t<2, false>{{parts.first, parts.second}};
				}, "to_args");
		const Parser<assembly_parse_component, assembly_instruction::args_mr_t> args_mr_parser =
			(result_parser + (is_component_type(assembly_parse_component::type::COMMA) >
				is_component_type(assembly_parse_component::type::MEMORY)))
			.map<assembly_instruction::args_mr_t>(
				[](const auto& parts) {
					const auto& mem_comp = std::get<assembly_memory>(parts.second.value);
					return assembly_instruction::args_mr_t{mem_comp, parts.first};
				}, "to_args");

		const std::vector<machine::operation> operations_0n = {
			machine::operation::NOP,
			machine::operation::RET,
			machine::operation::HLT,
			machine::operation::CLC,
			machine::operation::STC,
			machine::operation::PUSHF,
			machine::operation::POPF,
			machine::operation::PUSHA,
			machine::operation::POPA
		};
		const std::vector<machine::operation> operations_0r = {
			machine::operation::POP,
			machine::operation::INC,
			machine::operation::DEC,
			machine::operation::IN,
			machine::operation::NEG,
			machine::operation::NOT
		};
		const std::vector<machine::operation> operations_1n = {
			machine::operation::JMP,
			machine::operation::JZ,
			machine::operation::JNZ,
			machine::operation::JC,
			machine::operation::JNC,
			machine::operation::JO,
			machine::operation::JNO,
			machine::operation::JS,
			machine::operation::JNS,
			machine::operation::JP,
			machine::operation::JNP,
			machine::operation::JG,
			machine::operation::JGE,
			machine::operation::JL,
			machine::operation::JLE,
			machine::operation::JA,
			machine::operation::JAE,
			machine::operation::JB,
			machine::operation::JBE,
			machine::operation::CALL,
			machine::operation::PUSH,
			machine::operation::OUT,
		};
		const std::vector<machine::operation> operations_1r = {
			machine::operation::MOV,
			machine::operation::ADD,
			machine::operation::SUB,
			machine::operation::MUL,
			machine::operation::IMUL,
			machine::operation::DIV,
			machine::operation::IDIV,
			machine::operation::MOD,
			machine::operation::IMOD,
			machine::operation::ADC,
			machine::operation::SBB,
			machine::operation::AND,
			machine::operation::OR,
			machine::operation::XOR,
			machine::operation::SHL,
			machine::operation::SHR,
			machine::operation::SAR,
			machine::operation::ROL,
			machine::operation::ROR,
			machine::operation::RCL,
			machine::operation::RCR,
		};
		const std::vector<machine::operation> operations_2n = {
			machine::operation::CMP,
			machine::operation::TEST,
		};
		// Special case: LEA only with memory operand
		const std::vector<machine::operation> operations_mr = {
			machine::operation::LEA,
		};
		Parser<assembly_parse_component, assembly_parse_component> is_instruction_of_type(
			const std::vector<machine::operation>& ops) {
			auto instr_parse_func = [ops](const std::vector<assembly_parse_component>& input,
				std::vector<std::pair<assembly_parse_component, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].component_type == assembly_parse_component::type::INSTRUCTION) {
					machine::operation op = std::get<machine::operation>(input[0].value);
					if (std::find(ops.begin(), ops.end(), op) != ops.end()) {
						output.emplace_back(input[0], 1);
					}
				}
			};
			std::string ops_list;
			return Parser<assembly_parse_component, assembly_parse_component>(instr_parse_func,
				"(is_instruction_of_type [...])");
		};
		const Parser<assembly_parse_component, assembly_instruction> instruction_parser =
		((is_instruction_of_type(operations_0n) + args_0n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<0, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_0r) + args_0r_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<0, true>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_1n) + args_1n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<1, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_1r) + args_1r_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<1, true>>& parts) {
					if (std::get<machine::operation>(parts.first.value) == machine::operation::LEA) {
						// LEA requires the operand to be memory
						if (parts.second.operands[0].operand_type != assembly_operand::type::MEMORY_POINTER) {
							throw std::invalid_argument("LEA instruction requires a memory operand");
						}
					}
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_2n) + args_2n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<2, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_mr) + args_mr_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_mr_t>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction"));
		const Parser<assembly_parse_component, std::string> label_parser =
			is_component_type(assembly_parse_component::type::LABEL).map<std::string>(
				[](const assembly_parse_component& comp) {
					return std::get<std::string>(comp.value);
				}, "to_label");
		const Parser<assembly_parse_component, std::variant<uint32_t, std::string>> meta_data_parser =
			(is_component_type(assembly_parse_component::type::LITERAL).filter([](const assembly_parse_component& comp) {
				return std::get<assembly_literal>(comp.value).literal_type == assembly_literal::type::NUMBER;
			}).map<std::variant<uint32_t, std::string>>(
				[](const assembly_parse_component& comp) {
					return static_cast<uint32_t>(std::get<int32_t>(std::get<assembly_literal>(
						comp.value).value));
				}, "to_number")) ||
			(is_component_type(assembly_parse_component::type::STRING).map<std::variant<uint32_t, std::string>>(
				[](const assembly_parse_component& comp) {
					return std::get<std::string>(comp.value);
				}, "to_string"));
		void convert_meta(const meta_type& meta, const std::vector<std::variant<uint32_t, std::string>>& data,
			std::vector<uint8_t>& output) {
			switch (meta) {
				case meta_type::DB:
					for (const auto& item : data) {
						if (std::holds_alternative<uint32_t>(item)) {
							uint32_t value = std::get<uint32_t>(item);
							if (value > 0xFF) {
								throw std::out_of_range("DB value out of range: " + std::to_string(value));
							}
							output.push_back(static_cast<uint8_t>(value));
						}
						else if (std::holds_alternative<std::string>(item)) {
							const std::string& str = std::get<std::string>(item);
							output.insert(output.end(), str.begin(), str.end());
						}
					}
					break;
				case meta_type::DW:
					for (const auto& item : data) {
						if (std::holds_alternative<uint32_t>(item)) {
							uint32_t value = std::get<uint32_t>(item);
							if (value > 0xFFFF) {
								throw std::out_of_range("DW value out of range: " + std::to_string(value));
							}
							output.push_back(static_cast<uint8_t>(value & 0xFF));
							output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
						}
						else if (std::holds_alternative<std::string>(item)) {
							const std::string& str = std::get<std::string>(item);
							for (char c : str) {
								output.push_back(static_cast<uint8_t>(c));
								output.push_back(0); // Null-terminate each character
							}
						}
					}
					break;
				case meta_type::DD:
					for (const auto& item : data) {
						if (std::holds_alternative<uint32_t>(item)) {
							uint32_t value = std::get<uint32_t>(item);
							output.push_back(static_cast<uint8_t>(value & 0xFF));
							output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
							output.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
							output.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
						}
						else if (std::holds_alternative<std::string>(item)) {
							const std::string& str = std::get<std::string>(item);
							for (char c : str) {
								output.push_back(static_cast<uint8_t>(c));
								output.push_back(0); // Null-terminate each character
								output.push_back(0);
								output.push_back(0);
							}
						}
					}
					break;
				default:
					throw std::invalid_argument("Unknown meta type");
			}
		}
		const Parser<assembly_parse_component, assembly_component> meta_parser =
			(is_component_type(assembly_parse_component::type::META) +
				(meta_data_parser % is_component_type(assembly_parse_component::type::COMMA)))
			.map<assembly_component>(
				[](const auto& parts) {
					meta_type mt = std::get<meta_type>(parts.first.value);
					const auto& data = parts.second;
					std::vector<uint8_t> bytes;
					convert_meta(mt, data, bytes);
					return assembly_component{bytes};
				}, "to_meta");


		const Parser<assembly_parse_component, assembly_parse_component> newline_parser = is_component_type(
			assembly_parse_component::type::NEWLINE);
		const Parser<assembly_parse_component, assembly_component> line_parser =
		(
			instruction_parser.map<assembly_component>([](const assembly_instruction& instr) {
				return assembly_component{instr};
			}, "to_component")
			|| label_parser.map<assembly_component>([](const std::string& label) {
				return assembly_component{label};
			}, "to_component")
			|| meta_parser
		);
		const Parser<assembly_parse_component, std::vector<assembly_component>> instructions_parser =
			(*newline_parser > line_parser + *(newline_parser > line_parser) < *
				newline_parser)
			.map<std::vector<assembly_component>>(
				[](const std::pair<assembly_component, std::vector<assembly_component>>& parts) {
					std::vector<assembly_component> result;
					result.reserve(1 + parts.second.size());
					result.push_back(parts.first);
					result.insert(result.end(), parts.second.begin(), parts.second.end());
					return result;
				}, "to_instructions");
	}

	assembly_program_t run_parser(const std::vector<assembly_parse_component>& components) {
		ParserTable empty_table;
		auto result = parser::instructions_parser.parse(components, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			std::vector<assembly_component> parsed_components;
			for (const auto& instr : result[0].first) {
				parsed_components.push_back(instr);
			}
			return parsed_components;
		}
		return {};
	}

	std::ostream& operator<<(std::ostream& os, const assembly_token& tok) {
		switch (tok.token_type) {
			case assembly_token::type::INSTRUCTION:
				os << "INSTRUCTION(" << tok.text << ")";
				break;
			case assembly_token::type::REGISTER:
				os << "REGISTER(" << tok.text << ")";
				break;
			case assembly_token::type::DATA_SIZE:
				os << "DATA_SIZE(" << tok.text << ")";
				break;
			case assembly_token::type::NUMBER:
				os << "NUMBER(" << tok.text << ")";
				break;
			case assembly_token::type::OPERATOR:
				os << "OPERATOR(" << tok.text << ")";
				break;
			case assembly_token::type::LEFT_PAREN:
				os << "LEFT_PAREN(" << tok.text << ")";
				break;
			case assembly_token::type::RIGHT_PAREN:
				os << "RIGHT_PAREN(" << tok.text << ")";
				break;
			case assembly_token::type::LEFT_BRACKET:
				os << "LEFT_BRACKET(" << tok.text << ")";
				break;
			case assembly_token::type::RIGHT_BRACKET:
				os << "RIGHT_BRACKET(" << tok.text << ")";
				break;
			case assembly_token::type::COMMA:
				os << "COMMA(" << tok.text << ")";
				break;
			case assembly_token::type::COLON:
				os << "COLON(" << tok.text << ")";
				break;
			case assembly_token::type::IDENTIFIER:
				os << "IDENTIFIER(" << tok.text << ")";
				break;
			case assembly_token::type::NEWLINE:
				os << "NEWLINE";
				break;
			case assembly_token::type::COMMENT:
				os << "COMMENT(" << tok.text << ")";
				break;
			case assembly_token::type::END_OF_FILE:
				os << "END_OF_FILE";
				break;
			case assembly_token::type::UNKNOWN:
				os << "UNKNOWN(" << tok.text << ")";
				break;
			case assembly_token::type::STRING:
				os << "STRING(" << tok.text << ")";
				break;
			case assembly_token::type::META:
				os << "META(" << tok.text << ")";
				break;
			case assembly_token::type::PTR:
				os << "PTR(" << tok.text << ")";
				break;
			default: break;
		}
		return os;
	}
	std::string assembly_parse_component::to_string() const {
		switch (component_type) {
			case type::INSTRUCTION:
				return std::format("INSTRUCTION({})", machine::operation_to_string(std::get<machine::operation>(value)));
			case type::REGISTER:
				return std::format("REGISTER({})", std::get<machine::register_t>(value).to_string());
			case type::LITERAL:
				return std::format("LITERAL({})", std::get<assembly_literal>(value).to_string());
			case type::LABEL:
				return std::format("LABEL({})", std::get<std::string>(value));
			case type::MEMORY:
				return std::format("MEMORY({})", std::get<assembly_memory>(value).to_string());
			case type::MEMORY_POINTER:
				return std::format("MEMORY_POINTER({})", std::get<assembly_memory_pointer>(value).to_string());
			case type::NEWLINE:
				return "NEWLINE";
			case type::END_OF_FILE:
				return "END_OF_FILE";
			case type::COMMA:
				return "COMMA";
			case type::UNKNOWN:
				return "UNKNOWN";
			default: break;
		}
		return "";
	}
	std::ostream& operator<<(std::ostream& os, const assembly_parse_component& comp) {
		switch (comp.component_type) {
			case assembly_parse_component::type::INSTRUCTION:
				os << "INSTRUCTION(" << std::get<machine::operation>(comp.value) << ")";
				break;
			case assembly_parse_component::type::REGISTER:
				os << "REGISTER(" << std::get<machine::register_t>(comp.value).to_string() << ")";
				break;
			case assembly_parse_component::type::MEMORY_POINTER:
				os << "MEMORY_POINTER(" << std::get<assembly_memory_pointer>(comp.value).to_string() << ")";
				break;
			case assembly_parse_component::type::LITERAL: {
				const assembly_literal& lit = std::get<assembly_literal>(comp.value);
				switch (lit.literal_type) {
					case assembly_literal::type::NUMBER:
						os << "LITERAL(NUMBER, " << std::get<int32_t>(lit.value) << ")";
						break;
					case assembly_literal::type::LABEL:
						os << "LITERAL(LABEL, " << std::get<std::string>(lit.value) << ")";
						break;
				}
				break;
			}
			case assembly_parse_component::type::LABEL:
				os << "LABEL(" << std::get<std::string>(comp.value) << ")";
				break;
			case assembly_parse_component::type::MEMORY: {
				const assembly_memory& mem = std::get<assembly_memory>(comp.value);
				switch (mem.memory_type) {
					case assembly_memory::type::DIRECT: {
						const auto& lit = std::get<extended_assembly_literal>(mem.value);
						os << "MEMORY(DIRECT, " << lit.to_string() << ")";
						break;
					}
					case assembly_memory::type::REGISTER:
						os << "MEMORY(REGISTER, " << std::get<machine::register_t>(mem.value).machine::register_t::to_string() <<
							")";
						break;
					case assembly_memory::type::DISPLACEMENT: {
						const assembly_memory::displacement& disp = std::get<
							assembly_memory::displacement>(mem.value);
						os << "MEMORY(DISPLACEMENT, BASE=" << disp.reg.to_string() << ", DISP=";
						os << disp.disp.to_string();
						os << ")";
						break;
					}
					case assembly_memory::type::SCALED_INDEX: {
						const assembly_memory::scaled_index& si = std::get<
							assembly_memory::scaled_index>(mem.value);
						os << "MEMORY(SCALED_INDEX, BASE=" << si.base.to_string() << ", INDEX=" << si.index.to_string() <<
							", SCALE=" << static_cast<int>(si.scale) << ")";
						break;
					}
					case assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
						const assembly_memory::scaled_index_displacement& sid = std::get<
							assembly_memory::scaled_index_displacement>(mem.value);
						os << "MEMORY(SCALED_INDEX_DISPLACEMENT, BASE=" << sid.base.to_string() << ", INDEX=" << sid.index.
							to_string() << ", SCALE=" << static_cast<int>(sid.scale) << ", DISP=";
						os << sid.disp.to_string();
						os << ")";
						break;
					}
				}
				break;
			}
			case assembly_parse_component::type::NEWLINE:
				os << "NEWLINE";
				break;
			case assembly_parse_component::type::END_OF_FILE:
				os << "END_OF_FILE";
				break;
			case assembly_parse_component::type::COMMA:
				os << "COMMA";
				break;
			case assembly_parse_component::type::UNKNOWN:
				os << "UNKNOWN";
				break;
			case assembly_parse_component::type::STRING:
				os << "STRING(" << std::get<std::string>(comp.value) << ")";
				break;
			case assembly_parse_component::type::META:
				os << "META(";
				switch (std::get<meta_type>(comp.value)) {
					case meta_type::DB:
						os << "DB";
						break;
					case meta_type::DW:
						os << "DW";
						break;
					case meta_type::DD:
						os << "DD";
						break;
				}
				os << ")";
				break;
			default:
				os << "INVALID_COMPONENT";
				break;
		}
		return os;
	}
} // assembly
