#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <variant>

#include "../machine/instruction.hpp"
#include "../machine/ram.hpp"
#include "../machine/register.hpp"
#include "assembly.hpp"

namespace assembly {
	struct assembly_token {
		enum class type {
			INSTRUCTION, // e.g. mov, add, sub
			REGISTER, // e.g. eax, ebx, ecx
			DATA_SIZE, // dword, word, byte
			NUMBER, // e.g. 123, 0x7B
			OPERATOR, // +, -, *
			LEFT_PAREN, // (
			RIGHT_PAREN, // )
			LEFT_BRACKET, // [
			RIGHT_BRACKET, // ]
			COMMA, // ,
			COLON, // :
			IDENTIFIER, // labels
			NEWLINE, // end of line
			COMMENT, // e.g. ; this is a comment
			END_OF_FILE, // end of input
			PTR, // ptr

			META, // e.g. db, dw, dd
			STRING, // in e.g. db "hello, world"

			UNKNOWN // unrecognized token
		} token_type;
		std::string text;
		friend std::ostream& operator<<(std::ostream& os, const assembly_token& tok);
		bool operator==(const assembly_token& other) const {
			return token_type == other.token_type && text == other.text;
		}
	};

	std::vector<assembly_token> run_lexer(const std::string& input);
	void remove_comments(std::vector<assembly_token>& tokens);
	void join_newlines(const std::vector<assembly_token>& tokens, std::vector<assembly_token>& result);

	enum class meta_type {
		DB, // define byte
		DW, // define word
		DD // define double word
	};
	struct assembly_parse_component {
		enum class type : uint8_t {
			INSTRUCTION, // mov, add, sub, etc.
			REGISTER, // eax, ebx, ecx, etc.
			LITERAL, // number or label reference
			LABEL, // label definition
			MEMORY, // memory access
			MEMORY_POINTER, // memory access with specified size
			NEWLINE, // end of line
			END_OF_FILE, // end of input
			COMMA, // ,
			META, // e.g. db, dw, dd
			STRING, // string literal in e.g. db "hello, world"
			UNKNOWN // unrecognized component
		} component_type;
		std::variant<
			machine::operation, // INSTRUCTION
			machine::register_t, // REGISTER
			assembly_literal, // LITERAL
			std::string, // LABEL DEFINITION, STRING
			assembly_memory, // MEMORY
			assembly_memory_pointer, // MEMORY_POINTER
			meta_type, // META
			std::monostate // NEWLINE, END_OF_FILE, UNKNOWN, COMMA
		> value;
		explicit assembly_parse_component(machine::operation op)
			: component_type(type::INSTRUCTION), value(op) {
		}
		explicit assembly_parse_component(machine::register_t reg)
			: component_type(type::REGISTER), value(reg) {
		}
		explicit assembly_parse_component(assembly_literal lit)
			: component_type(type::LITERAL), value(lit) {
		}
		explicit assembly_parse_component(const std::string& label)
			: component_type(type::LABEL), value(label) {
		}
		explicit assembly_parse_component(meta_type mt)
			: component_type(type::META), value(mt) {
		}
		assembly_parse_component(type t, const std::string& text)
			: component_type(t), value(text) {
			if (t != type::LABEL && t != type::STRING) {
				throw std::invalid_argument("Invalid type for this constructor");
			}
		}
		explicit assembly_parse_component(assembly_memory mem)
			: component_type(type::MEMORY), value(mem) {
		}
		explicit assembly_parse_component(assembly_memory_pointer mem)
			: component_type(type::MEMORY_POINTER), value(mem) {
		}
		explicit assembly_parse_component(type t)
			: component_type(t), value(std::monostate{}) {
			if (t != type::NEWLINE && t != type::END_OF_FILE && t != type::UNKNOWN && t != type::COMMA) {
				throw std::invalid_argument("Invalid type for this constructor");
			}
		}
		std::string to_string() const;
		friend std::ostream& operator<<(std::ostream& os, const assembly_parse_component& comp);
	};

	std::vector<assembly_parse_component> run_component_parser(const std::vector<assembly_token>& tokens);

	assembly_program_t run_parser(const std::vector<assembly_parse_component>& components);
} // assembly
