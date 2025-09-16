#pragma once
#ifndef MACHINE_REGISTER
#define MACHINE_REGISTER
#endif

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <format>

#include "ram.hpp"

namespace machine {
	enum class register_id : uint8_t {
		eax = 0,
		ebx = 1,
		ecx = 2,
		edx = 3,
		esi = 4,
		edi = 5,
		esp = 6,
		ebp = 7,
		eip = 8,
		flags = 9
	};
	inline std::string to_string(register_id id);
	inline std::ostream& operator<<(std::ostream& os, register_id id) {
		os << to_string(id);
		return os;
	}
	enum class register_access : uint8_t {
		dword = 0,
		word = 1,
		low_byte = 2,
		high_byte = 3
	};
	struct register_t {
		register_id id : 5;
		register_access access : 2;
		constexpr register_t(register_id id, register_access access = register_access::dword)
			: id(id), access(access) {
			if (static_cast<uint8_t>(id) > 5 && static_cast<uint8_t>(access) > 1) {
				throw std::runtime_error("Invalid access type for this register");
			}
			if (id == register_id::flags && access != register_access::dword) {
				throw std::runtime_error("Flags register must be accessed as dword");
			}
		}
		constexpr register_t(register_id id, data_size_t size)
			: id(id), access([size] {
				switch (size) {
					case data_size_t::BYTE:
						return register_access::low_byte;
					case data_size_t::WORD:
						return register_access::word;
					case data_size_t::DWORD:
						return register_access::dword;
					default:
						throw std::runtime_error("Invalid data size for register access");
				}
			}()) {
			if (static_cast<uint8_t>(id) > 5 && static_cast<uint8_t>(access) > 1) {
				throw std::runtime_error("Invalid access type for this register");
			}
			if (id == register_id::flags && access != register_access::dword) {
				throw std::runtime_error("Flags register must be accessed as dword");
			}
		}
		[[nodiscard]] std::string to_string() const;
		bool operator==(const register_t& other) const {
			return id == other.id && access == other.access;
		}
		static register_t from_string(const std::string& str);
		friend std::ostream& operator<<(std::ostream& os, const register_t& reg) {
			os << reg.to_string();
			return os;
		}
	};

	enum class flag : uint8_t {
		carry = 0,
		parity = 2,
		auxiliary = 4,
		zero = 6,
		sign = 7,
		overflow = 11,
	};

	struct register_file {
		union {
			std::array<uint32_t, 9> regs{};

			struct {
				uint32_t eax;
				uint32_t ebx;
				uint32_t ecx;
				uint32_t edx;
				uint32_t esi;
				uint32_t edi;
				uint32_t esp;
				uint32_t ebp;
				uint32_t eip;
				union {
					uint32_t value;
					struct {
						uint32_t cf : 1; // Carry Flag
						uint32_t  : 1; // Reserved
						uint32_t pf : 1; // Parity Flag
						uint32_t  : 1; // Reserved
						uint32_t af : 1; // Auxiliary Carry Flag
						uint32_t  : 1; // Reserved
						uint32_t zf : 1; // Zero Flag
						uint32_t sf : 1; // Sign Flag
						uint32_t  : 3; // Reserved
						uint32_t of : 1; // Overflow Flag
						uint32_t  : 20; // Reserved
					};
				} flags;
			};
		};

		uint32_t& operator[](register_id id) {
			return regs[static_cast<uint8_t>(id)];
		}
		uint32_t operator[](register_id id) const {
			return regs[static_cast<uint8_t>(id)];
		}
		[[nodiscard]] uint32_t get(register_t reg) const {
			switch (reg.access) {
				case register_access::dword:
					return regs[static_cast<uint8_t>(reg.id)];
				case register_access::word:
					return regs[static_cast<uint8_t>(reg.id)] & 0xFFFF;
				case register_access::low_byte:
					return regs[static_cast<uint8_t>(reg.id)] & 0xFF;
				case register_access::high_byte:
					return (regs[static_cast<uint8_t>(reg.id)] >> 8) & 0xFF;
				default:
					throw std::runtime_error("Invalid access type");
			}
		}
		void set(register_t reg, uint32_t value) {
			switch (reg.access) {
				case register_access::dword:
					regs[static_cast<uint8_t>(reg.id)] = value;
					break;
				case register_access::word:
					regs[static_cast<uint8_t>(reg.id)] = (regs[static_cast<uint8_t>(reg.id)] & 0xFFFF0000) | (value & 0xFFFF);
					break;
				case register_access::low_byte:
					regs[static_cast<uint8_t>(reg.id)] = (regs[static_cast<uint8_t>(reg.id)] & 0xFFFFFF00) | (value & 0xFF);
					break;
				case register_access::high_byte:
					regs[static_cast<uint8_t>(reg.id)] = (regs[static_cast<uint8_t>(reg.id)] & 0xFFFF00FF) | ((value & 0xFF) <<
						8);
					break;
				default:
					throw std::runtime_error("Invalid access type");
			}
		}
		void set_flag(flag f, bool value) {
			if (value) {
				flags.value |= (1 << static_cast<uint8_t>(f));
			}
			else {
				flags.value &= ~(1 << static_cast<uint8_t>(f));
			}
		}
		[[nodiscard]] bool get_flag(flag f) const {
			return (flags.value >> static_cast<uint8_t>(f)) & 1;
		}
	};
}

template<>
struct std::formatter<machine::register_t> : std::formatter<std::string> {
	bool uppercase{false};

	constexpr auto parse(std::format_parse_context& ctx) {
		auto pos = ctx.begin();
		for (; pos != ctx.end() && *pos != '}'; ++pos) {
			auto c = *pos;
			if (c == 'u' || c == 'U') {
				uppercase = true;
			}
			if (c == 'l' || c == 'L') {
				uppercase = false;
			}
		}
		return pos;
	}
	auto format(const machine::register_t& reg, auto& ctx) const {
		auto id = reg.id;
		auto access = reg.access;
		switch (id) {
			case machine::register_id::eax:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EAX" : "eax", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "AX" : "ax", ctx);
					case machine::register_access::low_byte:
						return std::formatter<std::string>::format(uppercase ? "AL" : "al", ctx);
					case machine::register_access::high_byte:
						return std::formatter<std::string>::format(uppercase ? "AH" : "ah", ctx);
				}
				break;
			case machine::register_id::ebx:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EBX" : "ebx", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "BX" : "bx", ctx);
					case machine::register_access::low_byte:
						return std::formatter<std::string>::format(uppercase ? "BL" : "bl", ctx);
					case machine::register_access::high_byte:
						return std::formatter<std::string>::format(uppercase ? "BH" : "bh", ctx);
				}
				break;
			case machine::register_id::ecx:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "ECX" : "ecx", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "CX" : "cx", ctx);
					case machine::register_access::low_byte:
						return std::formatter<std::string>::format(uppercase ? "CL" : "cl", ctx);
					case machine::register_access::high_byte:
						return std::formatter<std::string>::format(uppercase ? "CH" : "ch", ctx);
				}
				break;
			case machine::register_id::edx:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EDX" : "edx", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "DX" : "dx", ctx);
					case machine::register_access::low_byte:
						return std::formatter<std::string>::format(uppercase ? "DL" : "dl", ctx);
					case machine::register_access::high_byte:
						return std::formatter<std::string>::format(uppercase ? "DH" : "dh", ctx);
				}
				break;
			case machine::register_id::esi:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "ESI" : "esi", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "SI" : "si", ctx);
					default:
						throw std::runtime_error("Invalid access type for this register");
				}
			case machine::register_id::edi:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EDI" : "edi", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "DI" : "di", ctx);
					default:
						throw std::runtime_error("Invalid access type for this register");
				}
			case machine::register_id::esp:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "ESP" : "esp", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "SP" : "sp", ctx);
					default:
						throw std::runtime_error("Invalid access type for this register");
				}
			case machine::register_id::ebp:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EBP" : "ebp", ctx);
					case machine::register_access::word:
						return std::formatter<std::string>::format(uppercase ? "BP" : "bp", ctx);
					default:
						throw std::runtime_error("Invalid access type for this register");
				}
			case machine::register_id::eip:
				switch (access) {
					case machine::register_access::dword:
						return std::formatter<std::string>::format(uppercase ? "EIP" : "eip", ctx);
					default:
						throw std::runtime_error("Invalid access type for this register");
				}
			case machine::register_id::flags:
				return std::formatter<std::string>::format(uppercase ? "FLAGS" : "flags", ctx);
			default:
				return std::formatter<std::string>::format("<invalid register>", ctx);
		}
		return std::formatter<std::string>::format("<invalid format>", ctx);
	}
};
template<>
struct std::formatter<machine::register_id> : std::formatter<std::string> {
	machine::register_access access{machine::register_access::dword};
	bool uppercase{false};
	constexpr auto parse(std::format_parse_context& ctx) {
		auto pos = ctx.begin();
		for (; pos != ctx.end() && *pos != '}'; ++pos) {
			const auto c = *pos;
			if (c == 'l' || c == 'L') {
				access = machine::register_access::low_byte;
				uppercase = (c == 'L');
			}
			else if (c == 'h' || c == 'H') {
				access = machine::register_access::high_byte;
				uppercase = (c == 'H');
			}
			else if (c == 'w' || c == 'W') {
				access = machine::register_access::word;
				uppercase = (c == 'W');
			}
			else if (c == 'd' || c == 'D') {
				access = machine::register_access::dword;
				uppercase = (c == 'D');
			}
		}
		return pos;
	}
	auto format(const machine::register_id& id, auto& ctx) const {
		return std::formatter<machine::register_t>{.uppercase = uppercase}
			.format(machine::register_t(id, access), ctx);
	}
};
template<>
struct std::formatter<machine::flag> : std::formatter<std::string> {
	enum class style {
		single_letter,
		two_letter,
		full_name
	} fmt_style{style::two_letter};
	bool uppercase{true};
	constexpr auto parse(std::format_parse_context& ctx) {
		auto pos = ctx.begin();
		for (; pos != ctx.end() && *pos != '}'; ++pos) {
			auto c = *pos;
			if (c == 's' || c == 'S') {
				fmt_style = style::single_letter;
				uppercase = (c == 'S');
			}
			else if (c == 't' || c == 'T') {
				fmt_style = style::two_letter;
				uppercase = (c == 'T');
			}
			else if (c == 'f' || c == 'F' || c == 'l' || c == 'L') {
				fmt_style = style::full_name;
				uppercase = (c == 'F') || (c == 'L');
			}
		}
		return pos;
	}
	auto format(const machine::flag& f, std::format_context& ctx) const {
		switch (f) {
			case machine::flag::carry:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "C" : "c", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "CF" : "cf", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Carry" : "carry", ctx);
				}
				break;
			case machine::flag::parity:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "P" : "p", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "PF" : "pf", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Parity" : "parity", ctx);
				}
				break;
			case machine::flag::auxiliary:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "A" : "a", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "AF" : "af", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Auxiliary" : "auxiliary", ctx);
				}
				break;
			case machine::flag::zero:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "Z" : "z", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "ZF" : "zf", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Zero" : "zero", ctx);
				}
				break;
			case machine::flag::sign:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "S" : "s", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "SF" : "sf", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Sign" : "sign", ctx);
				}
				break;
			case machine::flag::overflow:
				switch (fmt_style) {
					case style::single_letter:
						return std::formatter<std::string>::format(uppercase ? "O" : "o", ctx);
					case style::two_letter:
						return std::formatter<std::string>::format(uppercase ? "OF" : "of", ctx);
					case style::full_name:
						return std::formatter<std::string>::format(uppercase ? "Overflow" : "overflow", ctx);
				}
				break;
			default:
				return std::formatter<std::string>::format("<invalid flag>", ctx);
		}
		return std::formatter<std::string>::format("<invalid format>", ctx);
	}
};


#include "register.inl"
