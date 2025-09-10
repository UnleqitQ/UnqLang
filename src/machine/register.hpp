#pragma once
#ifndef MACHINE_REGISTER
#define MACHINE_REGISTER
#endif

#include <array>
#include <cstdint>
#include <stdexcept>

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
		register_id id : 4;
		register_access access : 2;
		constexpr explicit register_t(register_id id, register_access access = register_access::dword)
			: id(id), access(access) {
			if (static_cast<uint8_t>(id) > 5 && static_cast<uint8_t>(access) > 1) {
				throw std::runtime_error("Invalid access type for this register");
			}
			if (id == register_id::flags && access != register_access::dword) {
				throw std::runtime_error("Flags register must be accessed as dword");
			}
		}
		[[nodiscard]] std::string to_string() const;
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

#include "register.inl"
