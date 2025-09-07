#pragma once
#ifndef MACHINE_REGISTER
#error "Include machine/register.hpp instead of machine/register.inl"
#endif

namespace machine {
	inline std::string to_string(register_id id) {
		switch (id) {
			case register_id::eax: return "eax";
			case register_id::ebx: return "ebx";
			case register_id::ecx: return "ecx";
			case register_id::edx: return "edx";
			case register_id::esi: return "esi";
			case register_id::edi: return "edi";
			case register_id::esp: return "esp";
			case register_id::ebp: return "ebp";
			case register_id::flags: return "flags";
			default: throw std::runtime_error("Invalid register id");
		}
	}
	inline std::string register_t::to_string() const {
		switch (access) {
			case register_access::dword:
				switch (id) {
					case register_id::eax: return "eax";
					case register_id::ebx: return "ebx";
					case register_id::ecx: return "ecx";
					case register_id::edx: return "edx";
					case register_id::esi: return "esi";
					case register_id::edi: return "edi";
					case register_id::esp: return "esp";
					case register_id::ebp: return "ebp";
					case register_id::flags: return "flags";
					default: throw std::runtime_error("Invalid register id");
				}
			case register_access::word:
				switch (id) {
					case register_id::eax: return "ax";
					case register_id::ebx: return "bx";
					case register_id::ecx: return "cx";
					case register_id::edx: return "dx";
					case register_id::esi: return "si";
					case register_id::edi: return "di";
					default: throw std::runtime_error("Invalid access type for this register");
				}
			case register_access::low_byte:
				switch (id) {
					case register_id::eax: return "al";
					case register_id::ebx: return "bl";
					case register_id::ecx: return "cl";
					case register_id::edx: return "dl";
					default: throw std::runtime_error("Invalid access type for this register");
				}
			case register_access::high_byte:
				switch (id) {
					case register_id::eax: return "ah";
					case register_id::ebx: return "bh";
					case register_id::ecx: return "ch";
					case register_id::edx: return "dh";
					default: throw std::runtime_error("Invalid access type for this register");
				}
			default: throw std::runtime_error("Invalid access type");
		}
	}
	inline register_t register_t::from_string(const std::string& str) {
		if (str == "eax") return register_t(register_id::eax, register_access::dword);
		if (str == "ebx") return register_t(register_id::ebx, register_access::dword);
		if (str == "ecx") return register_t(register_id::ecx, register_access::dword);
		if (str == "edx") return register_t(register_id::edx, register_access::dword);
		if (str == "esi") return register_t(register_id::esi, register_access::dword);
		if (str == "edi") return register_t(register_id::edi, register_access::dword);
		if (str == "esp") return register_t(register_id::esp, register_access::dword);
		if (str == "ebp") return register_t(register_id::ebp, register_access::dword);
		if (str == "flags") return register_t(register_id::flags, register_access::dword);
		if (str == "ax") return register_t(register_id::eax, register_access::word);
		if (str == "bx") return register_t(register_id::ebx, register_access::word);
		if (str == "cx") return register_t(register_id::ecx, register_access::word);
		if (str == "dx") return register_t(register_id::edx, register_access::word);
		if (str == "si") return register_t(register_id::esi, register_access::word);
		if (str == "di") return register_t(register_id::edi, register_access::word);
		if (str == "al") return register_t(register_id::eax, register_access::low_byte);
		if (str == "bl") return register_t(register_id::ebx, register_access::low_byte);
		if (str == "cl") return register_t(register_id::ecx, register_access::low_byte);
		if (str == "dl") return register_t(register_id::edx, register_access::low_byte);
		if (str == "ah") return register_t(register_id::eax, register_access::high_byte);
		if (str == "bh") return register_t(register_id::ebx, register_access::high_byte);
		if (str == "ch") return register_t(register_id::ecx, register_access::high_byte);
		if (str == "dh") return register_t(register_id::edx, register_access::high_byte);
		throw std::runtime_error("Invalid register string: " + str);
	}
}
