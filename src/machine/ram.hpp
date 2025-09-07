#pragma once
#ifndef MACHINE_RAM
#define MACHINE_RAM
#endif

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace machine {
	enum class data_size_t : uint8_t {
		BYTE = 0,
		WORD = 1,
		DWORD = 2
	};
	inline data_size_t data_size_from_string(const std::string& str);
	inline std::ostream& operator<<(std::ostream& os, const data_size_t& ds);
	struct ram {
		static constexpr size_t SIZE = 1024 * 64; // 64KB
		std::vector<uint8_t> data = std::vector<uint8_t>(SIZE, 0);
		[[nodiscard]] uint8_t read8(uint32_t address) const {
			if (address >= data.size()) {
				throw std::out_of_range("RAM read8 out of range");
			}
			return data[address];
		}
		void write8(uint32_t address, uint8_t value) {
			if (address >= data.size()) {
				throw std::out_of_range("RAM write8 out of range");
			}
			data[address] = value;
		}
		[[nodiscard]] uint16_t read16(uint32_t address) const {
			if (address + 1 >= data.size()) {
				throw std::out_of_range("RAM read16 out of range");
			}
			return static_cast<uint16_t>(data[address]) |
			       (static_cast<uint16_t>(data[address + 1]) << 8);
		}
		void write16(uint32_t address, uint16_t value) {
			if (address + 1 >= data.size()) {
				throw std::out_of_range("RAM write16 out of range");
			}
			data[address] = static_cast<uint8_t>(value & 0xFF);
			data[address + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
		}
		[[nodiscard]] uint32_t read32(uint32_t address) const {
			if (address + 3 >= data.size()) {
				throw std::out_of_range("RAM read32 out of range");
			}
			return static_cast<uint32_t>(data[address]) |
			       (static_cast<uint32_t>(data[address + 1]) << 8) |
			       (static_cast<uint32_t>(data[address + 2]) << 16) |
			       (static_cast<uint32_t>(data[address + 3]) << 24);
		}
		void write32(uint32_t address, uint32_t value) {
			if (address + 3 >= data.size()) {
				throw std::out_of_range("RAM write32 out of range");
			}
			data[address] = static_cast<uint8_t>(value & 0xFF);
			data[address + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
			data[address + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
			data[address + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
		}

		void clear() {
			std::fill(data.begin(), data.end(), 0);
		}
	};
}

#include "ram.inl"
