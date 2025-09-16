#pragma once

#define UNSAFE

#include <unordered_map>

#include "assembler.hpp"
#include "instruction.hpp"
#include "peripheral.hpp"
#include "ram.hpp"
#include "register.hpp"

namespace machine {
	enum class execution_state_t : uint8_t {
		RUNNING,
		HALTED,
		ERROR
	};

	class computer {
		ram m_ram;
		register_file m_registers;
		execution_state_t m_state = execution_state_t::HALTED;
		bool m_verbose = false;
		std::string m_error_message;
		std::unordered_map<uint16_t, peripheral> m_peripherals;

	public:
		computer() {
			uint32_t initial_stack_pointer = ram::SIZE;
			m_registers.esp = initial_stack_pointer;
			m_registers.ebp = initial_stack_pointer;
		}
		computer(const ram& r, const register_file& reg)
			: m_ram(r), m_registers(reg) {
		}

		void register_peripheral(const peripheral& peripheral) {
			m_peripherals[peripheral.port] = peripheral;
		}
		void load_program(const simple_program_t& program, uint32_t start_address = 0);
		void load_program(const program_t& program, uint32_t start_address = 0);
		void step(); // Execute a single instruction
		void run(int max_steps = -1); // Run until the end of the program or max_steps reached

		void set_verbose(bool v);
		bool is_verbose() const {
			return m_verbose;
		}
		const std::string& get_error_message() const {
			return m_error_message;
		}

		ram& get_ram() {
			return m_ram;
		}
		const ram& get_ram() const {
			return m_ram;
		}
		register_file& get_registers() {
			return m_registers;
		}
		const register_file& get_registers() const {
			return m_registers;
		}
		uint32_t get_instruction_pointer() const {
			return m_registers.eip;
		}
		void set_instruction_pointer(uint32_t ip) {
			m_registers.eip = ip;
		}
		execution_state_t get_state() const {
			return m_state;
		}
		void set_state(execution_state_t state) {
			m_state = state;
		}

		bool is_halted() const {
			return m_state == execution_state_t::HALTED;
		}
		bool is_running() const {
			return m_state == execution_state_t::RUNNING;
		}
		bool is_error() const {
			return m_state == execution_state_t::ERROR;
		}

		instruction_t fetch_current_instruction(uint32_t& out_next_eip) const {
			instruction_t instr;
			size_t pc = m_registers.eip;
#ifdef UNSAFE
			assembler::disassemble_unsafe(m_ram.data, instr, pc);
#else
			assembler::disassemble(m_ram.data, instr, pc);
#endif
			out_next_eip = static_cast<uint32_t>(pc);
			return instr;
		}

	private:
		uint32_t retrieve_memory_address(const memory_operand& mem_op) const;
		uint32_t retrieve_operand_value(const operand_arg& op) const;
		uint32_t retrieve_result_value(const result_arg& res) const;
		void set_result_value(const result_arg& res, uint32_t value);
		bool execute_instruction(const instruction_t& instr, uint32_t next_ip);
	};
} // machine
