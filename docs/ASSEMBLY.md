# Assembly

This document describes the assembly language used in this project.\
The assembly language is inspired by NASM syntax.

## Syntax

The assembly language uses the following syntax:

```bnf
<program> ::= <line>*
<line> ::= <line_content> <comment>? '\n'
<line_content> ::= <label> | <instruction> | <meta_instruction> | ε
<comment> ::= ';' <any_characters>
<label> ::= <identifier> ':'
<instruction> ::= <opcode> <operand_list> | 'lea' <operand> ',' <memory>
<opcode> ::= ... (list of opcodes)
<operand_list> ::= <operand> (',' <operand>)* | ε
<meta_instruction> ::= <meta_opcode> <meta_operand_list>
<operand> ::= <register> | <immediate> | <memory_ptr>
<memory_ptr> ::= <size_specifier> 'ptr' <memory>
<size_specifier> ::= 'byte' | 'word' | 'dword' (| 'qword')
<memory> ::= '[' <memory_expression> ']'
<memory_expression> ::= 
    <immediate> | <register> | 
    <register> <sign> <immediate> |
    <register> <sign> <register> '*' <immediate> |
    <register> <sign> <register> '*' <immediate> <sign> <immediate>
<sign> ::= '+' | '-'
<immediate> ::= <number> | <identifier> | <char_literal>
<register> ::= ... (list of registers)
<identifier> ::= <letter> (<letter> | <digit> | '_')*
<number> ::= <sign>? (<decimal> | <hexadecimal>)
<decimal> ::= <digit>+
<hexadecimal> ::= '0x' <hex_digit>+
<letter> ::= 'a'..'z' | 'A'..'Z'
<digit> ::= '0'..'9'
<hex_digit> ::= '0'..'9' | 'a'..'f | 'A'..'F'
<char_literal> ::= '\'' <any_character> '\''
<meta_opcode> ::= 'db' | 'dw' | 'dd'
<meta_operand_list> ::= <meta_operand> (',' <meta_operand>)* | ε
<meta_operand> ::= <number> | <char_literal> | <string_literal>
<string_literal> ::= '"' <any_character>* '"'
```

## Instructions

The assembly language supports a variety of instructions.
The opcode defines the operands it takes.\
For example, the `mov` instruction can take two operands, the destination and the source.
The destination can be a register or a memory location, while the source can be a register, memory location, or
immediate value.\
The following instructions define their operands as follows:

- `operand`: a register, immediate value, or memory pointer
- `result`: a register or memory pointer
- `memory`: a memory address (not the pointer)

The following is a list of supported instructions and their operand types:

| Instruction (maybe Alias) | Operands             | Description                             |
|---------------------------|----------------------|-----------------------------------------|
| `nop`                     | ε                    | No operation                            |
| `mov`                     | `result`, `operand`  | Move data from source to destination    |
| `movsx`                   | `result`, `operand`  | Move with sign extension                |
| `movzx`                   | `result`, `operand`  | Move with zero extension                |
| `lea`                     | `result`, `memory`   | Load effective address                  |
| `push`                    | `operand`            | Push value onto stack                   |
| `pop`                     | `result`             | Pop value from stack                    |
| `add`                     | `result`, `operand`  | Add source to destination               |
| `sub`                     | `result`, `operand`  | Subtract source from destination        |
| `mul`                     | `result`, `operand`  | Multiply destination by source          |
| `imul`                    | `result`, `operand`  | Signed multiply destination by source   |
| `div`                     | `result`, `operand`  | Divide destination by source            |
| `idiv`                    | `result`, `operand`  | Signed divide destination by source     |
| `mod`                     | `result`, `operand`  | Modulus of destination by source        |
| `imod`                    | `result`, `operand`  | Signed modulus of destination by source |
| `neg`                     | `result`             | Negate the value in destination         |
| `inc`                     | `result`             | Increment the value in destination      |
| `dec`                     | `result`             | Decrement the value in destination      |
| `adc`                     | `result`, `operand`  | Add with carry                          |
| `sbb`                     | `result`, `operand`  | Subtract with borrow                    |
| `and`                     | `result`, `operand`  | Bitwise AND                             |
| `or`                      | `result`, `operand`  | Bitwise OR                              |
| `xor`                     | `result`, `operand`  | Bitwise XOR                             |
| `not`                     | `result`             | Bitwise NOT                             |
| `shl`                     | `result`, `operand`  | Shift left                              |
| `shr`                     | `result`, `operand`  | Shift right                             |
| `sar`                     | `result`, `operand`  | Arithmetic shift right                  |
| `rol`                     | `result`, `operand`  | Rotate left                             |
| `ror`                     | `result`, `operand`  | Rotate right                            |
| `rcl`                     | `result`, `operand`  | Rotate through carry left               |
| `rcr`                     | `result`, `operand`  | Rotate through carry right              |
| `cmp`                     | `operand`, `operand` | Compare two values                      |
| `test`                    | `operand`, `operand` | Bitwise AND without storing result      |
| `jmp`                     | `operand`            | Unconditional jump                      |
| `jz` ( `je`)              | `operand`            | Jump if zero (equal)                    |
| `jnz` (`jne`)             | `operand`            | Jump if not zero (not equal)            |
| `js`                      | `operand`            | Jump if sign (negative)                 |
| `jns`                     | `operand`            | Jump if not sign (not negative)         |
| `jc`                      | `operand`            | Jump if carry                           |
| `jnc`                     | `operand`            | Jump if not carry                       |
| `jo`                      | `operand`            | Jump if overflow                        |
| `jno`                     | `operand`            | Jump if not overflow                    |
| `jp`                      | `operand`            | Jump if parity                          |
| `jnp`                     | `operand`            | Jump if not parity                      |
| `jl`                      | `operand`            | Jump if less (signed)                   |
| `jle`                     | `operand`            | Jump if less or equal (signed)          |
| `jg`                      | `operand`            | Jump if greater (signed)                |
| `jge`                     | `operand`            | Jump if greater or equal (signed)       |
| `ja`                      | `operand`            | Jump if above (unsigned)                |
| `jae`                     | `operand`            | Jump if above or equal (unsigned)       |
| `jb`                      | `operand`            | Jump if below (unsigned)                |
| `jbe`                     | `operand`            | Jump if below or equal (unsigned)       |
| `call`                    | `operand`            | Call a procedure                        |
| `ret`                     | ε                    | Return from procedure                   |
| `pusha`                   | ε                    | Push all general-purpose registers      |
| `popa`                    | ε                    | Pop all general-purpose registers       |
| `pushf`                   | ε                    | Push flags register onto stack          |
| `popf`                    | ε                    | Pop flags register from stack           |
| `clc`                     | ε                    | Clear carry flag                        |
| `stc`                     | ε                    | Set carry flag                          |
| `hlt` (`end`)             | ε                    | Halt the program                        |
| `setz`                    | `result`             | Set if zero                             |
| `setnz`                   | `result`             | Set if not zero                         |
| `sets`                    | `result`             | Set if sign (negative)                  |
| `setns`                   | `result`             | Set if not sign (not negative)          |
| `setc`                    | `result`             | Set if carry                            |
| `setnc`                   | `result`             | Set if not carry                        |
| `seto`                    | `result`             | Set if overflow                         |
| `setno`                   | `result`             | Set if not overflow                     |
| `setl`                    | `result`             | Set if less (signed)                    |
| `setle`                   | `result`             | Set if less or equal (signed)           |
| `setg`                    | `result`             | Set if greater (signed)                 |
| `setge`                   | `result`             | Set if greater or equal (signed)        |
| `seta`                    | `result`             | Set if above (unsigned)                 |
| `setae`                   | `result`             | Set if above or equal (unsigned)        |
| `setb`                    | `result`             | Set if below (unsigned)                 |
| `setbe`                   | `result`             | Set if below or equal (unsigned)        |
| `in`                      | `result`, `operand`  | Input from port (second argument)       |
| `out`                     | `operand`, `operand` | Output to port (second argument)        |

## Meta Instructions

Meta instructions are used to define data in memory.\
They do not correspond to actual machine instructions but are directives for the assembler.
The following meta instructions are supported:

- `db`: Define byte(s)
- `dw`: Define word(s) (2 bytes)
- `dd`: Define double word(s) (4 bytes)

## Comments

Comments start with a semicolon (`;`) and continue to the end of the line.\
They are ignored by the assembler.

## Registers

The assembly language supports the following registers:

- General Purpose Registers:
    - Accumulator: `eax`, `ax`, `ah`, `al`
    - Base: `ebx`, `bx`, `bh`, `bl`
    - Counter: `ecx`, `cx`, `ch`, `cl`
    - Data: `edx`, `dx`, `dh`, `dl`
    - Source Index: `esi`, `si`
    - Destination Index: `edi`, `di`
- Pointer Registers:
    - Stack Pointer: `esp`
    - Base Pointer: `ebp`
- Instruction Pointer: `eip`
- (Flags are also considered a register, but are not directly accessible)

## Labels

Labels are used to mark positions in the code for jumps and calls.\
A label is resolved at assembly time to the address of the instruction following it.\
Labels must be unique within a program.
They are defined by writing an identifier followed by a colon (`:`) at the beginning of a line.

A label is equivalent to a number and can be used wherever a number is expected.

## Memory Addressing
Memory can be accessed using various addressing modes.\
The memory operand is enclosed in square brackets (`[]`) and can include combinations of registers, immediate
values, and arithmetic operations.  
The following addressing modes are supported:
- Direct Addressing: `[immediate]`
- Register Indirect Addressing: `[register]`
- Base Plus Offset: `[register + immediate]`
- Indexed Addressing: `[register + register * immediate]`
- Base Plus Indexed Plus Offset: `[register + register * immediate + immediate]`

A negative sign (`-`) can be used instead of a plus sign (`+`) to subtract values in memory expressions.
This just negates the value of the immediate.

## Size Specifiers

When accessing memory, a size specifier has to be used to indicate the size of the data being accessed.\
The size specifier is placed before the `ptr` keyword in a memory operand.\
The following size specifiers are supported:
- `byte`: 1 byte
- `word`: 2 bytes
- `dword`: 4 bytes
- (`qword`: 8 bytes) (not implemented)
