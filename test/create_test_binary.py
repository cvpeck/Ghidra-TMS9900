#!/usr/bin/env python3
# ~/Documents/Coding/ghidra-extensions/Ghidra-TMS9900/test/create_test_binary.py

import struct
import os

def w(val):
    return struct.pack('>H', val & 0xFFFF)

def two_op(op3, mode_b, reg_td, reg_dst, reg_ts, reg_src):
    return (op3 << 13) | (mode_b << 12) | (reg_td << 10) | (reg_dst << 6) | (reg_ts << 4) | reg_src

def single_op(op10, reg_ts, reg_src):
    return (op10 << 6) | (reg_ts << 4) | reg_src

def imm_op(iri_op, iri_reg):
    return (iri_op << 5) | iri_reg

def jump(jmp_op, displacement):
    return (jmp_op << 8) | (displacement & 0xFF)

def shift(shift_op_val, count, reg):
    return (shift_op_val << 8) | (count << 4) | reg

def op11(op11_val, reg=0):
    return (op11_val << 5) | reg

def op6_op(op6_val, reg_dst, reg_ts, reg_src):
    return (op6_val << 10) | (reg_dst << 6) | (reg_ts << 4) | reg_src

def crum(crum_op_val, crum_c_val, reg_ts, reg_src):
    return (crum_op_val << 10) | (crum_c_val << 6) | (reg_ts << 4) | reg_src

# Memory map:
# 0x0000 - 0x003F : interrupt vector table (WP, PC pairs)
# 0x0040 - 0x004F : workspace registers area (8 registers x 2 bytes = 16 bytes... actually 16 regs = 32 bytes)
# 0x0060 - 0x00FF : unused
# 0x0100          : code starts here
#
# Vector table format: pairs of (WP, PC)
# Reset vector: WP=0x0040, PC=0x0100

WP_ADDR   = 0x0040   # workspace registers live here
CODE_ADDR = 0x0100   # code starts here

binary = bytearray(0x0200)  # 512 bytes total

def patch_w(buf, addr, val):
    buf[addr]   = (val >> 8) & 0xFF
    buf[addr+1] = val & 0xFF

# === Vector table at 0x0000 ===
# Reset:  WP=0x0040, PC=0x0100
patch_w(binary, 0x0000, WP_ADDR)    # Reset WP
patch_w(binary, 0x0002, CODE_ADDR)  # Reset PC

# NMI / other vectors - point to safe location (RTWP at 0x00FE)
for vec in range(0x0004, 0x0040, 4):
    patch_w(binary, vec,   WP_ADDR)    # WP
    patch_w(binary, vec+2, 0x00FE)     # PC -> RTWP

# === Safe RTWP at 0x00FE ===
patch_w(binary, 0x00FE, 0x0380)      # RTWP

# === Workspace registers at 0x0040 (R0-R15) ===
# Pre-initialize with known values for testing
for i in range(16):
    patch_w(binary, WP_ADDR + i*2, i * 0x10)
# R0 = 0x0000 ... R15 = 0x00F0

# === Code at 0x0100 ===
log = []

def emit(val_bytes, desc):
    addr = CODE_ADDR + len(code)
    code.extend(val_bytes)
    log.append((addr, desc))

code = bytearray()

# --- Load Immediate ---
emit(w(imm_op(0x10, 0)) + w(0x1234),   "LI   R0, >1234")
emit(w(imm_op(0x10, 1)) + w(0x0002),   "LI   R1, >0002")
emit(w(imm_op(0x10, 2)) + w(0x00FF),   "LI   R2, >00FF")
emit(w(imm_op(0x10, 3)) + w(0xFFFF),   "LI   R3, >FFFF")

# --- Move ---
emit(w(two_op(6, 0, 0, 1, 0, 0)),      "MOV  R0, R1")
emit(w(two_op(6, 0, 0, 2, 0, 1)),      "MOV  R1, R2")
emit(w(two_op(6, 1, 0, 3, 0, 2)),      "MOVB R2, R3")

# --- Arithmetic ---
emit(w(two_op(5, 0, 0, 1, 0, 0)),      "A    R0, R1")
emit(w(imm_op(0x11, 0)) + w(0x0100),   "AI   R0, >0100")
emit(w(single_op(0x16, 0, 1)),          "INC  R1")
emit(w(single_op(0x17, 0, 2)),          "INCT R2")
emit(w(single_op(0x18, 0, 1)),          "DEC  R1")
emit(w(single_op(0x19, 0, 2)),          "DECT R2")
emit(w(single_op(0x14, 0, 0)),          "NEG  R0")
emit(w(single_op(0x1d, 0, 0)),          "ABS  R0")

# --- Logical ---
emit(w(imm_op(0x12, 0)) + w(0x0F0F),       "ANDI R0, >0F0F")
emit(w(imm_op(0x13, 1)) + w(0xF000),       "ORI  R1, >F000")
emit(w(op6_op(0xa, 1, 0, 2)),              "XOR  R2, R1")     # fix: op6=0xa
emit(w(two_op(5, 1, 0, 1, 0, 2)),          "AB   R2, R1")     # fix: was mislabeled XOR
emit(w(single_op(0x15, 0, 0)),              "INV  R0")
emit(w(single_op(0x13, 0, 3)),              "CLR  R3")

# --- Compare ---
emit(w(imm_op(0x14, 0)) + w(0x1334),       "CI   R0, >1334")
emit(w(two_op(4, 0, 0, 1, 0, 0)),          "C    R0, R1")
emit(w(two_op(4, 1, 0, 1, 0, 2)),          "CB   R2, R1")

# --- Shift ---
emit(w(shift(0x08, 1, 0)),                  "SRA  R0, 1")
emit(w(shift(0x09, 2, 1)),                  "SRL  R1, 2")
emit(w(shift(0x0A, 3, 2)),                  "SLA  R2, 3")
emit(w(shift(0x0B, 4, 3)),                  "SRC  R3, 4")

# --- Multiply / Divide ---
emit(w(op6_op(0xe, 2, 0, 1)),              "MPY  R1, R2")     # op6=0xe, dst=R2, src=R1
emit(w(op6_op(0xf, 2, 0, 1)),              "DIV  R1, R2")     # op6=0xf, dst=R2, src=R1

# --- CRU ---
emit(w(crum(0xc, 8, 0, 2)),               "LDCR R2, 8")      # crum_op=0xc, count=8
emit(w(crum(0xd, 8, 0, 2)),               "STCR R2, 8")      # crum_op=0xd, count=8

# --- Byte swap ---
emit(w(single_op(0x1b, 0, 0)),              "SWPB R0")

# --- Status / Workspace ---
emit(w(op11(0x16, 4)),                      "STST R4")
emit(w(op11(0x15, 5)),                      "STWP R5")

# --- Jumps ---
emit(w(jump(0x10, 0)),                      "JMP  $+2")
emit(w(jump(0x13, 0)),                      "JEQ  $+2")
emit(w(jump(0x16, 0)),                      "JNE  $+2")
emit(w(jump(0x15, 0)),                      "JGT  $+2")
emit(w(jump(0x11, 0)),                      "JLT  $+2")
emit(w(jump(0x14, 0)),                      "JHE  $+2")
emit(w(jump(0x12, 0)),                      "JLE  $+2")
emit(w(jump(0x1b, 0)),                      "JH   $+2")
emit(w(jump(0x1a, 0)),                      "JL   $+2")
emit(w(jump(0x17, 0)),                      "JNC  $+2")
emit(w(jump(0x18, 0)),                      "JOC  $+2")
emit(w(jump(0x1c, 0)),                      "JOP  $+2")

# --- Branch / Call ---
emit(w(single_op(0x10, 0, 0)),              "BLWP R0")        # op10=0x10
emit(w(single_op(0x1a, 0, 0)),              "BL   R0")
emit(w(single_op(0x12, 0, 1)),              "X    R1")        # op10=0x12
emit(w(0x0380),                             "RTWP")           # fix: before B so reachable
emit(w(single_op(0x11, 0, 0)),              "B    R0")        # unconditional, last instruction


# === Patch code into binary ===
binary[CODE_ADDR:CODE_ADDR+len(code)] = code

os.makedirs('test', exist_ok=True)
outfile = 'test/tms9900_test.bin'
with open(outfile, 'wb') as f:
    f.write(binary)

print(f"Written {len(binary)} bytes to {outfile}")
print()
print("Memory map:")
print(f"  0x0000  Interrupt vector table")
print(f"  0x0040  Workspace registers (R0-R15)")
print(f"  0x00FE  Safe RTWP")
print(f"  0x0100  Code start")
print()
print("Instruction map:")
print(f"  {'Addr':>6}  Instruction")
print(f"  {'----':>6}  -----------")
for addr, desc in log:
    print(f"  0x{addr:04X}  {desc}")
print()
print("Ghidra import settings:")
print("  Format:       Raw Binary")
print("  Language:     TMS9900:BE:16:default")
print("  Base address: 0x0000")
print("  Entry point:  auto (from reset vector at 0x0000)")