#pragma once

#include <ua.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Decode instruction at address
// Returns instruction size (>0) on success, 0 on failure
int idalib_decode_insn(ea_t ea) {
  insn_t insn;
  return decode_insn(&insn, ea);
}

// Get instruction at address as a structure
rust::String idalib_get_insn_info(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Instruction at 0x%" PRIx64 ":\n", uint64(ea));
  buf.cat_sprnt("  Size: %d bytes\n", insn.size);
  buf.cat_sprnt("  Itype: %d\n", insn.itype);

  // Get mnemonic
  qstring mnem;
  print_insn_mnem(&mnem, ea);
  buf.cat_sprnt("  Mnemonic: %s\n", mnem.c_str());

  // Get full disassembly
  qstring disasm;
  generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
  buf.cat_sprnt("  Disassembly: %s\n", disasm.c_str());

  // Operand count
  int op_count = 0;
  for (int i = 0; i < UA_MAXOP; i++) {
    if (insn.ops[i].type == o_void) break;
    op_count++;
  }
  buf.cat_sprnt("  Operands: %d\n", op_count);

  return rust::String(buf.c_str());
}

// Print instruction mnemonic
rust::String idalib_print_insn_mnem(ea_t ea) {
  qstring mnem;
  print_insn_mnem(&mnem, ea);
  return rust::String(mnem.c_str());
}

// Print full instruction line (mnemonic + operands)
rust::String idalib_generate_disasm_line(ea_t ea) {
  qstring disasm;
  generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
  return rust::String(disasm.c_str());
}

// Get canonical mnemonic (architecture-independent)
rust::String idalib_get_canon_mnem(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return rust::String();
  }

  // Get the mnemonic using processor-specific name
  const char *mnem = insn.get_canon_mnem(PH);
  if (mnem == nullptr) {
    return rust::String();
  }
  return rust::String(mnem);
}

// Get instruction size
asize_t idalib_get_item_size(ea_t ea) {
  return get_item_size(ea);
}

// Get operand type
int idalib_get_operand_type(ea_t ea, int opnum) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return -1;
  }

  if (opnum < 0 || opnum >= UA_MAXOP) {
    return -1;
  }

  return insn.ops[opnum].type;
}

// Get operand value (for immediates, memory refs, etc)
uint64 idalib_get_operand_value(ea_t ea, int opnum) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return BADADDR;
  }

  if (opnum < 0 || opnum >= UA_MAXOP) {
    return BADADDR;
  }

  return insn.ops[opnum].value;
}

// Print operand as string
rust::String idalib_print_operand(ea_t ea, int opnum) {
  qstring buf;
  print_operand(&buf, ea, opnum);
  return rust::String(buf.c_str());
}

// Check if instruction is a call
bool idalib_is_call_insn(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return false;
  }
  return is_call_insn(insn);
}

// Check if instruction is a return
bool idalib_is_ret_insn(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return false;
  }
  return is_ret_insn(insn);
}

// Check if instruction is an indirect jump
bool idalib_is_indirect_jump_insn(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return false;
  }
  return is_indirect_jump_insn(insn);
}

// Check if instruction is a basic block end
bool idalib_is_basic_block_end(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return false;
  }
  return is_basic_block_end(insn, false);
}

// Get instruction feature flags
uint32 idalib_get_insn_feature(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return 0;
  }
  return insn.get_canon_feature(PH);
}

// Get operand detailed information as JSON-like string
rust::String idalib_get_operand_info(ea_t ea, int opnum) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return rust::String();
  }

  if (opnum < 0 || opnum >= UA_MAXOP) {
    return rust::String();
  }

  const op_t &op = insn.ops[opnum];
  if (op.type == o_void) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Operand %d at 0x%" PRIx64 ":\n", opnum, uint64(ea));
  buf.cat_sprnt("  Type: %d\n", op.type);
  buf.cat_sprnt("  Flags: 0x%x\n", op.flags);
  buf.cat_sprnt("  Dtype: %d\n", op.dtype);

  // Print operand string
  qstring op_str;
  print_operand(&op_str, ea, opnum);
  buf.cat_sprnt("  String: %s\n", op_str.c_str());

  // Type-specific info
  switch (op.type) {
    case o_reg:
      buf.cat_sprnt("  Register: %d\n", op.reg);
      break;
    case o_mem:
    case o_near:
    case o_far:
      buf.cat_sprnt("  Address: 0x%" PRIx64 "\n", uint64(op.addr));
      break;
    case o_imm:
      buf.cat_sprnt("  Immediate: 0x%" PRIx64 "\n", uint64(op.value));
      break;
    case o_displ:
    case o_phrase:
      buf.cat_sprnt("  Phrase: %d\n", op.phrase);
      buf.cat_sprnt("  Displacement: 0x%" PRIx64 "\n", uint64(op.addr));
      break;
  }

  return rust::String(buf.c_str());
}

// Get next instruction address (handles variable-length instructions)
ea_t idalib_get_next_insn_ea(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return BADADDR;
  }
  return ea + insn.size;
}

// Get previous instruction address
ea_t idalib_get_prev_insn_ea(ea_t ea) {
  return prev_head(ea, 0);
}

// Check if address contains a valid instruction
bool idalib_is_insn(ea_t ea) {
  insn_t insn;
  return decode_insn(&insn, ea) > 0;
}

// Get instruction operand count
int idalib_get_operand_count(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return 0;
  }

  int count = 0;
  for (int i = 0; i < UA_MAXOP; i++) {
    if (insn.ops[i].type == o_void) break;
    count++;
  }
  return count;
}

// Get instruction type (itype)
int idalib_get_insn_itype(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return -1;
  }
  return insn.itype;
}

// Enumerate all instructions in a range with details
rust::String idalib_enumerate_instructions(ea_t start_ea, ea_t end_ea, size_t limit) {
  qstring buf;
  size_t count = 0;

  buf.sprnt("Instructions from 0x%" PRIx64 " to 0x%" PRIx64 ":\n",
            uint64(start_ea), uint64(end_ea));

  for (ea_t ea = start_ea; ea < end_ea && count < limit; ) {
    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
      ea = next_head(ea, end_ea);
      if (ea == BADADDR) break;
      continue;
    }

    // Get mnemonic
    qstring mnem;
    print_insn_mnem(&mnem, ea);

    // Get disassembly
    qstring disasm;
    generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);

    buf.cat_sprnt("  [%zu] 0x%" PRIx64 ": %s (size=%d, itype=%d)\n",
                  count, uint64(ea), disasm.c_str(), insn.size, insn.itype);

    ea += insn.size;
    count++;
  }

  buf.cat_sprnt("\nTotal: %zu instructions\n", count);
  return rust::String(buf.c_str());
}
