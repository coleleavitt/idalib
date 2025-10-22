#pragma once

#include <frame.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Add a function frame
bool idalib_add_frame(ea_t func_ea, sval_t frsize, ushort frregs, asize_t argsize) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return add_frame(pfn, frsize, frregs, argsize);
}

// Delete a function frame
bool idalib_del_frame(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return del_frame(pfn);
}

// Set size of function frame
bool idalib_set_frame_size(ea_t func_ea, asize_t frsize, ushort frregs, asize_t argsize) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return set_frame_size(pfn, frsize, frregs, argsize);
}

// Get full size of a function frame
asize_t idalib_get_frame_size(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_frame_size(pfn);
}

// Get size of function return address
int idalib_get_frame_retsize(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_frame_retsize(pfn);
}

// Get frame part information as string
rust::String idalib_get_frame_part(ea_t func_ea, int part) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  range_t range;
  get_frame_part(&range, pfn, (frame_part_t)part);

  qstring buf;
  const char *part_name;
  switch (part) {
    case FPC_ARGS:    part_name = "ARGS"; break;
    case FPC_RETADDR: part_name = "RETADDR"; break;
    case FPC_SAVREGS: part_name = "SAVREGS"; break;
    case FPC_LVARS:   part_name = "LVARS"; break;
    default:          part_name = "UNKNOWN"; break;
  }

  buf.sprnt("%s: 0x%" PRIx64 "-0x%" PRIx64,
            part_name,
            uint64(range.start_ea),
            uint64(range.end_ea));
  return rust::String(buf.c_str());
}

// Get function frame type information
rust::String idalib_get_func_frame(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  tinfo_t tif;
  if (!get_func_frame(&tif, pfn)) {
    return rust::String();
  }

  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Build stack variable name
rust::String idalib_build_stkvar_name(ea_t func_ea, sval_t offset) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  qstring buf;
  ssize_t result = build_stkvar_name(&buf, pfn, offset);

  if (result < 0) {
    return rust::String();
  }

  return rust::String(buf.c_str());
}

// Calculate stack variable structure offset
ea_t idalib_calc_stkvar_struc_offset(ea_t func_ea, ea_t insn_ea, int opnum) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return BADADDR;
  }

  insn_t insn;
  if (decode_insn(&insn, insn_ea) <= 0) {
    return BADADDR;
  }

  return calc_stkvar_struc_offset(pfn, insn, opnum);
}

// Calculate frame offset
sval_t idalib_calc_frame_offset(ea_t func_ea, sval_t off) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return BADADDR;
  }
  return calc_frame_offset(pfn, off, nullptr, nullptr);
}

// Get stack pointer delta at address
sval_t idalib_get_spd(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_spd(pfn, ea);
}

// Get effective stack pointer delta
sval_t idalib_get_effective_spd(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_effective_spd(pfn, ea);
}

// Get stack pointer delta (difference from function entry)
sval_t idalib_get_sp_delta(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_sp_delta(pfn, ea);
}

// Add automatic stack point
bool idalib_add_auto_stkpnt(ea_t func_ea, ea_t ea, sval_t delta) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return add_auto_stkpnt(pfn, ea, delta);
}

// Add user-defined stack point
bool idalib_add_user_stkpnt(ea_t ea, sval_t delta) {
  return add_user_stkpnt(ea, delta);
}

// Delete stack point
bool idalib_del_stkpnt(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return del_stkpnt(pfn, ea);
}

// Get comprehensive frame information as string
rust::String idalib_get_frame_info(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Function at 0x%" PRIx64 " Frame Info:\n", uint64(func_ea));

  asize_t frame_size = get_frame_size(pfn);
  buf.cat_sprnt("  Total frame size: 0x%" PRIx64 "\n", uint64(frame_size));

  int retsize = get_frame_retsize(pfn);
  buf.cat_sprnt("  Return address size: %d\n", retsize);

  // Get frame parts
  range_t range;

  get_frame_part(&range, pfn, FPC_LVARS);
  buf.cat_sprnt("  Local vars: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                uint64(range.start_ea), uint64(range.end_ea),
                uint64(range.end_ea - range.start_ea));

  get_frame_part(&range, pfn, FPC_SAVREGS);
  buf.cat_sprnt("  Saved regs: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                uint64(range.start_ea), uint64(range.end_ea),
                uint64(range.end_ea - range.start_ea));

  get_frame_part(&range, pfn, FPC_RETADDR);
  buf.cat_sprnt("  Return addr: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                uint64(range.start_ea), uint64(range.end_ea),
                uint64(range.end_ea - range.start_ea));

  get_frame_part(&range, pfn, FPC_ARGS);
  buf.cat_sprnt("  Arguments: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                uint64(range.start_ea), uint64(range.end_ea),
                uint64(range.end_ea - range.start_ea));

  return rust::String(buf.c_str());
}

// Delete wrong frame info - simplified version (always reanalyzes)
int idalib_delete_wrong_frame_info(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  // Use nullptr callback - will always return true to reanalyze
  return delete_wrong_frame_info(pfn, nullptr);
}

// Recalculate stack pointer delta
bool idalib_recalc_spd(ea_t ea) {
  return recalc_spd(ea);
}
