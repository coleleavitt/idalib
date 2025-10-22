#pragma once

#include <nalt.hpp>
#include <jumptable.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Get switch info at address
rust::String idalib_get_switch_info(ea_t ea) {
  switch_info_t si;
  if (get_switch_info(&si, ea) <= 0) {
    return rust::String();
  }

  // Format switch info as string
  qstring buf;
  buf.sprnt("Switch at 0x%" PRIx64 ":\n", uint64(ea));
  buf.cat_sprnt("  Jump table: 0x%" PRIx64 "\n", uint64(si.jumps));
  buf.cat_sprnt("  Number of cases: %d\n", si.get_jtable_size());
  buf.cat_sprnt("  Default: 0x%" PRIx64 "\n", uint64(si.defjump));
  buf.cat_sprnt("  Low case: %" PRId64 "\n", int64(si.lowcase));

  return rust::String(buf.c_str());
}

// Check if address has switch info
bool idalib_is_switch(ea_t ea) {
  switch_info_t si;
  return get_switch_info(&si, ea) > 0;
}

// Get jump table address
ea_t idalib_get_jump_table_addr(ea_t ea) {
  switch_info_t si;
  if (get_switch_info(&si, ea) <= 0) {
    return BADADDR;
  }
  return si.jumps;
}

// Get number of cases in switch
int idalib_get_switch_case_count(ea_t ea) {
  switch_info_t si;
  if (get_switch_info(&si, ea) <= 0) {
    return -1;
  }
  return si.get_jtable_size();
}

// Get default case address
ea_t idalib_get_switch_default(ea_t ea) {
  switch_info_t si;
  if (get_switch_info(&si, ea) <= 0) {
    return BADADDR;
  }
  return si.defjump;
}

// Get switch parent (the indirect jump instruction)
ea_t idalib_get_switch_parent(ea_t ea) {
  return get_switch_parent(ea);
}

// Delete switch info at address
void idalib_del_switch_info(ea_t ea) {
  del_switch_info(ea);
}

// Check for jump table at address (simplified - just checks if switch info exists)
bool idalib_check_for_table_jump(ea_t ea) {
  switch_info_t si;
  return get_switch_info(&si, ea) > 0;
}
