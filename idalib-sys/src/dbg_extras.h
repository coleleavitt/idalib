#pragma once

#include <dbg.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Check if the debugger is currently running
bool idalib_is_debugger_on() {
  return is_debugger_on();
}

// Check if an address is mapped to debugger memory
bool idalib_is_debugger_memory(ea_t ea) {
  return is_debugger_memory(ea);
}

// Get one byte of the debugged process memory
bool idalib_get_dbg_byte(ea_t ea, uint32_t *out) {
  return get_dbg_byte(out, ea);
}

// Get one byte of the debugged process memory (returns -1 on error)
int32_t idalib_get_dbg_byte_value(ea_t ea) {
  uint32_t value = 0;
  if (get_dbg_byte(&value, ea)) {
    return (int32_t)value;
  }
  return -1;
}

// Change one byte of the debugged process memory
bool idalib_put_dbg_byte(ea_t ea, uint32_t x) {
  return put_dbg_byte(ea, x);
}

// Invalidate the debugged process memory configuration
void idalib_invalidate_dbgmem_config() {
  invalidate_dbgmem_config();
}

// Invalidate the debugged process memory contents
// If ea == BADADDR, invalidates the whole memory contents
void idalib_invalidate_dbgmem_contents(ea_t ea, asize_t size) {
  invalidate_dbgmem_contents(ea, size);
}

// Lock the debugger memory configuration
void idalib_lock_dbgmem_config() {
  lock_dbgmem_config();
}

// Unlock the debugger memory configuration
void idalib_unlock_dbgmem_config() {
  unlock_dbgmem_config();
}

// Read multiple bytes from debugged process memory
rust::String idalib_get_dbg_bytes(ea_t ea, size_t size) {
  if (!is_debugger_on() || !is_debugger_memory(ea)) {
    return rust::String();
  }

  qstring buf;
  buf.resize(size * 3); // "XX " per byte

  for (size_t i = 0; i < size; i++) {
    uint32_t byte_val = 0;
    if (!get_dbg_byte(&byte_val, ea + i)) {
      return rust::String();
    }
    buf.cat_sprnt("%02X ", byte_val & 0xFF);
  }

  // Remove trailing space
  if (!buf.empty() && buf.last() == ' ') {
    buf.remove_last();
  }

  return rust::String(buf.c_str());
}

// Get debugger status information
rust::String idalib_get_debugger_status() {
  qstring buf;

  if (is_debugger_on()) {
    buf.append("Debugger: RUNNING\n");
  } else {
    buf.append("Debugger: NOT RUNNING\n");
    return rust::String(buf.c_str());
  }

  // Get current debugger pointer
  if (dbg != nullptr) {
    buf.cat_sprnt("Debugger module: %s\n", dbg->name);
    buf.cat_sprnt("Processor: %s\n", dbg->processor);

    // Show some flags
    if (dbg->flags & DBG_FLAG_REMOTE) {
      buf.append("  Remote debugger\n");
    }
    if (dbg->flags & DBG_FLAG_NOHOST) {
      buf.append("  No host process\n");
    }
    if (dbg->flags & DBG_FLAG_SAFE) {
      buf.append("  Safe mode\n");
    }
    if (dbg->flags & DBG_FLAG_CLEAN_EXIT) {
      buf.append("  Clean exit\n");
    }
  }

  return rust::String(buf.c_str());
}
