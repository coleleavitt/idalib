#pragma once

#include <fixup.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Check if a fixup exists at the given address
bool idalib_exists_fixup(ea_t source) {
  return exists_fixup(source);
}

// Get fixup information as string
rust::String idalib_get_fixup(ea_t source) {
  fixup_data_t fd;
  if (!get_fixup(&fd, source)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Fixup at 0x%" PRIx64 ":\n", uint64(source));
  buf.cat_sprnt("  Type: 0x%x\n", fd.get_type());
  buf.cat_sprnt("  Flags: 0x%x\n", fd.get_flags());
  buf.cat_sprnt("  Displacement: 0x%" PRIx64 "\n", uint64(fd.displacement));
  buf.cat_sprnt("  Selection: 0x%llx\n", (unsigned long long)fd.sel);
  buf.cat_sprnt("  Offset: 0x%" PRIx64 "\n", uint64(fd.off));

  return rust::String(buf.c_str());
}

// Delete fixup information
void idalib_del_fixup(ea_t source) {
  del_fixup(source);
}

// Get the first address with fixup information
ea_t idalib_get_first_fixup_ea() {
  return get_first_fixup_ea();
}

// Find next address with fixup information
ea_t idalib_get_next_fixup_ea(ea_t ea) {
  return get_next_fixup_ea(ea);
}

// Find previous address with fixup information
ea_t idalib_get_prev_fixup_ea(ea_t ea) {
  return get_prev_fixup_ea(ea);
}

// Apply fixup information for an address
bool idalib_apply_fixup(ea_t item_ea, ea_t fixup_ea, int n, bool is_macro) {
  return apply_fixup(item_ea, fixup_ea, n, is_macro);
}

// Get the operand value from fixup
uval_t idalib_get_fixup_value(ea_t ea, fixup_type_t type) {
  return get_fixup_value(ea, type);
}

// Calculate fixup size
int idalib_calc_fixup_size(fixup_type_t type) {
  return calc_fixup_size(type);
}

// Get fixup description
rust::String idalib_get_fixup_desc(fixup_type_t type) {
  // For just getting the description of a fixup type, we need to construct a minimal fixup_data_t
  fixup_data_t fd(type, 0);

  qstring buf;
  const char *result = get_fixup_desc(&buf, BADADDR, fd);

  if (result == nullptr) {
    return rust::String();
  }

  return rust::String(buf.c_str());
}

// Enumerate all fixups as string
rust::String idalib_enumerate_fixups(ea_t start_ea, ea_t end_ea) {
  qstring buf;
  int count = 0;

  ea_t ea = get_first_fixup_ea();
  if (ea == BADADDR) {
    return rust::String("No fixups found");
  }

  // If start_ea specified, find first fixup >= start_ea
  if (start_ea != BADADDR) {
    while (ea != BADADDR && ea < start_ea) {
      ea = get_next_fixup_ea(ea);
    }
  }

  buf.append("Fixups:\n");

  while (ea != BADADDR) {
    // Stop if we've gone past end_ea
    if (end_ea != BADADDR && ea >= end_ea) {
      break;
    }

    fixup_data_t fd;
    if (get_fixup(&fd, ea)) {
      buf.cat_sprnt("  0x%" PRIx64 ": type=0x%x flags=0x%x offset=0x%" PRIx64 "\n",
                    uint64(ea), fd.get_type(), fd.get_flags(), uint64(fd.off));
      count++;
    }

    ea = get_next_fixup_ea(ea);

    // Limit output to prevent excessive data
    if (count >= 1000) {
      buf.cat_sprnt("  ... (truncated after %d fixups)\n", count);
      break;
    }
  }

  buf.cat_sprnt("Total: %d fixups\n", count);
  return rust::String(buf.c_str());
}

// Get fixups in a range
rust::String idalib_get_fixups_in_range(ea_t ea, asize_t size) {
  fixups_t fixups;
  if (!get_fixups(&fixups, ea, size)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Fixups in range 0x%" PRIx64 "-0x%" PRIx64 ":\n",
            uint64(ea), uint64(ea + size));

  for (size_t i = 0; i < fixups.size(); i++) {
    const fixup_info_t &fi = fixups[i];
    buf.cat_sprnt("  [%zu] ea=0x%" PRIx64 " type=0x%x flags=0x%x offset=0x%" PRIx64 "\n",
                  i, uint64(fi.ea), fi.fd.get_type(), fi.fd.get_flags(), uint64(fi.fd.off));
  }

  buf.cat_sprnt("Total: %zu fixups\n", fixups.size());
  return rust::String(buf.c_str());
}

// Count fixups in the database
size_t idalib_count_fixups() {
  size_t count = 0;
  ea_t ea = get_first_fixup_ea();

  while (ea != BADADDR) {
    count++;
    ea = get_next_fixup_ea(ea);
  }

  return count;
}
