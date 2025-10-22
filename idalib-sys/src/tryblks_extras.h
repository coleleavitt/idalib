#pragma once

#include <tryblks.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Get try block information from the specified address range
rust::String idalib_get_tryblks(ea_t start_ea, ea_t end_ea) {
  range_t range;
  range.start_ea = start_ea;
  range.end_ea = end_ea;

  tryblks_t tbv;
  size_t count = get_tryblks(&tbv, range);

  if (count == 0) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Found %zu try blocks in range 0x%" PRIx64 "-0x%" PRIx64 ":\n",
            count, uint64(start_ea), uint64(end_ea));

  for (size_t i = 0; i < tbv.size(); i++) {
    const tryblk_t &tb = tbv[i];
    buf.cat_sprnt("\nTry block #%zu (level %d):\n", i, tb.level);

    // Print guarded regions
    buf.cat_sprnt("  Guarded regions: %zu\n", tb.size());
    for (size_t j = 0; j < tb.size(); j++) {
      buf.cat_sprnt("    [%zu] 0x%" PRIx64 "-0x%" PRIx64 "\n",
                    j, uint64(tb[j].start_ea), uint64(tb[j].end_ea));
    }

    // Print handler type
    if (tb.is_cpp()) {
      buf.cat_sprnt("  Type: C++ try/catch\n");
      const catchvec_t &catches = tb.cpp();
      buf.cat_sprnt("  Catch blocks: %zu\n", catches.size());
      for (size_t k = 0; k < catches.size(); k++) {
        const catch_t &c = catches[k];
        buf.cat_sprnt("    [%zu] type_id: %lld, obj: %lld, regions: %zu\n",
                      k, (long long)c.type_id, (long long)c.obj, c.size());
      }
    } else if (tb.is_seh()) {
      buf.cat_sprnt("  Type: SEH __try/__except/__finally\n");
      const seh_t &s = tb.seh();
      buf.cat_sprnt("  SEH code: 0x%" PRIx64 "\n", uint64(s.seh_code));
      buf.cat_sprnt("  Filter regions: %zu\n", s.filter.size());
    } else {
      buf.cat_sprnt("  Type: NONE\n");
    }
  }

  return rust::String(buf.c_str());
}

// Get number of try blocks in the specified address range
size_t idalib_get_tryblks_count(ea_t start_ea, ea_t end_ea) {
  range_t range;
  range.start_ea = start_ea;
  range.end_ea = end_ea;
  return get_tryblks(nullptr, range);
}

// Delete try block information in the specified range
void idalib_del_tryblks(ea_t start_ea, ea_t end_ea) {
  range_t range;
  range.start_ea = start_ea;
  range.end_ea = end_ea;
  del_tryblks(range);
}

// Find the start address of the system eh region including the argument
ea_t idalib_find_syseh(ea_t ea) {
  return find_syseh(ea);
}

// Check if the given address is part of tryblks description
bool idalib_is_ea_tryblks(ea_t ea, uint32_t flags) {
  return is_ea_tryblks(ea, flags);
}

// Check if EA is within a C++ try block
bool idalib_is_ea_cpp_try(ea_t ea) {
  return is_ea_tryblks(ea, TBEA_TRY);
}

// Check if EA is the start of a C++ catch/cleanup block
bool idalib_is_ea_cpp_catch(ea_t ea) {
  return is_ea_tryblks(ea, TBEA_CATCH);
}

// Check if EA is within a SEH try block
bool idalib_is_ea_seh_try(ea_t ea) {
  return is_ea_tryblks(ea, TBEA_SEHTRY);
}

// Check if EA is the start of a SEH finally/except block
bool idalib_is_ea_seh_handler(ea_t ea) {
  return is_ea_tryblks(ea, TBEA_SEHLPAD);
}

// Check if EA is the start of a SEH filter
bool idalib_is_ea_seh_filter(ea_t ea) {
  return is_ea_tryblks(ea, TBEA_SEHFILT);
}
