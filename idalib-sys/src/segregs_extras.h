#pragma once

#include <segregs.hpp>
#include <pro.h>
#include "cxx.h"

// Get value of a segment register at an address
sel_t idalib_get_sreg(ea_t ea, int rg) {
  return get_sreg(ea, rg);
}

// Create a new segment register range
bool idalib_split_sreg_range(ea_t ea, int rg, sel_t v, uchar tag, bool silent) {
  return split_sreg_range(ea, rg, v, tag, silent);
}

// Set default value of a segment register for a segment
bool idalib_set_default_sreg_value(ea_t seg_start, int rg, sel_t value) {
  segment_t *sg = getseg(seg_start);
  if (sg == nullptr) {
    return false;
  }
  return set_default_sreg_value(sg, rg, value);
}

// Set default value of a segment register for all segments
bool idalib_set_default_sreg_value_all(int rg, sel_t value) {
  return set_default_sreg_value(nullptr, rg, value);
}

// Set default value of DS register for all segments
void idalib_set_default_dataseg(sel_t ds_sel) {
  set_default_dataseg(ds_sel);
}

// Set the segment register value at the next instruction
void idalib_set_sreg_at_next_code(ea_t ea1, ea_t ea2, int rg, sel_t value) {
  set_sreg_at_next_code(ea1, ea2, rg, value);
}

// Get segment register range by linear address
rust::String idalib_get_sreg_range(ea_t ea, int rg) {
  sreg_range_t sr;
  if (!get_sreg_range(&sr, ea, rg)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Range: 0x%llx-0x%llx, Value: 0x%x, Tag: %d",
            (unsigned long long)sr.start_ea,
            (unsigned long long)sr.end_ea,
            sr.val,
            sr.tag);
  return rust::String(buf.c_str());
}

// Get segment register range previous to one with address
rust::String idalib_get_prev_sreg_range(ea_t ea, int rg) {
  sreg_range_t sr;
  if (!get_prev_sreg_range(&sr, ea, rg)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Range: 0x%llx-0x%llx, Value: 0x%x, Tag: %d",
            (unsigned long long)sr.start_ea,
            (unsigned long long)sr.end_ea,
            sr.val,
            sr.tag);
  return rust::String(buf.c_str());
}

// Get number of segment register ranges
size_t idalib_get_sreg_ranges_qty(int rg) {
  return get_sreg_ranges_qty(rg);
}

// Get segment register range by its number
rust::String idalib_getn_sreg_range(int rg, int n) {
  sreg_range_t sr;
  if (!getn_sreg_range(&sr, rg, n)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Range: 0x%llx-0x%llx, Value: 0x%x, Tag: %d",
            (unsigned long long)sr.start_ea,
            (unsigned long long)sr.end_ea,
            sr.val,
            sr.tag);
  return rust::String(buf.c_str());
}

// Get number of segment register range by address
int idalib_get_sreg_range_num(ea_t ea, int rg) {
  return get_sreg_range_num(ea, rg);
}

// Delete segment register range started at ea
bool idalib_del_sreg_range(ea_t ea, int rg) {
  return del_sreg_range(ea, rg);
}

// Duplicate segment register ranges
void idalib_copy_sreg_ranges(int dst_rg, int src_rg, bool map_selector) {
  copy_sreg_ranges(dst_rg, src_rg, map_selector);
}
