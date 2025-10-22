#pragma once

#include <offset.hpp>
#include <pro.h>
#include "cxx.h"

// Mark operand as offset
bool idalib_op_offset(ea_t ea, int n, ea_t base) {
  return op_offset(ea, n, REF_OFF32, BADADDR, base);
}

// Mark operand as offset with full control
bool idalib_op_offset_ex(ea_t ea, int n, int reftype, ea_t target, ea_t base, ea_t tdelta) {
  refinfo_t ri;
  ri.init(reftype, base, target, tdelta);
  return op_offset_ex(ea, n, &ri);
}

// Get offset expression as string
rust::String idalib_get_offset_expression(ea_t ea, int n) {
  adiff_t offset = 0;
  ea_t base = 0;
  qstring buf;

  int result = get_offset_expression(&buf, ea, n, offset, base);
  if (result > 0) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Calculate offset base address
ea_t idalib_calc_offset_base(ea_t ea, int n) {
  return calc_offset_base(ea, n);
}

// Get default reference type for address
int idalib_get_default_reftype(ea_t ea) {
  return get_default_reftype(ea);
}

// Check if value can be a 32-bit offset
ea_t idalib_can_be_off32(ea_t ea) {
  return can_be_off32(ea);
}

// Calculate probable base by value
ea_t idalib_calc_probable_base(ea_t ea, ea_t off) {
  return calc_probable_base_by_value(ea, off);
}

// Calculate reference data (get target from operand, returns BADADDR if not an offset)
ea_t idalib_calc_reference_target(ea_t ea, int n) {
  ea_t target = BADADDR;
  ea_t base = BADADDR;
  adiff_t tdelta = 0;

  refinfo_t ri;
  if (!calc_reference_data(&target, &base, ea, ri, tdelta)) {
    return BADADDR;
  }

  return target;
}

// Calculate reference base (returns BADADDR if not an offset)
ea_t idalib_calc_reference_base(ea_t ea, int n) {
  ea_t target = BADADDR;
  ea_t base = BADADDR;
  adiff_t tdelta = 0;

  refinfo_t ri;
  if (!calc_reference_data(&target, &base, ea, ri, tdelta)) {
    return BADADDR;
  }

  return base;
}
