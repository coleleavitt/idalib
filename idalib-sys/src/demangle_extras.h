#pragma once

#include <demangle.hpp>
#include <pro.h>
#include "cxx.h"

// Demangle a C++ name
rust::String idalib_demangle_name(const char *mangled, uint32_t disable_mask) {
  if (mangled == nullptr) {
    return rust::String();
  }

  char buf[MAXSTR];
  int32 result = demangle(buf, sizeof(buf), mangled, disable_mask);

  if (result < 0) {
    return rust::String(); // Error
  }

  return rust::String(buf);
}

// Demangle with default settings (long form)
rust::String idalib_demangle_name_long(const char *mangled) {
  return idalib_demangle_name(mangled, MNG_LONG_FORM);
}

// Demangle with short form (minimal decorations)
rust::String idalib_demangle_name_short(const char *mangled) {
  return idalib_demangle_name(mangled, MNG_SHORT_FORM);
}

// Check if name can be demangled (returns compiler type or 0)
int32_t idalib_can_demangle(const char *mangled) {
  if (mangled == nullptr) {
    return 0;
  }
  return demangle(nullptr, 0, mangled, 0);
}

// Get demangled name at address (if name is mangled)
rust::String idalib_demangle_name_at(ea_t ea, uint32_t disable_mask) {
  qstring name = get_name(ea);
  if (name.empty()) {
    return rust::String();
  }

  return idalib_demangle_name(name.c_str(), disable_mask);
}

// Get demangled name at address with long form
rust::String idalib_demangle_name_at_long(ea_t ea) {
  return idalib_demangle_name_at(ea, MNG_LONG_FORM);
}
