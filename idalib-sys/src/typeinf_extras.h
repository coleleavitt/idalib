#pragma once

#include <typeinf.hpp>
#include <pro.h>
#include "cxx.h"

// Get type info for an address (wrapper for tinfo_t object)
rust::String idalib_get_tinfo(ea_t ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, ea)) {
    return rust::String();
  }
  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Set type info from a C declaration string
bool idalib_set_tinfo_from_string(ea_t ea, const char *decl) {
  tinfo_t tif;
  qstring name;

  // Parse the declaration
  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return false;
  }

  // Apply it to the address
  return set_tinfo(ea, &tif);
}

// Delete type info at an address
bool idalib_del_tinfo(ea_t ea) {
  return set_tinfo(ea, nullptr);
}

// Print type at address with flags
rust::String idalib_print_type(ea_t ea, int prtype_flags) {
  qstring buf;
  if (!print_type(&buf, ea, prtype_flags)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Parse a C declaration - returns type string
rust::String idalib_parse_decl_type(const char *decl) {
  tinfo_t tif;
  qstring name;

  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return rust::String();
  }

  qstring buf;
  tif.print(&buf);
  return rust::String(buf.c_str());
}

// Parse a C declaration - returns name
rust::String idalib_parse_decl_name(const char *decl) {
  tinfo_t tif;
  qstring name;

  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return rust::String();
  }

  return rust::String(name.c_str());
}

// Get named type from type library
rust::String idalib_get_named_type(const char *name) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, name)) {
    return rust::String();
  }
  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Set named type in type library
bool idalib_set_named_type(const char *name, const char *decl) {
  tinfo_t tif;
  qstring parsed_name;

  if (!parse_decl(&tif, &parsed_name, nullptr, decl, PT_SIL)) {
    return false;
  }

  return tif.set_named_type(nullptr, name);
}

// Get numbered type (by ordinal)
rust::String idalib_get_numbered_type(uint32 ordinal) {
  tinfo_t tif;
  if (!tif.get_numbered_type(nullptr, ordinal)) {
    return rust::String();
  }
  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Get function type info
rust::String idalib_get_func_tinfo(ea_t ea) {
  func_t *pfn = get_func(ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  tinfo_t tif;
  if (!get_tinfo(&tif, pfn->start_ea)) {
    return rust::String();
  }

  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Guess type info for a function
rust::String idalib_guess_func_tinfo(ea_t ea) {
  func_t *pfn = get_func(ea);
  if (pfn == nullptr) {
    return rust::String();
  }

  tinfo_t tif;
  if (guess_tinfo(&tif, pfn->start_ea) <= 0) {
    return rust::String();
  }

  qstring buf;
  if (!tif.print(&buf)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Apply tinfo to a function
bool idalib_apply_tinfo(ea_t ea, const char *decl) {
  tinfo_t tif;
  qstring name;

  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return false;
  }

  return apply_tinfo(ea, tif, TINFO_DEFINITE);
}

// Get type size
size_t idalib_get_type_size(ea_t ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, ea)) {
    return BADSIZE;
  }

  return tif.get_size();
}

// Check if address has type info
bool idalib_has_tinfo(ea_t ea) {
  tinfo_t tif;
  return get_tinfo(&tif, ea);
}
