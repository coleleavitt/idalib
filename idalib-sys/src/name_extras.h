#pragma once

#include "name.hpp"

#include "cxx.h"

rust::String idalib_get_ea_name(ea_t ea) {
  qstring name;
  if (get_ea_name(&name, ea)) {
    return rust::String(name.c_str());
  } else {
    return rust::String("");
  }
}

bool idalib_set_ea_name(ea_t ea, const char *name, int32_t flags) {
  return set_name(ea, name, flags);
}

bool idalib_force_ea_name(ea_t ea, const char *name) {
  return force_name(ea, name);
}

bool idalib_del_global_name(ea_t ea) {
  return del_global_name(ea);
}

bool idalib_del_local_name(ea_t ea) {
  return del_local_name(ea);
}