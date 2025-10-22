#pragma once

#include "nalt.hpp"
#include "pro.h"
#include "loader.hpp"

#include "cxx.h"
#include <vector>

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    return rust::String(path, size);
  } else {
    return rust::String();
  }
}
 
struct import_ctx {
  qstring current_module_name;
  rust::Vec<rust::String> &module_names;
  rust::Vec<rust::String> &import_names;
  rust::Vec<uint64_t> &addresses;
  rust::Vec<uint32_t> &ordinals;
};

static int import_enum_callback(ea_t ea, const char *name, uval_t ordinal, void *param) {
  import_ctx* ctx = static_cast<import_ctx*>(param);

  ctx->module_names.push_back(rust::String(ctx->current_module_name.c_str()));
  ctx->import_names.push_back(rust::String(name ? name : ""));
  ctx->addresses.push_back(ea);
  ctx->ordinals.push_back(static_cast<uint32_t>(ordinal));

  return 1;
}

// Get total number of import modules
uint32_t idalib_get_import_module_qty() {
  return get_import_module_qty();
}

// Get import module name by index
rust::String idalib_get_import_module_name(uint32_t idx) {
  qstring module_name;
  if (get_import_module_name(&module_name, idx)) {
    return rust::String(module_name.c_str());
  }
  return rust::String();
}

// Get all imports for a specific module (by index)
void idalib_get_imports_for_module(
    uint32_t module_idx,
    rust::Vec<rust::String> &import_names,
    rust::Vec<uint64_t> &addresses,
    rust::Vec<uint32_t> &ordinals) {

  qstring module_name;
  if (!get_import_module_name(&module_name, module_idx)) {
    return;
  }

  // Temporary vectors to hold module names (not needed for single module)
  rust::Vec<rust::String> temp_module_names;
  import_ctx ctx{module_name, temp_module_names, import_names, addresses, ordinals};
  enum_import_names(module_idx, import_enum_callback, static_cast<void *>(&ctx));
}

// Legacy function: Get all imports eagerly (kept for backward compatibility)
bool idalib_get_imports(rust::Vec<rust::String> &module_names, rust::Vec<rust::String> &import_names, rust::Vec<uint64_t> &addresses, rust::Vec<uint32_t> &ordinals) {
  for (uint32_t idx = 0; idx < get_import_module_qty(); idx++) {
    qstring module_name;
    if (!get_import_module_name(&module_name, idx)) {
      return false;
    }

    import_ctx ctx{module_name, module_names, import_names, addresses, ordinals};
    enum_import_names(idx, import_enum_callback, static_cast<void *>(&ctx));
  }
  return true;
}
