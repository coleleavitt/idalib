#pragma once

#include <problems.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Get the human-friendly description of the problem
rust::String idalib_get_problem_desc(problist_id_t type, ea_t ea) {
  qstring buf;
  ssize_t result = get_problem_desc(&buf, type, ea);

  if (result < 0) {
    return rust::String();
  }

  return rust::String(buf.c_str());
}

// Insert an address to a list of problems
void idalib_remember_problem(problist_id_t type, ea_t ea, const char *msg) {
  remember_problem(type, ea, msg);
}

// Insert an address to a list of problems (no message)
void idalib_remember_problem_simple(problist_id_t type, ea_t ea) {
  remember_problem(type, ea, nullptr);
}

// Get an address from the specified problem list
ea_t idalib_get_problem(problist_id_t type, ea_t lowea) {
  return get_problem(type, lowea);
}

// Remove an address from a problem list
bool idalib_forget_problem(problist_id_t type, ea_t ea) {
  return forget_problem(type, ea);
}

// Get problem list description (long name)
rust::String idalib_get_problem_name(problist_id_t type) {
  const char *name = get_problem_name(type, true);
  if (name == nullptr) {
    return rust::String();
  }
  return rust::String(name);
}

// Get problem list description (short name)
rust::String idalib_get_problem_name_short(problist_id_t type) {
  const char *name = get_problem_name(type, false);
  if (name == nullptr) {
    return rust::String();
  }
  return rust::String(name);
}

// Check if the specified address is present in the problem list
bool idalib_is_problem_present(problist_id_t type, ea_t ea) {
  return is_problem_present(type, ea);
}

// Enumerate all problems of a specific type
rust::String idalib_enumerate_problems(problist_id_t type, ea_t start_ea, ea_t end_ea) {
  qstring buf;
  const char *type_name = get_problem_name(type, true);

  buf.sprnt("Problems of type 0x%x (%s):\n", type, type_name ? type_name : "Unknown");

  int count = 0;
  ea_t ea = get_problem(type, start_ea);

  while (ea != BADADDR) {
    // Stop if we've gone past end_ea
    if (end_ea != BADADDR && ea >= end_ea) {
      break;
    }

    // Get problem description if available
    qstring desc;
    ssize_t desc_len = get_problem_desc(&desc, type, ea);

    if (desc_len > 0) {
      buf.cat_sprnt("  0x%" PRIx64 ": %s\n", uint64(ea), desc.c_str());
    } else {
      buf.cat_sprnt("  0x%" PRIx64 "\n", uint64(ea));
    }

    count++;

    // Get next problem
    ea = get_problem(type, ea + 1);

    // Limit output to prevent excessive data
    if (count >= 1000) {
      buf.cat_sprnt("  ... (truncated after %d problems)\n", count);
      break;
    }
  }

  buf.cat_sprnt("Total: %d problems\n", count);
  return rust::String(buf.c_str());
}

// Enumerate all problem types and their counts
rust::String idalib_enumerate_all_problems() {
  qstring buf;
  buf.append("All problem types:\n");

  for (problist_id_t type = PR_NOBASE; type < PR_END; type++) {
    const char *type_name = get_problem_name(type, true);
    if (type_name == nullptr) {
      continue;
    }

    // Count problems of this type
    int count = 0;
    ea_t ea = get_problem(type, 0);

    while (ea != BADADDR) {
      count++;
      ea = get_problem(type, ea + 1);

      // Quick count limit
      if (count >= 10000) {
        count = 10000;
        break;
      }
    }

    if (count > 0) {
      buf.cat_sprnt("  [%d] %s: %d problems\n", type, type_name, count);
    }
  }

  return rust::String(buf.c_str());
}

// Get problem information at address (check all types)
rust::String idalib_get_problems_at(ea_t ea) {
  qstring buf;
  buf.sprnt("Problems at 0x%" PRIx64 ":\n", uint64(ea));

  bool found_any = false;

  for (problist_id_t type = PR_NOBASE; type < PR_END; type++) {
    if (is_problem_present(type, ea)) {
      const char *type_name = get_problem_name(type, true);

      qstring desc;
      ssize_t desc_len = get_problem_desc(&desc, type, ea);

      if (desc_len > 0) {
        buf.cat_sprnt("  [%d] %s: %s\n", type, type_name, desc.c_str());
      } else {
        buf.cat_sprnt("  [%d] %s\n", type, type_name);
      }

      found_any = true;
    }
  }

  if (!found_any) {
    buf.append("  No problems found\n");
  }

  return rust::String(buf.c_str());
}
