#pragma once

#include <auto.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Wait for auto-analysis to complete
// Returns: true if analysis finished, false otherwise
bool idalib_auto_wait() {
  return auto_wait();
}

// Wait for auto-analysis on a range to complete
// Returns: number of functions created, -1 on error
int idalib_plan_and_wait(ea_t ea1, ea_t ea2, int final_pass) {
  ssize_t result = auto_wait_range(ea1, ea2);
  return (int)result;
}

// Check if auto-analysis is enabled
bool idalib_auto_is_ok() {
  return inf_should_create_stkvars();
}

// Enable auto-analysis
void idalib_enable_auto() {
  enable_auto(true);
}

// Disable auto-analysis
void idalib_disable_auto() {
  enable_auto(false);
}

// Show auto-analysis state
rust::String idalib_show_auto_state() {
  atype_t state = get_auto_state();

  qstring buf;
  buf.sprnt("Auto-analysis state:\n");
  buf.cat_sprnt("  Enabled: %s\n", inf_should_create_stkvars() ? "yes" : "no");
  buf.cat_sprnt("  State value: %d\n", state);

  if (state == AU_NONE) {
    buf.cat_sprnt("  State: none (idle)\n");
  } else if (state == AU_CODE) {
    buf.cat_sprnt("  State: making code\n");
  } else if (state == AU_PROC) {
    buf.cat_sprnt("  State: making procedures\n");
  } else if (state == AU_USED) {
    buf.cat_sprnt("  State: reanalyzing\n");
  } else if (state == AU_FINAL) {
    buf.cat_sprnt("  State: final pass\n");
  } else {
    buf.cat_sprnt("  State: working (%d)\n", state);
  }

  return rust::String(buf.c_str());
}

// Make code at address (analyze as code)
bool idalib_auto_make_code(ea_t ea) {
  auto_make_code(ea);
  return true;
}

// Make procedure at address (create function)
bool idalib_auto_make_proc(ea_t ea) {
  auto_make_proc(ea);
  return true;
}

// Reanalyze area
bool idalib_reanalyze_area(ea_t ea1, ea_t ea2) {
  auto_mark_range(ea1, ea2, AU_USED);
  return true;
}

// Mark address range for analysis
bool idalib_auto_mark_range(ea_t ea1, ea_t ea2, int atype) {
  auto_mark_range(ea1, ea2, (atype_t)atype);
  return true;
}

// Undefine and reanalyze
bool idalib_auto_recreate_insn(ea_t ea) {
  auto_recreate_insn(ea);
  return true;
}

// Analyze extra - reanalyze range
void idalib_analyze_area(ea_t ea1, ea_t ea2) {
  auto_mark_range(ea1, ea2, AU_USED);
}

// Plan to analyze the specified range
bool idalib_plan_to_analyze(ea_t ea1, ea_t ea2, int plan) {
  auto_mark_range(ea1, ea2, (atype_t)plan);
  return true;
}

// Check if analysis queue is empty
bool idalib_is_auto_queue_empty() {
  return get_auto_state() == AU_NONE;
}

// Get analysis state enum value
int idalib_get_auto_state_value() {
  return (int)get_auto_state();
}

// Plan to make a function
void idalib_plan_function(ea_t ea) {
  auto_make_proc(ea);
}

// Plan to make code
void idalib_plan_code(ea_t ea) {
  auto_make_code(ea);
}

// Plan to analyze operands
void idalib_plan_operands(ea_t ea) {
  auto_mark(ea, AU_USED);
}

// Plan final analysis pass
void idalib_plan_final_analysis(ea_t ea1, ea_t ea2) {
  auto_mark_range(ea1, ea2, AU_FINAL);
}

// Check what type of analysis is planned for address
rust::String idalib_get_planned_analysis(ea_t ea) {
  qstring buf;
  buf.sprnt("Address 0x%" PRIx64 ":\n", uint64(ea));

  if (is_code(get_flags(ea))) {
    buf.cat_sprnt("  Currently: code\n");
  } else if (is_data(get_flags(ea))) {
    buf.cat_sprnt("  Currently: data\n");
  } else {
    buf.cat_sprnt("  Currently: unexplored\n");
  }

  func_t *pfn = get_func(ea);
  if (pfn != nullptr) {
    buf.cat_sprnt("  Function: yes (0x%" PRIx64 "-0x%" PRIx64 ")\n",
                  uint64(pfn->start_ea), uint64(pfn->end_ea));
  } else {
    buf.cat_sprnt("  Function: no\n");
  }

  return rust::String(buf.c_str());
}

// Wait for auto-analysis with timeout (milliseconds)
// Returns true if completed, false if timeout
bool idalib_auto_wait_timeout(int timeout_ms) {
  if (timeout_ms <= 0) {
    return auto_wait();
  }

  int elapsed = 0;
  const int check_interval = 100; // Check every 100ms

  while (elapsed < timeout_ms) {
    if (get_auto_state() == AU_NONE) {
      return true;
    }

    qsleep(check_interval);
    elapsed += check_interval;
  }

  return false;
}

// Perform full analysis on database
void idalib_analyze_database(ea_t ea1, ea_t ea2) {
  if (ea1 == BADADDR) ea1 = inf_get_min_ea();
  if (ea2 == BADADDR) ea2 = inf_get_max_ea();

  // Mark entire range for analysis
  auto_mark_range(ea1, ea2, AU_USED);
  auto_mark_range(ea1, ea2, AU_FINAL);
}

// Analyze specific address as code
bool idalib_analyze_as_code(ea_t ea) {
  // Undefine first if needed
  if (is_data(get_flags(ea))) {
    del_items(ea, DELIT_EXPAND);
  }

  // Make code
  auto_make_code(ea);
  return true;
}

// Analyze specific address as function
bool idalib_analyze_as_function(ea_t ea) {
  // First make it code if needed
  if (!is_code(get_flags(ea))) {
    if (!idalib_analyze_as_code(ea)) {
      return false;
    }
  }

  // Then make it a function
  auto_make_proc(ea);
  return true;
}

// Get comprehensive analysis info
rust::String idalib_get_analysis_info() {
  atype_t state = get_auto_state();

  qstring buf;
  buf.sprnt("IDA Analysis Information:\n");
  buf.cat_sprnt("  Database range: 0x%" PRIx64 " - 0x%" PRIx64 "\n",
                uint64(inf_get_min_ea()), uint64(inf_get_max_ea()));

  // Analysis state
  buf.cat_sprnt("  Auto-analysis enabled: %s\n",
                inf_should_create_stkvars() ? "yes" : "no");

  if (state == AU_NONE) {
    buf.cat_sprnt("  State: idle\n");
  } else if (state == AU_CODE) {
    buf.cat_sprnt("  State: making code\n");
  } else if (state == AU_PROC) {
    buf.cat_sprnt("  State: making procedures\n");
  } else if (state == AU_USED) {
    buf.cat_sprnt("  State: reanalyzing\n");
  } else if (state == AU_FINAL) {
    buf.cat_sprnt("  State: final pass\n");
  } else {
    buf.cat_sprnt("  State: working (%d)\n", state);
  }

  return rust::String(buf.c_str());
}
