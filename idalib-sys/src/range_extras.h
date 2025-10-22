#pragma once

#include <range.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Check if address is within a range
bool idalib_range_contains(ea_t range_start, ea_t range_end, ea_t ea) {
  return ea >= range_start && ea < range_end;
}

// Get range size
asize_t idalib_range_size(ea_t range_start, ea_t range_end) {
  if (range_end <= range_start) {
    return 0;
  }
  return range_end - range_start;
}

// Check if two ranges overlap
bool idalib_ranges_overlap(ea_t r1_start, ea_t r1_end, ea_t r2_start, ea_t r2_end) {
  return r1_start < r2_end && r2_start < r1_end;
}

// Get range intersection
rust::String idalib_range_intersection(ea_t r1_start, ea_t r1_end, ea_t r2_start, ea_t r2_end) {
  if (!idalib_ranges_overlap(r1_start, r1_end, r2_start, r2_end)) {
    return rust::String();
  }

  ea_t start = r1_start > r2_start ? r1_start : r2_start;
  ea_t end = r1_end < r2_end ? r1_end : r2_end;

  qstring buf;
  buf.sprnt("0x%" PRIx64 "-0x%" PRIx64, uint64(start), uint64(end));
  return rust::String(buf.c_str());
}

// Enumerate all segments with detailed information
rust::String idalib_enumerate_segments_detailed() {
  qstring buf;
  int seg_count = 0;

  buf.sprnt("Segments in database:\n");

  for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea)) {
    qstring seg_name;
    get_segm_name(&seg_name, seg);

    qstring seg_class;
    get_segm_class(&seg_class, seg);

    buf.cat_sprnt("  [%d] 0x%" PRIx64 "-0x%" PRIx64 " (%s, class: %s, %s%s%s)\n",
                  seg_count,
                  uint64(seg->start_ea),
                  uint64(seg->end_ea),
                  seg_name.c_str(),
                  seg_class.c_str(),
                  seg->perm & SEGPERM_READ ? "R" : "-",
                  seg->perm & SEGPERM_WRITE ? "W" : "-",
                  seg->perm & SEGPERM_EXEC ? "X" : "-");

    seg_count++;
    if (seg_count >= 1000) {
      buf.cat_sprnt("  ... (showing first 1000 segments)\n");
      break;
    }
  }

  buf.cat_sprnt("\nTotal segments: %d\n", seg_count);
  return rust::String(buf.c_str());
}

// Get segment by address
rust::String idalib_get_segment_at(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return rust::String();
  }

  qstring seg_name;
  get_segm_name(&seg_name, seg);

  qstring seg_class;
  get_segm_class(&seg_class, seg);

  qstring buf;
  buf.sprnt("Segment at 0x%" PRIx64 ":\n", uint64(ea));
  buf.cat_sprnt("  Name: %s\n", seg_name.c_str());
  buf.cat_sprnt("  Class: %s\n", seg_class.c_str());
  buf.cat_sprnt("  Range: 0x%" PRIx64 "-0x%" PRIx64 "\n", uint64(seg->start_ea), uint64(seg->end_ea));
  buf.cat_sprnt("  Size: 0x%" PRIx64 " bytes\n", uint64(seg->end_ea - seg->start_ea));
  buf.cat_sprnt("  Permissions: %s%s%s\n",
                seg->perm & SEGPERM_READ ? "R" : "-",
                seg->perm & SEGPERM_WRITE ? "W" : "-",
                seg->perm & SEGPERM_EXEC ? "X" : "-");
  buf.cat_sprnt("  Bitness: %d-bit\n", seg->bitness == 0 ? 16 : seg->bitness == 1 ? 32 : 64);
  buf.cat_sprnt("  Type: 0x%x\n", seg->type);

  return rust::String(buf.c_str());
}

// Get segment by name
ea_t idalib_get_segment_by_name(const char *name) {
  segment_t *seg = get_segm_by_name(name);
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Check if segment is code
bool idalib_is_code_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return seg->type == SEG_CODE;
}

// Check if segment is data
bool idalib_is_data_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return seg->type == SEG_DATA;
}

// Check if segment is BSS
bool idalib_is_bss_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return seg->type == SEG_BSS;
}

// Check if segment is executable
bool idalib_is_executable_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return (seg->perm & SEGPERM_EXEC) != 0;
}

// Check if segment is writable
bool idalib_is_writable_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return (seg->perm & SEGPERM_WRITE) != 0;
}

// Check if segment is readable
bool idalib_is_readable_segment(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return false;
  }
  return (seg->perm & SEGPERM_READ) != 0;
}

// Get segment start address
ea_t idalib_get_segment_start(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Get segment end address
ea_t idalib_get_segment_end(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->end_ea;
}

// Get segment name
rust::String idalib_get_segment_name(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return rust::String();
  }

  qstring seg_name;
  get_segm_name(&seg_name, seg);
  return rust::String(seg_name.c_str());
}

// Get segment class
rust::String idalib_get_segment_class(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return rust::String();
  }

  qstring seg_class;
  get_segm_class(&seg_class, seg);
  return rust::String(seg_class.c_str());
}

// Get segment count
int idalib_get_segment_count() {
  int count = 0;
  for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea)) {
    count++;
    if (count >= 10000) break; // Safety limit
  }
  return count;
}

// Get first segment address
ea_t idalib_get_first_segment_ea() {
  segment_t *seg = get_first_seg();
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Get next segment address
ea_t idalib_get_next_segment_ea(ea_t ea) {
  segment_t *seg = get_next_seg(ea);
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Get previous segment address
ea_t idalib_get_prev_segment_ea(ea_t ea) {
  segment_t *seg = get_prev_seg(ea);
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Get last segment address
ea_t idalib_get_last_segment_ea() {
  segment_t *seg = get_last_seg();
  if (seg == nullptr) {
    return BADADDR;
  }
  return seg->start_ea;
}

// Get segment bitness (16/32/64)
int idalib_get_segment_bitness(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return -1;
  }
  return seg->bitness == 0 ? 16 : seg->bitness == 1 ? 32 : 64;
}

// Get segment type
int idalib_get_segment_type(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return -1;
  }
  return seg->type;
}

// Get segment permissions
int idalib_get_segment_permissions(ea_t ea) {
  segment_t *seg = getseg(ea);
  if (seg == nullptr) {
    return 0;
  }
  return seg->perm;
}

// Find segment containing range
rust::String idalib_find_segments_in_range(ea_t start_ea, ea_t end_ea) {
  qstring buf;
  int count = 0;

  buf.sprnt("Segments overlapping 0x%" PRIx64 "-0x%" PRIx64 ":\n",
            uint64(start_ea), uint64(end_ea));

  for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea)) {
    // Check if segment overlaps with range
    if (seg->start_ea < end_ea && start_ea < seg->end_ea) {
      qstring seg_name;
      get_segm_name(&seg_name, seg);

      buf.cat_sprnt("  [%d] %s: 0x%" PRIx64 "-0x%" PRIx64 "\n",
                    count, seg_name.c_str(),
                    uint64(seg->start_ea), uint64(seg->end_ea));
      count++;
    }

    if (count >= 100) {
      buf.cat_sprnt("  ... (showing first 100 segments)\n");
      break;
    }
  }

  buf.cat_sprnt("\nTotal overlapping segments: %d\n", count);
  return rust::String(buf.c_str());
}
