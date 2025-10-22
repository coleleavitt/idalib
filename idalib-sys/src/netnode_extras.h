#pragma once

#include <netnode.hpp>
#include <pro.h>
#include <inttypes.h>
#include "cxx.h"

// Create or get a named netnode
// Returns the netnode number, or BADADDR if failed
nodeidx_t idalib_netnode_get(const char *name, bool create) {
  netnode n(name, 0, create);
  if (n == BADNODE) {
    return BADNODE;
  }
  return (nodeidx_t)n;
}

// Check if a netnode with given name exists
bool idalib_netnode_exists(const char *name) {
  return netnode::exist(name);
}

// Check if a netnode with given number exists
bool idalib_netnode_exists_num(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  return exist(n);
}

// Get netnode name
rust::String idalib_netnode_get_name(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  qstring name;
  ssize_t len = n.get_name(&name);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(name.c_str());
}

// Rename a netnode
bool idalib_netnode_rename(nodeidx_t num, const char *newname) {
  netnode n((nodeidx_t)num);
  return n.rename(newname);
}

// Delete a netnode
void idalib_netnode_kill(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  n.kill();
}

// Get string value of netnode
rust::String idalib_netnode_valstr(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.valstr(&buf);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Set string value of netnode
bool idalib_netnode_set_str(nodeidx_t num, const char *value) {
  netnode n((nodeidx_t)num);
  return n.set(value, strlen(value));
}

// Get long value of netnode
nodeidx_t idalib_netnode_long_value(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  return n.long_value();
}

// Set long value of netnode
bool idalib_netnode_set_long(nodeidx_t num, nodeidx_t value) {
  netnode n((nodeidx_t)num);
  return n.set_long((nodeidx_t)value);
}

// Delete value of netnode
bool idalib_netnode_delvalue(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  return n.delvalue();
}

// Check if value exists
bool idalib_netnode_value_exists(nodeidx_t num) {
  netnode n((nodeidx_t)num);
  return n.value_exists();
}

// Get supval (sparse array) string value
rust::String idalib_netnode_supstr(nodeidx_t num, nodeidx_t idx, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.supstr(&buf, (nodeidx_t)idx, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Set supval (sparse array) string value
bool idalib_netnode_supset_str(nodeidx_t num, nodeidx_t idx, const char *value, int tag) {
  netnode n((nodeidx_t)num);
  return n.supset((nodeidx_t)idx, value, strlen(value), (char)tag);
}

// Get supval long value (reads as a nodeidx_t-sized blob)
nodeidx_t idalib_netnode_supval(nodeidx_t num, nodeidx_t idx, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t value = 0;
  ssize_t len = netnode_supval((nodeidx_t)n, idx, &value, sizeof(value), tag);
  if (len < 0) {
    return 0;
  }
  return value;
}

// Set supval long value
bool idalib_netnode_supset_long(nodeidx_t num, nodeidx_t idx, nodeidx_t value, int tag) {
  netnode n((nodeidx_t)num);
  return n.supset((nodeidx_t)idx, &value, sizeof(value), (char)tag);
}

// Delete supval
bool idalib_netnode_supdel(nodeidx_t num, nodeidx_t idx, int tag) {
  netnode n((nodeidx_t)num);
  return n.supdel((nodeidx_t)idx, (char)tag);
}

// Get first supval index
nodeidx_t idalib_netnode_supfirst(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.supfirst((char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get next supval index
nodeidx_t idalib_netnode_supnext(nodeidx_t num, nodeidx_t cur, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.supnext((nodeidx_t)cur, (char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get last supval index
nodeidx_t idalib_netnode_suplast(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.suplast((char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get previous supval index
nodeidx_t idalib_netnode_supprev(nodeidx_t num, nodeidx_t cur, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.supprev((nodeidx_t)cur, (char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Delete all supvals
bool idalib_netnode_supdel_all(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  return n.supdel_all((char)tag);
}

// Get altval (array) value
nodeidx_t idalib_netnode_altval(nodeidx_t num, nodeidx_t idx, int tag) {
  netnode n((nodeidx_t)num);
  return n.altval((nodeidx_t)idx, (char)tag);
}

// Set altval (array) value
bool idalib_netnode_altset(nodeidx_t num, nodeidx_t idx, nodeidx_t value, int tag) {
  netnode n((nodeidx_t)num);
  return n.altset((nodeidx_t)idx, (nodeidx_t)value, (char)tag);
}

// Delete altval
bool idalib_netnode_altdel(nodeidx_t num, nodeidx_t idx, int tag) {
  netnode n((nodeidx_t)num);
  return n.altdel((nodeidx_t)idx, (char)tag);
}

// Get first altval index
nodeidx_t idalib_netnode_altfirst(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.altfirst((char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get next altval index
nodeidx_t idalib_netnode_altnext(nodeidx_t num, nodeidx_t cur, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.altnext((nodeidx_t)cur, (char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get last altval index
nodeidx_t idalib_netnode_altlast(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.altlast((char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Get previous altval index
nodeidx_t idalib_netnode_altprev(nodeidx_t num, nodeidx_t cur, int tag) {
  netnode n((nodeidx_t)num);
  nodeidx_t idx = n.altprev((nodeidx_t)cur, (char)tag);
  if (idx == BADNODE) {
    return BADADDR;
  }
  return (nodeidx_t)idx;
}

// Delete all altvals
bool idalib_netnode_altdel_all(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  return n.altdel_all((char)tag);
}

// Get hashval string value
rust::String idalib_netnode_hashstr(nodeidx_t num, const char *idx, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.hashstr(&buf, idx, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Set hashval string value
bool idalib_netnode_hashset_str(nodeidx_t num, const char *idx, const char *value, int tag) {
  netnode n((nodeidx_t)num);
  return n.hashset(idx, value, strlen(value), (char)tag);
}

// Get hashval long value
nodeidx_t idalib_netnode_hashval_long(nodeidx_t num, const char *idx, int tag) {
  netnode n((nodeidx_t)num);
  return n.hashval_long(idx, (char)tag);
}

// Set hashval long value
bool idalib_netnode_hashset_long(nodeidx_t num, const char *idx, nodeidx_t value, int tag) {
  netnode n((nodeidx_t)num);
  return n.hashset(idx, &value, sizeof(value), (char)tag);
}

// Delete hashval
bool idalib_netnode_hashdel(nodeidx_t num, const char *idx, int tag) {
  netnode n((nodeidx_t)num);
  return n.hashdel(idx, (char)tag);
}

// Get first hash key
rust::String idalib_netnode_hashfirst(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.hashfirst(&buf, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Get next hash key
rust::String idalib_netnode_hashnext(nodeidx_t num, const char *idx, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.hashnext(&buf, idx, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Get last hash key
rust::String idalib_netnode_hashlast(nodeidx_t num, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.hashlast(&buf, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Get previous hash key
rust::String idalib_netnode_hashprev(nodeidx_t num, const char *idx, int tag) {
  netnode n((nodeidx_t)num);
  qstring buf;
  ssize_t len = n.hashprev(&buf, idx, (char)tag);
  if (len < 0) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Enumerate all netnodes
rust::String idalib_enumerate_netnodes(size_t limit) {
  qstring buf;
  size_t count = 0;

  buf.sprnt("Netnodes in database:\n");

  netnode n;
  if (!n.start()) {
    buf.cat_sprnt("  (no netnodes found)\n");
    return rust::String(buf.c_str());
  }

  do {
    qstring name;
    ssize_t name_len = n.get_name(&name);

    buf.cat_sprnt("  [%zu] 0x%" PRIx64, count, uint64_t(n));
    if (name_len >= 0) {
      buf.cat_sprnt(" (%s)", name.c_str());
    }
    buf.cat_sprnt("\n");

    count++;
    if (count >= limit) {
      buf.cat_sprnt("  ... (showing first %zu netnodes)\n", limit);
      break;
    }
  } while (n.next());

  buf.cat_sprnt("\nTotal: %zu netnodes\n", count);
  return rust::String(buf.c_str());
}

// Get detailed netnode information
rust::String idalib_netnode_info(nodeidx_t num) {
  netnode n((nodeidx_t)num);

  if (!exist(n)) {
    return rust::String();
  }

  qstring buf;
  buf.sprnt("Netnode 0x%" PRIx64 ":\n", num);

  // Name
  qstring name;
  ssize_t name_len = n.get_name(&name);
  if (name_len >= 0) {
    buf.cat_sprnt("  Name: %s\n", name.c_str());
  } else {
    buf.cat_sprnt("  Name: (unnamed)\n");
  }

  // Value
  if (n.value_exists()) {
    qstring val;
    ssize_t val_len = n.valstr(&val);
    if (val_len >= 0) {
      buf.cat_sprnt("  Value (string): %s\n", val.c_str());
    } else {
      buf.cat_sprnt("  Value: (binary, %zd bytes)\n", n.valobj(nullptr, 0));
    }
  } else {
    buf.cat_sprnt("  Value: (none)\n");
  }

  return rust::String(buf.c_str());
}
