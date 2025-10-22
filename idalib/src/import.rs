use std::marker::PhantomData;

use crate::Address;
use crate::ffi::nalt::{
    idalib_get_import_module_name, idalib_get_import_module_qty, idalib_get_imports_for_module,
};
use crate::idb::IDB;

#[derive(Debug, Clone)]
pub struct Import {
    pub module_name: String,
    pub function_name: String,
    pub address: Address,
    pub ordinal: u32,
}

/// Iterator over all imports in the database.
///
/// # Performance
///
/// This iterator uses **lazy loading** - it only fetches imports for the current module
/// as needed, rather than loading all imports into memory upfront. This is efficient
/// for binaries with many imports.
///
/// Iteration is done module-by-module: when all imports from one module are exhausted,
/// the iterator moves to the next module.
pub struct ImportIterator<'a> {
    /// Current module index we're iterating through
    current_module_idx: u32,
    /// Total number of import modules
    total_modules: u32,
    /// Iterator over imports in the current module
    current_module_imports: std::vec::IntoIter<Import>,
    /// Phantom data to bind lifetime
    _marker: PhantomData<&'a IDB>,
}

impl<'a> ImportIterator<'a> {
    /// Creates a new import iterator.
    ///
    /// This is a lazy operation - no imports are fetched until iteration begins.
    pub(crate) fn new() -> Self {
        let total_modules = unsafe { idalib_get_import_module_qty() };

        Self {
            current_module_idx: 0,
            total_modules,
            current_module_imports: Vec::new().into_iter(),
            _marker: PhantomData,
        }
    }

    /// Load imports for the current module
    fn load_current_module(&mut self) -> bool {
        if self.current_module_idx >= self.total_modules {
            return false;
        }

        let module_name = unsafe { idalib_get_import_module_name(self.current_module_idx) };

        let mut import_names = Vec::new();
        let mut addresses = Vec::new();
        let mut ordinals = Vec::new();

        unsafe {
            idalib_get_imports_for_module(
                self.current_module_idx,
                &mut import_names,
                &mut addresses,
                &mut ordinals,
            );
        }

        let imports: Vec<Import> = import_names
            .into_iter()
            .zip(addresses)
            .zip(ordinals)
            .map(|((function_name, address), ordinal)| Import {
                module_name: module_name.clone(),
                function_name,
                address,
                ordinal,
            })
            .collect();

        self.current_module_imports = imports.into_iter();
        self.current_module_idx += 1;

        true
    }
}

impl<'a> Iterator for ImportIterator<'a> {
    type Item = Import;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get next import from current module
        if let Some(import) = self.current_module_imports.next() {
            return Some(import);
        }

        // Current module exhausted, try to load next module
        if self.load_current_module() {
            // Recursively call next() to get first import from new module
            self.next()
        } else {
            // No more modules
            None
        }
    }
}
