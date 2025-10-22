#![doc(html_no_source)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_lifetimes)]
#![allow(unsafe_op_in_unsafe_fn)]

use std::path::PathBuf;

use autocxx::prelude::*;
use thiserror::Error;

mod platform;

#[derive(Debug, Error)]
pub enum IDAError {
    #[error(transparent)]
    Ffi(anyhow::Error),
    #[error(transparent)]
    HexRays(#[from] hexrays::HexRaysError),
    #[error("could not initialise IDA: error code {:x}", _0.0)]
    Init(c_int),
    #[error("could not create/open IDA database: input file `{0}` not found")]
    FileNotFound(PathBuf),
    #[error("could not open IDA database: error code {:x}", _0.0)]
    OpenDb(c_int),
    #[error("could not close IDA database: error code {:x}", _0.0)]
    CloseDb(c_int),
    #[error("invalid license")]
    InvalidLicense,
    #[error("could not generate pattern or signature files")]
    MakeSigs,
    #[error("could not get library version")]
    GetVersion,
}

impl IDAError {
    pub fn ffi<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Ffi(anyhow::Error::from(e))
    }

    pub fn ffi_with<M>(m: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Ffi(anyhow::Error::msg(m))
    }

    pub fn not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound(path.into())
    }
}

include_cpp! {
    // NOTE: this fixes autocxx's inability to detect ea_t, optype_t as POD...
    #include "types.h"

    #include "auto.hpp"
    #include "bytes.hpp"
    #include "dbg.hpp"
    #include "demangle.hpp"
    #include "entry.hpp"
    #include "fixup.hpp"
    #include "frame.hpp"
    #include "funcs.hpp"
    #include "gdl.hpp"
    #include "hexrays.hpp"
    #include "ida.hpp"
    #include "idalib.hpp"
    #include "idp.hpp"
    #include "jumptable.hpp"
    #include "loader.hpp"
    #include "moves.hpp"
    #include "nalt.hpp"
    #include "name.hpp"
    #include "offset.hpp"
    #include "pro.h"
    #include "problems.hpp"
    #include "segment.hpp"
    #include "segregs.hpp"
    #include "strlist.hpp"
    #include "tryblks.hpp"
    #include "typeinf.hpp"
    #include "ua.hpp"
    #include "xref.hpp"

    generate!("qstring")

    // generate_pod!("cm_t")
    // generate_pod!("comp_t")
    // generate_pod!("compiler_info_t")
    generate_pod!("ea_t")
    generate_pod!("filetype_t")
    generate_pod!("range_t")
    generate_pod!("uval_t")

    // auto
    generate!("auto_wait")

    // bytes
    generate_pod!("flags64_t")
    generate!("is_data")
    generate!("is_code")
    generate!("get_flags")

    // entry
    generate!("get_entry")
    generate!("get_entry_ordinal")
    generate!("get_entry_qty")

    // idp
    generate!("processor_t")
    generate!("get_ph")
    generate!("is_align_insn")
    generate!("is_basic_block_end")
    generate!("is_call_insn")
    generate!("is_indirect_jump_insn")

    generate!("is_ret_insn")
    generate!("IRI_EXTENDED")
    generate!("IRI_RET_LITERALLY")
    generate!("IRI_SKIP_RETTARGET")
    generate!("IRI_STRICT") // default

    generate!("next_head")
    generate!("prev_head")

    generate!("str2reg")

    // funcs
    generate!("func_t")
    generate!("lock_func")
    generate!("get_func")
    generate!("get_func_num")
    generate!("get_func_qty")
    generate!("getn_func")

    generate!("calc_thunk_func_target")

    generate!("FUNC_NORET")
    generate!("FUNC_FAR")
    generate!("FUNC_LIB")
    generate!("FUNC_STATICDEF")
    generate!("FUNC_FRAME")
    generate!("FUNC_USERFAR")
    generate!("FUNC_HIDDEN")
    generate!("FUNC_THUNK")
    generate!("FUNC_BOTTOMBP")
    generate!("FUNC_NORET_PENDING")
    generate!("FUNC_SP_READY")
    generate!("FUNC_FUZZY_SP")
    generate!("FUNC_PROLOG_OK")
    generate!("FUNC_PURGED_OK")
    generate!("FUNC_TAIL")
    generate!("FUNC_LUMINA")
    generate!("FUNC_OUTLINE")
    generate!("FUNC_REANALYZE")
    generate!("FUNC_RESERVED")

    // gdl
    generate!("qbasic_block_t")
    generate!("qflow_chart_t")
    generate!("gdl_graph_t")
    generate_pod!("fc_block_type_t")

    generate!("FC_PRINT")
    generate!("FC_NOEXT")
    generate!("FC_RESERVED")
    generate!("FC_APPND")
    generate!("FC_CHKBREAK")
    generate!("FC_CALL_ENDS")
    generate!("FC_NOPREDS")
    generate!("FC_OUTLINES")

    // hexrays
    generate!("init_hexrays_plugin")
    generate!("term_hexrays_plugin")

    // generate!("decompile_func")
    generate!("cfuncptr_t")
    generate!("hexrays_failure_t")

    generate_pod!("merror_t")

    /*
    generate!("MERR_OK")
    generate!("MERR_BLOCK")
    generate!("MERR_INTERR")
    generate!("MERR_INSN")
    generate!("MERR_MEM")
    generate!("MERR_BADBLK")
    generate!("MERR_BADSP")
    generate!("MERR_PROLOG")
    generate!("MERR_SWITCH")
    generate!("MERR_EXCEPTION")
    generate!("MERR_HUGESTACK")
    generate!("MERR_LVARS")
    generate!("MERR_BITNESS")
    generate!("MERR_BADCALL")
    generate!("MERR_BADFRAME")
    generate!("MERR_UNKTYPE")
    generate!("MERR_BADIDB")
    generate!("MERR_SIZEOF")
    generate!("MERR_REDO")
    generate!("MERR_CANCELED")
    generate!("MERR_RECDEPTH")
    generate!("MERR_OVERLAP")
    generate!("MERR_PARTINIT")
    generate!("MERR_COMPLEX")
    generate!("MERR_LICENSE")
    generate!("MERR_ONLY")
    generate!("MERR_ONLY")
    generate!("MERR_BUSY")
    generate!("MERR_FARPTR")
    generate!("MERR_EXTERN")
    generate!("MERR_FUNCSIZE")
    generate!("MERR_BADRANGES")
    generate!("MERR_BADARCH")
    generate!("MERR_DSLOT")
    generate!("MERR_STOP")
    generate!("MERR_CLOUD")
    generate!("MERR_MAX_ERR")
    generate!("MERR_LOOP")
    */

    generate!("carg_t")
    generate!("carglist_t")

    extern_cpp_type!("cblock_t", crate::hexrays::cblock_t)
    extern_cpp_type!("cfunc_t", crate::hexrays::cfunc_t)
    extern_cpp_type!("citem_t", crate::hexrays::citem_t)
    extern_cpp_type!("cinsn_t", crate::hexrays::cinsn_t)
    extern_cpp_type!("cexpr_t", crate::hexrays::cexpr_t)
    extern_cpp_type!("cswitch_t", crate::hexrays::cswitch_t)
    extern_cpp_type!("ctry_t", crate::hexrays::ctry_t)
    extern_cpp_type!("cthrow_t", crate::hexrays::cthrow_t)

    // idalib
    generate!("open_database")
    generate!("close_database")

    generate!("make_signatures")
    generate!("enable_console_messages")
    generate!("set_screen_ea")

    // segment
    generate!("segment_t")
    generate!("lock_segment")
    generate!("getseg")
    generate!("getnseg")
    generate!("get_segm_qty")
    generate!("get_segm_by_name")
    generate!("get_first_seg")
    generate!("get_last_seg")
    generate!("get_next_seg")

    generate!("SEG_NORM")
    generate!("SEG_XTRN")
    generate!("SEG_CODE")
    generate!("SEG_DATA")
    generate!("SEG_IMP")
    generate!("SEG_GRP")
    generate!("SEG_NULL")
    generate!("SEG_UNDF")
    generate!("SEG_BSS")
    generate!("SEG_ABSSYM")
    generate!("SEG_COMM")
    generate!("SEG_IMEM")
    generate!("SEG_MAX_SEGTYPE_CODE")

    generate!("saAbs")
    generate!("saRelByte")
    generate!("saRelWord")
    generate!("saRelPara")
    generate!("saRelPage")
    generate!("saRelDble")
    generate!("saRel4K")
    generate!("saGroup")
    generate!("saRel32Bytes")
    generate!("saRel64Bytes")
    generate!("saRelQword")
    generate!("saRel128Bytes")
    generate!("saRel512Bytes")
    generate!("saRel1024Bytes")
    generate!("saRel2048Bytes")
    generate!("saRel_MAX_ALIGN_CODE")

    generate!("SEGPERM_EXEC")
    generate!("SEGPERM_WRITE")
    generate!("SEGPERM_READ")
    generate!("SEGPERM_MAXVAL")

    // ua (we use insn_t, op_t, etc. from pod)
    generate!("decode_insn")
    generate!("print_insn_mnem")

    extern_cpp_type!("insn_t", crate::pod::insn_t)
    extern_cpp_type!("op_t", crate::pod::op_t)

    generate_pod!("optype_t")

    generate!("o_void")
    generate!("o_reg")
    generate!("o_mem")
    generate!("o_phrase")
    generate!("o_displ")
    generate!("o_imm")
    generate!("o_far")
    generate!("o_near")
    generate!("o_idpspec0")
    generate!("o_idpspec1")
    generate!("o_idpspec2")
    generate!("o_idpspec3")
    generate!("o_idpspec4")
    generate!("o_idpspec5")

    generate!("dt_byte")
    generate!("dt_word")
    generate!("dt_dword")
    generate!("dt_float")
    generate!("dt_double")
    generate!("dt_tbyte")
    generate!("dt_packreal")
    generate!("dt_qword")
    generate!("dt_byte16")
    generate!("dt_code")
    generate!("dt_void")
    generate!("dt_fword")
    generate!("dt_bitfild")
    generate!("dt_string")
    generate!("dt_unicode")
    generate!("dt_ldbl")
    generate!("dt_byte32")
    generate!("dt_byte64")
    generate!("dt_half")

    // xref
    generate_pod!("xrefblk_t")

    // NOTE: autocxx fails to generate methods on xrefblk_t...
    generate!("xrefblk_t_first_from")
    generate!("xrefblk_t_next_from")
    generate!("xrefblk_t_first_to")
    generate!("xrefblk_t_next_to")

    generate!("XREF_ALL")
    generate!("XREF_FAR")
    generate!("XREF_DATA")

    generate!("cref_t")
    generate!("dref_t")

    generate!("XREF_USER")
    generate!("XREF_TAIL")
    generate!("XREF_BASE")
    generate!("XREF_MASK")
    generate!("XREF_PASTEND")

    generate!("has_external_refs")
    generate!("get_first_dref_to")
    generate!("get_next_dref_to")

    // comments
    generate!("set_cmt")
    generate!("append_cmt")

    // strings
    generate!("build_strlist")
    generate!("clear_strlist")
    generate!("get_strlist_qty")

    // loader
    generate!("plugin_t")
    generate!("find_plugin")
    generate!("run_plugin")

    generate!("PLUGIN_MOD")
    generate!("PLUGIN_DRAW")
    generate!("PLUGIN_SEG")
    generate!("PLUGIN_UNL")
    generate!("PLUGIN_HIDE")
    generate!("PLUGIN_DBG")
    generate!("PLUGIN_PROC")
    generate!("PLUGIN_FIX")
    generate!("PLUGIN_MULTI")
    generate!("PLUGIN_SCRIPTED")

    // nalt
    generate!("retrieve_input_file_md5")
    generate!("retrieve_input_file_sha256")
    generate!("retrieve_input_file_size")

    // name(s)
    generate!("get_nlist_idx")
    generate!("get_nlist_size")
    generate!("get_nlist_ea")
    generate!("get_nlist_name")
    generate!("is_in_nlist")
    generate!("is_public_name")
    generate!("is_weak_name")

    // name flags
    generate!("SN_CHECK")
    generate!("SN_NOCHECK")
    generate!("SN_PUBLIC")
    generate!("SN_NON_PUBLIC")
    generate!("SN_WEAK")
    generate!("SN_NON_WEAK")
    generate!("SN_AUTO")
    generate!("SN_NON_AUTO")
    generate!("SN_NOLIST")
    generate!("SN_NOWARN")
    generate!("SN_LOCAL")
    generate!("SN_IDBENC")
    generate!("SN_FORCE")
    generate!("SN_NODUMMY")
    generate!("SN_DELTAIL")
}

pub mod hexrays {
    use std::mem;

    use thiserror::Error;

    // NOTE: we don't export it; ideally this conversion should exist in idalib (not -sys), but it
    // having the conversion here gives us a cleaner interface.
    use super::ffi::merror_t;

    #[derive(Debug, Error)]
    #[error("{desc}")]
    pub struct HexRaysError {
        code: HexRaysErrorCode,
        addr: u64,
        desc: String,
    }

    impl HexRaysError {
        pub fn code(&self) -> HexRaysErrorCode {
            self.code
        }

        pub fn address(&self) -> u64 {
            self.addr
        }

        pub fn reason(&self) -> &str {
            &self.desc
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum HexRaysErrorCode {
        Ok,
        Block,
        Internal,
        Insn,
        Mem,
        BadBlock,
        BadSp,
        Prolog,
        Switch,
        Exception,
        HugeStack,
        LVars,
        Bitness,
        BadCall,
        BadFrame,
        UnknownType,
        BadIDB,
        SizeOf,
        Redo,
        Cancelled,
        RecursionDepth,
        Overlap,
        PartInitVar,
        Complex,
        License,
        Only32,
        Only64,
        Busy,
        FarPtr,
        Extern,
        FuncSize,
        BadRanges,
        BadArch,
        DelaySlot,
        Stop,
        Cloud,
        Loop,
        Unknown,
    }

    impl HexRaysErrorCode {
        pub fn is_ok(&self) -> bool {
            matches!(self, Self::Ok | Self::Block)
        }

        pub fn is_err(&self) -> bool {
            !self.is_ok()
        }
    }

    impl From<merror_t> for HexRaysErrorCode {
        fn from(value: merror_t) -> Self {
            match value {
                merror_t::MERR_OK => Self::Ok,
                merror_t::MERR_BLOCK => Self::Block,
                merror_t::MERR_INTERR => Self::Internal,
                merror_t::MERR_INSN => Self::Insn,
                merror_t::MERR_MEM => Self::Mem,
                merror_t::MERR_BADBLK => Self::BadBlock,
                merror_t::MERR_BADSP => Self::BadSp,
                merror_t::MERR_PROLOG => Self::Prolog,
                merror_t::MERR_SWITCH => Self::Switch,
                merror_t::MERR_EXCEPTION => Self::Exception,
                merror_t::MERR_HUGESTACK => Self::HugeStack,
                merror_t::MERR_LVARS => Self::LVars,
                merror_t::MERR_BITNESS => Self::Bitness,
                merror_t::MERR_BADCALL => Self::BadCall,
                merror_t::MERR_BADFRAME => Self::BadFrame,
                merror_t::MERR_UNKTYPE => Self::UnknownType,
                merror_t::MERR_BADIDB => Self::BadIDB,
                merror_t::MERR_SIZEOF => Self::SizeOf,
                merror_t::MERR_REDO => Self::Redo,
                merror_t::MERR_CANCELED => Self::Cancelled,
                merror_t::MERR_RECDEPTH => Self::RecursionDepth,
                merror_t::MERR_OVERLAP => Self::Overlap,
                merror_t::MERR_PARTINIT => Self::PartInitVar,
                merror_t::MERR_COMPLEX => Self::Complex,
                merror_t::MERR_LICENSE => Self::License,
                merror_t::MERR_ONLY32 => Self::Only32,
                merror_t::MERR_ONLY64 => Self::Only64,
                merror_t::MERR_BUSY => Self::Busy,
                merror_t::MERR_FARPTR => Self::FarPtr,
                merror_t::MERR_EXTERN => Self::Extern,
                merror_t::MERR_FUNCSIZE => Self::FuncSize,
                merror_t::MERR_BADRANGES => Self::BadRanges,
                merror_t::MERR_BADARCH => Self::BadArch,
                merror_t::MERR_DSLOT => Self::DelaySlot,
                merror_t::MERR_STOP => Self::Stop,
                merror_t::MERR_CLOUD => Self::Cloud,
                merror_t::MERR_LOOP => Self::Loop,
                _ => Self::Unknown,
            }
        }
    }

    mod __impl {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]
        #![allow(rustdoc::all)]

        include!(concat!(env!("OUT_DIR"), "/hexrays.rs"));
    }

    pub use __impl::{cblock_t, cexpr_t, cfunc_t, cinsn_t, citem_t, cswitch_t, cthrow_t, ctry_t};

    pub use super::ffi::{
        carg_t, carglist_t, cfuncptr_t, init_hexrays_plugin, term_hexrays_plugin,
    };
    pub use super::ffix::{
        cblock_iter, idalib_hexrays_cblock_iter, idalib_hexrays_cblock_iter_next,
        idalib_hexrays_cblock_len, idalib_hexrays_cfunc_pseudocode, idalib_hexrays_cfuncptr_inner,
        idalib_hexrays_decompile_func,
    };

    unsafe impl cxx::ExternType for cfunc_t {
        type Id = cxx::type_id!("cfunc_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for citem_t {
        type Id = cxx::type_id!("citem_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cinsn_t {
        type Id = cxx::type_id!("cinsn_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cexpr_t {
        type Id = cxx::type_id!("cexpr_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cblock_t {
        type Id = cxx::type_id!("cblock_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cswitch_t {
        type Id = cxx::type_id!("cswitch_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cthrow_t {
        type Id = cxx::type_id!("cthrow_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for ctry_t {
        type Id = cxx::type_id!("ctry_t");
        type Kind = cxx::kind::Opaque;
    }

    pub unsafe fn decompile_func(
        f: *mut super::ffi::func_t,
        all_blocks: bool,
    ) -> Result<cxx::UniquePtr<cfuncptr_t>, HexRaysError> {
        let mut flags = __impl::DECOMP_NO_WAIT | __impl::DECOMP_NO_CACHE;

        if all_blocks {
            flags |= __impl::DECOMP_ALL_BLKS;
        }

        let mut failure = super::ffix::hexrays_error_t::default();
        let result = super::ffix::idalib_hexrays_decompile_func(
            f,
            &mut failure as *mut _,
            (flags as i32).into(),
        );

        let code = HexRaysErrorCode::from(mem::transmute::<i32, merror_t>(failure.code));

        if result.is_null() || code.is_err() {
            Err(HexRaysError {
                addr: failure.addr,
                code,
                desc: failure.desc,
            })
        } else {
            Ok(result)
        }
    }
}

pub mod idp {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/idp.rs"));
}

pub mod inf {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/inf.rs"));

    unsafe impl cxx::ExternType for compiler_info_t {
        type Id = cxx::type_id!("compiler_info_t");
        type Kind = cxx::kind::Trivial;
    }

    pub use super::ffi::filetype_t;
    pub use super::ffix::{
        idalib_inf_abi_set_by_user, idalib_inf_allow_non_matched_ops, idalib_inf_allow_sigmulti,
        idalib_inf_append_sigcmt, idalib_inf_big_arg_align, idalib_inf_check_manual_ops,
        idalib_inf_check_unicode_strlits, idalib_inf_coagulate_code, idalib_inf_coagulate_data,
        idalib_inf_compress_idb, idalib_inf_create_all_xrefs, idalib_inf_create_func_from_call,
        idalib_inf_create_func_from_ptr, idalib_inf_create_func_tails,
        idalib_inf_create_jump_tables, idalib_inf_create_off_on_dref,
        idalib_inf_create_off_using_fixup, idalib_inf_create_strlit_on_xref,
        idalib_inf_data_offset, idalib_inf_dbg_no_store_path, idalib_inf_decode_fpp,
        idalib_inf_final_pass, idalib_inf_full_sp_ana, idalib_inf_gen_assume, idalib_inf_gen_lzero,
        idalib_inf_gen_null, idalib_inf_gen_org, idalib_inf_gen_tryblks, idalib_inf_get_abibits,
        idalib_inf_get_af, idalib_inf_get_af2, idalib_inf_get_app_bitness,
        idalib_inf_get_appcall_options, idalib_inf_get_apptype, idalib_inf_get_asmtype,
        idalib_inf_get_baseaddr, idalib_inf_get_bin_prefix_size, idalib_inf_get_cc,
        idalib_inf_get_cc_cm, idalib_inf_get_cc_defalign, idalib_inf_get_cc_id,
        idalib_inf_get_cc_size_b, idalib_inf_get_cc_size_e, idalib_inf_get_cc_size_i,
        idalib_inf_get_cc_size_l, idalib_inf_get_cc_size_ldbl, idalib_inf_get_cc_size_ll,
        idalib_inf_get_cc_size_s, idalib_inf_get_cmt_indent, idalib_inf_get_cmtflg,
        idalib_inf_get_database_change_count, idalib_inf_get_datatypes, idalib_inf_get_demnames,
        idalib_inf_get_filetype, idalib_inf_get_genflags, idalib_inf_get_highoff,
        idalib_inf_get_indent, idalib_inf_get_lenxref, idalib_inf_get_lflags,
        idalib_inf_get_limiter, idalib_inf_get_listnames, idalib_inf_get_long_demnames,
        idalib_inf_get_lowoff, idalib_inf_get_main, idalib_inf_get_margin,
        idalib_inf_get_max_autoname_len, idalib_inf_get_max_ea, idalib_inf_get_maxref,
        idalib_inf_get_min_ea, idalib_inf_get_nametype, idalib_inf_get_netdelta,
        idalib_inf_get_omax_ea, idalib_inf_get_omin_ea, idalib_inf_get_ostype,
        idalib_inf_get_outflags, idalib_inf_get_prefflag, idalib_inf_get_privrange,
        idalib_inf_get_privrange_end_ea, idalib_inf_get_privrange_start_ea,
        idalib_inf_get_procname, idalib_inf_get_refcmtnum, idalib_inf_get_short_demnames,
        idalib_inf_get_specsegs, idalib_inf_get_start_cs, idalib_inf_get_start_ea,
        idalib_inf_get_start_ip, idalib_inf_get_start_sp, idalib_inf_get_start_ss,
        idalib_inf_get_strlit_break, idalib_inf_get_strlit_flags, idalib_inf_get_strlit_pref,
        idalib_inf_get_strlit_sernum, idalib_inf_get_strlit_zeroes, idalib_inf_get_strtype,
        idalib_inf_get_type_xrefnum, idalib_inf_get_version, idalib_inf_get_xrefflag,
        idalib_inf_get_xrefnum, idalib_inf_guess_func_type, idalib_inf_handle_eh,
        idalib_inf_handle_rtti, idalib_inf_hide_comments, idalib_inf_hide_libfuncs,
        idalib_inf_huge_arg_align, idalib_inf_is_16bit, idalib_inf_is_32bit_exactly,
        idalib_inf_is_32bit_or_higher, idalib_inf_is_64bit, idalib_inf_is_auto_enabled,
        idalib_inf_is_be, idalib_inf_is_dll, idalib_inf_is_flat_off32, idalib_inf_is_graph_view,
        idalib_inf_is_hard_float, idalib_inf_is_kernel_mode, idalib_inf_is_limiter_empty,
        idalib_inf_is_limiter_thick, idalib_inf_is_limiter_thin, idalib_inf_is_mem_aligned4,
        idalib_inf_is_snapshot, idalib_inf_is_wide_high_byte_first, idalib_inf_line_pref_with_seg,
        idalib_inf_loading_idc, idalib_inf_macros_enabled, idalib_inf_map_stkargs,
        idalib_inf_mark_code, idalib_inf_merge_strlits, idalib_inf_no_store_user_info,
        idalib_inf_noflow_to_data, idalib_inf_noret_ana, idalib_inf_op_offset, idalib_inf_pack_idb,
        idalib_inf_pack_stkargs, idalib_inf_prefix_show_funcoff, idalib_inf_prefix_show_segaddr,
        idalib_inf_prefix_show_stack, idalib_inf_prefix_truncate_opcode_bytes,
        idalib_inf_propagate_regargs, idalib_inf_propagate_stkargs, idalib_inf_readonly_idb,
        idalib_inf_rename_jumpfunc, idalib_inf_rename_nullsub, idalib_inf_set_show_all_comments,
        idalib_inf_set_show_hidden_funcs, idalib_inf_set_show_hidden_insns,
        idalib_inf_set_show_hidden_segms, idalib_inf_should_create_stkvars,
        idalib_inf_should_trace_sp, idalib_inf_show_all_comments, idalib_inf_show_auto,
        idalib_inf_show_hidden_funcs, idalib_inf_show_hidden_insns, idalib_inf_show_hidden_segms,
        idalib_inf_show_line_pref, idalib_inf_show_repeatables, idalib_inf_show_src_linnum,
        idalib_inf_show_void, idalib_inf_show_xref_fncoff, idalib_inf_show_xref_seg,
        idalib_inf_show_xref_tmarks, idalib_inf_show_xref_val, idalib_inf_stack_ldbl,
        idalib_inf_stack_varargs, idalib_inf_strlit_autocmt, idalib_inf_strlit_name_bit,
        idalib_inf_strlit_names, idalib_inf_strlit_savecase, idalib_inf_strlit_serial_names,
        idalib_inf_test_mode, idalib_inf_trace_flow, idalib_inf_truncate_on_del,
        idalib_inf_unicode_strlits, idalib_inf_use_allasm, idalib_inf_use_flirt,
        idalib_inf_use_gcc_layout,
    };
}

pub mod pod {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/pod.rs"));

    unsafe impl cxx::ExternType for op_t {
        type Id = cxx::type_id!("op_t");
        type Kind = cxx::kind::Trivial;
    }

    unsafe impl cxx::ExternType for insn_t {
        type Id = cxx::type_id!("insn_t");
        type Kind = cxx::kind::Trivial;
    }
}

#[cxx::bridge]
mod ffix {
    #[derive(Default)]
    struct hexrays_error_t {
        code: i32,
        addr: u64,
        desc: String,
    }

    unsafe extern "C++" {
        include!("autocxxgen_ffi.h");
        include!("idalib.hpp");

        include!("types.h");
        include!("bookmarks_extras.h");
        include!("bytes_extras.h");
        include!("comments_extras.h");
        include!("dbg_extras.h");
        include!("demangle_extras.h");
        include!("entry_extras.h");
        include!("fixup_extras.h");
        include!("frame_extras.h");
        include!("func_extras.h");
        include!("hexrays_extras.h");
        include!("idalib_extras.h");
        include!("inf_extras.h");
        include!("jumptable_extras.h");
        include!("kernwin_extras.h");
        include!("loader_extras.h");
        include!("nalt_extras.h");
        include!("offset_extras.h");
        include!("ph_extras.h");
        include!("name_extras.h");
        include!("problems_extras.h");
        include!("segm_extras.h");
        include!("search_extras.h");
        include!("segregs_extras.h");
        include!("strings_extras.h");
        include!("tryblks_extras.h");
        include!("typeinf_extras.h");

        type c_short = autocxx::c_short;
        type c_int = autocxx::c_int;
        type c_uint = autocxx::c_uint;
        type c_longlong = autocxx::c_longlong;
        type c_ulonglong = autocxx::c_ulonglong;

        // type comp_t = super::ffi::comp_t;
        type compiler_info_t = super::inf::compiler_info_t;
        // type cm_t = super::ffi::cm_t;
        type filetype_t = super::ffi::filetype_t;
        type range_t = super::ffi::range_t;
        // type uval_t = autocxx::c_ulonglong;

        type func_t = super::ffi::func_t;
        type processor_t = super::ffi::processor_t;
        type qflow_chart_t = super::ffi::qflow_chart_t;
        type qbasic_block_t = super::ffi::qbasic_block_t;
        type segment_t = super::ffi::segment_t;

        // cfuncptr_t
        type qrefcnt_t_cfunc_t_AutocxxConcrete = super::ffi::qrefcnt_t_cfunc_t_AutocxxConcrete;
        type cfunc_t = super::hexrays::cfunc_t;
        type cblock_t = super::hexrays::cblock_t;
        type cinsn_t = super::hexrays::cinsn_t;

        type cblock_iter;

        type plugin_t = super::ffi::plugin_t;

        unsafe fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;

        unsafe fn idalib_open_database_quiet(
            argc: c_int,
            argv: *const *const c_char,
            auto_analysis: bool,
        ) -> c_int;
        unsafe fn idalib_check_license() -> bool;
        unsafe fn idalib_get_license_id(id: &mut [u8; 6]) -> bool;

        // NOTE: we can't use uval_t here due to it resolving to c_ulonglong,
        // which causes `verify_extern_type` to fail...
        unsafe fn idalib_entry_name(e: c_ulonglong) -> Result<String>;

        unsafe fn idalib_func_flags(f: *const func_t) -> u64;
        unsafe fn idalib_func_name(f: *const func_t) -> Result<String>;

        unsafe fn idalib_func_flow_chart(
            f: *mut func_t,
            flags: c_int,
        ) -> Result<UniquePtr<qflow_chart_t>>;

        unsafe fn idalib_hexrays_cfuncptr_inner(
            f: *const qrefcnt_t_cfunc_t_AutocxxConcrete,
        ) -> *mut cfunc_t;
        unsafe fn idalib_hexrays_cfunc_pseudocode(f: *mut cfunc_t) -> String;

        unsafe fn idalib_hexrays_decompile_func(
            f: *mut func_t,
            err: *mut hexrays_error_t,
            flags: c_int,
        ) -> UniquePtr<qrefcnt_t_cfunc_t_AutocxxConcrete>;

        unsafe fn idalib_hexrays_cblock_iter(b: *mut cblock_t) -> UniquePtr<cblock_iter>;
        unsafe fn idalib_hexrays_cblock_iter_next(slf: Pin<&mut cblock_iter>) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cblock_len(b: *mut cblock_t) -> usize;

        unsafe fn idalib_inf_get_version() -> u16;
        unsafe fn idalib_inf_get_genflags() -> u16;
        unsafe fn idalib_inf_is_auto_enabled() -> bool;
        unsafe fn idalib_inf_use_allasm() -> bool;
        unsafe fn idalib_inf_loading_idc() -> bool;
        unsafe fn idalib_inf_no_store_user_info() -> bool;
        unsafe fn idalib_inf_readonly_idb() -> bool;
        unsafe fn idalib_inf_check_manual_ops() -> bool;
        unsafe fn idalib_inf_allow_non_matched_ops() -> bool;
        unsafe fn idalib_inf_is_graph_view() -> bool;
        unsafe fn idalib_inf_get_lflags() -> u32;
        unsafe fn idalib_inf_decode_fpp() -> bool;
        unsafe fn idalib_inf_is_32bit_or_higher() -> bool;
        unsafe fn idalib_inf_is_32bit_exactly() -> bool;
        unsafe fn idalib_inf_is_16bit() -> bool;
        unsafe fn idalib_inf_is_64bit() -> bool;
        unsafe fn idalib_inf_is_dll() -> bool;
        unsafe fn idalib_inf_is_flat_off32() -> bool;
        unsafe fn idalib_inf_is_be() -> bool;
        unsafe fn idalib_inf_is_wide_high_byte_first() -> bool;
        unsafe fn idalib_inf_dbg_no_store_path() -> bool;
        unsafe fn idalib_inf_is_snapshot() -> bool;
        unsafe fn idalib_inf_pack_idb() -> bool;
        unsafe fn idalib_inf_compress_idb() -> bool;
        unsafe fn idalib_inf_is_kernel_mode() -> bool;
        unsafe fn idalib_inf_get_app_bitness() -> c_uint;
        unsafe fn idalib_inf_get_database_change_count() -> u32;
        unsafe fn idalib_inf_get_filetype() -> filetype_t;
        unsafe fn idalib_inf_get_ostype() -> u16;
        unsafe fn idalib_inf_get_apptype() -> u16;
        unsafe fn idalib_inf_get_asmtype() -> u8;
        unsafe fn idalib_inf_get_specsegs() -> u8;
        unsafe fn idalib_inf_get_af() -> u32;
        unsafe fn idalib_inf_trace_flow() -> bool;
        unsafe fn idalib_inf_mark_code() -> bool;
        unsafe fn idalib_inf_create_jump_tables() -> bool;
        unsafe fn idalib_inf_noflow_to_data() -> bool;
        unsafe fn idalib_inf_create_all_xrefs() -> bool;
        unsafe fn idalib_inf_create_func_from_ptr() -> bool;
        unsafe fn idalib_inf_create_func_from_call() -> bool;
        unsafe fn idalib_inf_create_func_tails() -> bool;
        unsafe fn idalib_inf_should_create_stkvars() -> bool;
        unsafe fn idalib_inf_propagate_stkargs() -> bool;
        unsafe fn idalib_inf_propagate_regargs() -> bool;
        unsafe fn idalib_inf_should_trace_sp() -> bool;
        unsafe fn idalib_inf_full_sp_ana() -> bool;
        unsafe fn idalib_inf_noret_ana() -> bool;
        unsafe fn idalib_inf_guess_func_type() -> bool;
        unsafe fn idalib_inf_truncate_on_del() -> bool;
        unsafe fn idalib_inf_create_strlit_on_xref() -> bool;
        unsafe fn idalib_inf_check_unicode_strlits() -> bool;
        unsafe fn idalib_inf_create_off_using_fixup() -> bool;
        unsafe fn idalib_inf_create_off_on_dref() -> bool;
        unsafe fn idalib_inf_op_offset() -> bool;
        unsafe fn idalib_inf_data_offset() -> bool;
        unsafe fn idalib_inf_use_flirt() -> bool;
        unsafe fn idalib_inf_append_sigcmt() -> bool;
        unsafe fn idalib_inf_allow_sigmulti() -> bool;
        unsafe fn idalib_inf_hide_libfuncs() -> bool;
        unsafe fn idalib_inf_rename_jumpfunc() -> bool;
        unsafe fn idalib_inf_rename_nullsub() -> bool;
        unsafe fn idalib_inf_coagulate_data() -> bool;
        unsafe fn idalib_inf_coagulate_code() -> bool;
        unsafe fn idalib_inf_final_pass() -> bool;
        unsafe fn idalib_inf_get_af2() -> u32;
        unsafe fn idalib_inf_handle_eh() -> bool;
        unsafe fn idalib_inf_handle_rtti() -> bool;
        unsafe fn idalib_inf_macros_enabled() -> bool;
        unsafe fn idalib_inf_merge_strlits() -> bool;
        unsafe fn idalib_inf_get_baseaddr() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ss() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_cs() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ip() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_sp() -> c_ulonglong;
        unsafe fn idalib_inf_get_main() -> c_ulonglong;
        unsafe fn idalib_inf_get_min_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_max_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omin_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omax_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_lowoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_highoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_maxref() -> c_ulonglong;
        unsafe fn idalib_inf_get_netdelta() -> c_longlong;
        unsafe fn idalib_inf_get_xrefnum() -> u8;
        unsafe fn idalib_inf_get_type_xrefnum() -> u8;
        unsafe fn idalib_inf_get_refcmtnum() -> u8;
        unsafe fn idalib_inf_get_xrefflag() -> u8;
        unsafe fn idalib_inf_show_xref_seg() -> bool;
        unsafe fn idalib_inf_show_xref_tmarks() -> bool;
        unsafe fn idalib_inf_show_xref_fncoff() -> bool;
        unsafe fn idalib_inf_show_xref_val() -> bool;
        unsafe fn idalib_inf_get_max_autoname_len() -> u16;
        unsafe fn idalib_inf_get_nametype() -> c_char;
        unsafe fn idalib_inf_get_short_demnames() -> u32;
        unsafe fn idalib_inf_get_long_demnames() -> u32;
        unsafe fn idalib_inf_get_demnames() -> u8;
        unsafe fn idalib_inf_get_listnames() -> u8;
        unsafe fn idalib_inf_get_indent() -> u8;
        unsafe fn idalib_inf_get_cmt_indent() -> u8;
        unsafe fn idalib_inf_get_margin() -> u16;
        unsafe fn idalib_inf_get_lenxref() -> u16;
        unsafe fn idalib_inf_get_outflags() -> u32;
        unsafe fn idalib_inf_show_void() -> bool;
        unsafe fn idalib_inf_show_auto() -> bool;
        unsafe fn idalib_inf_gen_null() -> bool;
        unsafe fn idalib_inf_show_line_pref() -> bool;
        unsafe fn idalib_inf_line_pref_with_seg() -> bool;
        unsafe fn idalib_inf_gen_lzero() -> bool;
        unsafe fn idalib_inf_gen_org() -> bool;
        unsafe fn idalib_inf_gen_assume() -> bool;
        unsafe fn idalib_inf_gen_tryblks() -> bool;
        unsafe fn idalib_inf_get_cmtflg() -> u8;
        unsafe fn idalib_inf_show_repeatables() -> bool;
        unsafe fn idalib_inf_show_all_comments() -> bool;
        unsafe fn idalib_inf_set_show_all_comments() -> bool;
        unsafe fn idalib_inf_hide_comments() -> bool;
        unsafe fn idalib_inf_show_src_linnum() -> bool;
        unsafe fn idalib_inf_test_mode() -> bool;
        unsafe fn idalib_inf_show_hidden_insns() -> bool;
        unsafe fn idalib_inf_set_show_hidden_insns() -> bool;
        unsafe fn idalib_inf_show_hidden_funcs() -> bool;
        unsafe fn idalib_inf_set_show_hidden_funcs() -> bool;
        unsafe fn idalib_inf_show_hidden_segms() -> bool;
        unsafe fn idalib_inf_set_show_hidden_segms() -> bool;
        unsafe fn idalib_inf_get_limiter() -> u8;
        unsafe fn idalib_inf_is_limiter_thin() -> bool;
        unsafe fn idalib_inf_is_limiter_thick() -> bool;
        unsafe fn idalib_inf_is_limiter_empty() -> bool;
        unsafe fn idalib_inf_get_bin_prefix_size() -> c_short;
        unsafe fn idalib_inf_get_prefflag() -> u8;
        unsafe fn idalib_inf_prefix_show_segaddr() -> bool;
        unsafe fn idalib_inf_prefix_show_funcoff() -> bool;
        unsafe fn idalib_inf_prefix_show_stack() -> bool;
        unsafe fn idalib_inf_prefix_truncate_opcode_bytes() -> bool;
        unsafe fn idalib_inf_get_strlit_flags() -> u8;
        unsafe fn idalib_inf_strlit_names() -> bool;
        unsafe fn idalib_inf_strlit_name_bit() -> bool;
        unsafe fn idalib_inf_strlit_serial_names() -> bool;
        unsafe fn idalib_inf_unicode_strlits() -> bool;
        unsafe fn idalib_inf_strlit_autocmt() -> bool;
        unsafe fn idalib_inf_strlit_savecase() -> bool;
        unsafe fn idalib_inf_get_strlit_break() -> u8;
        unsafe fn idalib_inf_get_strlit_zeroes() -> c_char;
        unsafe fn idalib_inf_get_strtype() -> i32;
        unsafe fn idalib_inf_get_strlit_sernum() -> c_ulonglong;
        unsafe fn idalib_inf_get_datatypes() -> c_ulonglong;
        unsafe fn idalib_inf_get_abibits() -> u32;
        unsafe fn idalib_inf_is_mem_aligned4() -> bool;
        unsafe fn idalib_inf_pack_stkargs() -> bool;
        unsafe fn idalib_inf_big_arg_align() -> bool;
        unsafe fn idalib_inf_stack_ldbl() -> bool;
        unsafe fn idalib_inf_stack_varargs() -> bool;
        unsafe fn idalib_inf_is_hard_float() -> bool;
        unsafe fn idalib_inf_abi_set_by_user() -> bool;
        unsafe fn idalib_inf_use_gcc_layout() -> bool;
        unsafe fn idalib_inf_map_stkargs() -> bool;
        unsafe fn idalib_inf_huge_arg_align() -> bool;
        unsafe fn idalib_inf_get_appcall_options() -> u32;
        unsafe fn idalib_inf_get_privrange_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_privrange_end_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_cc_id() -> u8;
        unsafe fn idalib_inf_get_cc_cm() -> u8;
        unsafe fn idalib_inf_get_cc_size_i() -> u8;
        unsafe fn idalib_inf_get_cc_size_b() -> u8;
        unsafe fn idalib_inf_get_cc_size_e() -> u8;
        unsafe fn idalib_inf_get_cc_defalign() -> u8;
        unsafe fn idalib_inf_get_cc_size_s() -> u8;
        unsafe fn idalib_inf_get_cc_size_l() -> u8;
        unsafe fn idalib_inf_get_cc_size_ll() -> u8;
        unsafe fn idalib_inf_get_cc_size_ldbl() -> u8;
        unsafe fn idalib_inf_get_procname() -> String;
        unsafe fn idalib_inf_get_strlit_pref() -> String;
        unsafe fn idalib_inf_get_cc(out: *mut compiler_info_t) -> bool;
        unsafe fn idalib_inf_get_privrange(out: *mut range_t) -> bool;

        unsafe fn idalib_ph_id(ph: *const processor_t) -> i32;
        unsafe fn idalib_ph_short_name(ph: *const processor_t) -> String;
        unsafe fn idalib_ph_long_name(ph: *const processor_t) -> String;
        unsafe fn idalib_is_thumb_at(ph: *const processor_t, ea: c_ulonglong) -> bool;

        unsafe fn idalib_get_insn_mnem(ea: c_ulonglong) -> String;

        unsafe fn idalib_qflow_graph_getn_block(
            f: *const qflow_chart_t,
            n: usize,
        ) -> *const qbasic_block_t;

        unsafe fn idalib_qbasic_block_succs<'a>(b: *const qbasic_block_t) -> &'a [c_int];
        unsafe fn idalib_qbasic_block_preds<'a>(b: *const qbasic_block_t) -> &'a [c_int];

        unsafe fn idalib_segm_name(s: *const segment_t) -> Result<String>;
        unsafe fn idalib_segm_bytes(s: *const segment_t, buf: &mut Vec<u8>) -> Result<usize>;
        unsafe fn idalib_segm_align(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_perm(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_bitness(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_type(s: *const segment_t) -> u8;

        unsafe fn idalib_get_cmt(ea: c_ulonglong, rptble: bool) -> String;

        unsafe fn idalib_bookmarks_t_mark(
            ea: c_ulonglong,
            index: c_uint,
            desc: *const c_char,
        ) -> u32;
        unsafe fn idalib_bookmarks_t_get_desc(index: c_uint) -> String;
        unsafe fn idalib_bookmarks_t_get(index: c_uint) -> c_ulonglong;
        unsafe fn idalib_bookmarks_t_erase(index: c_uint) -> bool;
        unsafe fn idalib_bookmarks_t_size() -> u32;
        unsafe fn idalib_bookmarks_t_find_index(ea: c_ulonglong) -> u32;

        unsafe fn idalib_find_text(ea: c_ulonglong, text: *const c_char) -> c_ulonglong;
        unsafe fn idalib_find_imm(ea: c_ulonglong, imm: c_uint) -> c_ulonglong;
        unsafe fn idalib_find_defined(ea: c_ulonglong) -> c_ulonglong;

        unsafe fn idalib_bin_search(
            start_ea: c_ulonglong,
            end_ea: c_ulonglong,
            pattern: *const c_char,
            flags: c_int,
        ) -> c_ulonglong;
        unsafe fn idalib_parse_binpat_str(
            pattern: *const c_char,
            out_bytes: &mut Vec<u8>,
            out_mask: &mut Vec<u8>,
        ) -> bool;
        unsafe fn idalib_find_binary(
            start_ea: c_ulonglong,
            end_ea: c_ulonglong,
            bytes: *const u8,
            mask: *const u8,
            len: usize,
        ) -> c_ulonglong;

        unsafe fn idalib_get_strlist_item_addr(index: usize) -> c_ulonglong;
        unsafe fn idalib_get_strlist_item_length(index: usize) -> usize;
        unsafe fn idalib_get_strlit_contents(ea: c_ulonglong, len: usize, strtype: i32) -> String;
        unsafe fn idalib_get_max_strlit_length(ea: c_ulonglong, strtype: i32) -> usize;

        unsafe fn idalib_ea2str(ea: c_ulonglong) -> String;

        unsafe fn idalib_get_byte(ea: c_ulonglong) -> u8;
        unsafe fn idalib_get_word(ea: c_ulonglong) -> u16;
        unsafe fn idalib_get_dword(ea: c_ulonglong) -> u32;
        unsafe fn idalib_get_qword(ea: c_ulonglong) -> u64;
        unsafe fn idalib_get_bytes(ea: c_ulonglong, buf: &mut Vec<u8>) -> Result<usize>;
        unsafe fn idalib_is_loaded(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_mapped(ea: c_ulonglong) -> bool;

        unsafe fn idalib_get_input_file_path() -> String;

        unsafe fn idalib_get_imports(
            module_name: &mut Vec<String>,
            import_names: &mut Vec<String>,
            addresses: &mut Vec<u64>,
            ordinals: &mut Vec<u32>,
        ) -> bool;

        unsafe fn idalib_plugin_version(p: *const plugin_t) -> u64;
        unsafe fn idalib_plugin_flags(p: *const plugin_t) -> u64;

        unsafe fn idalib_get_library_version(
            major: *mut c_int,
            minor: *mut c_int,
            build: *mut c_int,
        ) -> bool;
        unsafe fn idalib_get_ea_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_set_ea_name(ea: c_ulonglong, name: *const c_char, flags: i32) -> bool;
        unsafe fn idalib_force_ea_name(ea: c_ulonglong, name: *const c_char) -> bool;
        unsafe fn idalib_del_global_name(ea: c_ulonglong) -> bool;
        unsafe fn idalib_del_local_name(ea: c_ulonglong) -> bool;

        // Type info functions
        unsafe fn idalib_get_tinfo(ea: c_ulonglong) -> String;
        unsafe fn idalib_set_tinfo_from_string(ea: c_ulonglong, decl: *const c_char) -> bool;
        unsafe fn idalib_del_tinfo(ea: c_ulonglong) -> bool;
        unsafe fn idalib_print_type(ea: c_ulonglong, prtype_flags: c_int) -> String;
        unsafe fn idalib_parse_decl_type(decl: *const c_char) -> String;
        unsafe fn idalib_parse_decl_name(decl: *const c_char) -> String;
        unsafe fn idalib_get_named_type(name: *const c_char) -> String;
        unsafe fn idalib_set_named_type(name: *const c_char, decl: *const c_char) -> bool;
        unsafe fn idalib_get_numbered_type(ordinal: u32) -> String;
        unsafe fn idalib_get_func_tinfo(ea: c_ulonglong) -> String;
        unsafe fn idalib_guess_func_tinfo(ea: c_ulonglong) -> String;
        unsafe fn idalib_apply_tinfo(ea: c_ulonglong, decl: *const c_char) -> bool;
        unsafe fn idalib_get_type_size(ea: c_ulonglong) -> usize;
        unsafe fn idalib_has_tinfo(ea: c_ulonglong) -> bool;

        // Offset functions
        unsafe fn idalib_op_offset(ea: c_ulonglong, n: c_int, base: c_ulonglong) -> bool;
        unsafe fn idalib_op_offset_ex(
            ea: c_ulonglong,
            n: c_int,
            reftype: c_int,
            target: c_ulonglong,
            base: c_ulonglong,
            tdelta: c_ulonglong,
        ) -> bool;
        unsafe fn idalib_get_offset_expression(ea: c_ulonglong, n: c_int) -> String;
        unsafe fn idalib_calc_offset_base(ea: c_ulonglong, n: c_int) -> c_ulonglong;
        unsafe fn idalib_get_default_reftype(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_can_be_off32(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_calc_probable_base(ea: c_ulonglong, off: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_calc_reference_target(ea: c_ulonglong, n: c_int) -> c_ulonglong;
        unsafe fn idalib_calc_reference_base(ea: c_ulonglong, n: c_int) -> c_ulonglong;

        // Demangle functions
        unsafe fn idalib_demangle_name(mangled: *const c_char, disable_mask: u32) -> String;
        unsafe fn idalib_demangle_name_long(mangled: *const c_char) -> String;
        unsafe fn idalib_demangle_name_short(mangled: *const c_char) -> String;
        unsafe fn idalib_can_demangle(mangled: *const c_char) -> i32;
        unsafe fn idalib_demangle_name_at(ea: c_ulonglong, disable_mask: u32) -> String;
        unsafe fn idalib_demangle_name_at_long(ea: c_ulonglong) -> String;

        // Jump table functions
        unsafe fn idalib_get_switch_info(ea: c_ulonglong) -> String;
        unsafe fn idalib_is_switch(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_jump_table_addr(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_switch_case_count(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_get_switch_default(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_switch_parent(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_del_switch_info(ea: c_ulonglong);
        unsafe fn idalib_check_for_table_jump(ea: c_ulonglong) -> bool;

        // Segment register functions
        unsafe fn idalib_get_sreg(ea: c_ulonglong, rg: c_int) -> c_ulonglong;
        unsafe fn idalib_split_sreg_range(
            ea: c_ulonglong,
            rg: c_int,
            v: c_ulonglong,
            tag: u8,
            silent: bool,
        ) -> bool;
        unsafe fn idalib_set_default_sreg_value(
            seg_start: c_ulonglong,
            rg: c_int,
            value: c_ulonglong,
        ) -> bool;
        unsafe fn idalib_set_default_sreg_value_all(rg: c_int, value: c_ulonglong) -> bool;
        unsafe fn idalib_set_default_dataseg(ds_sel: c_ulonglong);
        unsafe fn idalib_set_sreg_at_next_code(
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            rg: c_int,
            value: c_ulonglong,
        );
        unsafe fn idalib_get_sreg_range(ea: c_ulonglong, rg: c_int) -> String;
        unsafe fn idalib_get_prev_sreg_range(ea: c_ulonglong, rg: c_int) -> String;
        unsafe fn idalib_get_sreg_ranges_qty(rg: c_int) -> usize;
        unsafe fn idalib_getn_sreg_range(rg: c_int, n: c_int) -> String;
        unsafe fn idalib_get_sreg_range_num(ea: c_ulonglong, rg: c_int) -> c_int;
        unsafe fn idalib_del_sreg_range(ea: c_ulonglong, rg: c_int) -> bool;
        unsafe fn idalib_copy_sreg_ranges(dst_rg: c_int, src_rg: c_int, map_selector: bool);

        // Try block (exception handling) functions
        unsafe fn idalib_get_tryblks(start_ea: c_ulonglong, end_ea: c_ulonglong) -> String;
        unsafe fn idalib_get_tryblks_count(start_ea: c_ulonglong, end_ea: c_ulonglong) -> usize;
        unsafe fn idalib_del_tryblks(start_ea: c_ulonglong, end_ea: c_ulonglong);
        unsafe fn idalib_find_syseh(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_is_ea_tryblks(ea: c_ulonglong, flags: u32) -> bool;
        unsafe fn idalib_is_ea_cpp_try(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_ea_cpp_catch(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_ea_seh_try(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_ea_seh_handler(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_ea_seh_filter(ea: c_ulonglong) -> bool;

        // Debugger interface functions
        unsafe fn idalib_is_debugger_on() -> bool;
        unsafe fn idalib_is_debugger_memory(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_dbg_byte(ea: c_ulonglong, out: *mut u32) -> bool;
        unsafe fn idalib_get_dbg_byte_value(ea: c_ulonglong) -> i32;
        unsafe fn idalib_put_dbg_byte(ea: c_ulonglong, x: u32) -> bool;
        unsafe fn idalib_invalidate_dbgmem_config();
        unsafe fn idalib_invalidate_dbgmem_contents(ea: c_ulonglong, size: c_ulonglong);
        unsafe fn idalib_lock_dbgmem_config();
        unsafe fn idalib_unlock_dbgmem_config();
        unsafe fn idalib_get_dbg_bytes(ea: c_ulonglong, size: usize) -> String;
        unsafe fn idalib_get_debugger_status() -> String;

        // Frame (stack frame analysis) functions
        unsafe fn idalib_add_frame(
            func_ea: c_ulonglong,
            frsize: c_longlong,
            frregs: u16,
            argsize: c_ulonglong,
        ) -> bool;
        unsafe fn idalib_del_frame(func_ea: c_ulonglong) -> bool;
        unsafe fn idalib_set_frame_size(
            func_ea: c_ulonglong,
            frsize: c_ulonglong,
            frregs: u16,
            argsize: c_ulonglong,
        ) -> bool;
        unsafe fn idalib_get_frame_size(func_ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_frame_retsize(func_ea: c_ulonglong) -> c_int;
        unsafe fn idalib_get_frame_part(func_ea: c_ulonglong, part: c_int) -> String;
        unsafe fn idalib_get_func_frame(func_ea: c_ulonglong) -> String;
        unsafe fn idalib_build_stkvar_name(func_ea: c_ulonglong, offset: c_longlong) -> String;
        unsafe fn idalib_get_spd(func_ea: c_ulonglong, ea: c_ulonglong) -> c_longlong;
        unsafe fn idalib_get_effective_spd(func_ea: c_ulonglong, ea: c_ulonglong) -> c_longlong;
        unsafe fn idalib_get_sp_delta(func_ea: c_ulonglong, ea: c_ulonglong) -> c_longlong;
        unsafe fn idalib_add_auto_stkpnt(
            func_ea: c_ulonglong,
            ea: c_ulonglong,
            delta: c_longlong,
        ) -> bool;
        unsafe fn idalib_add_user_stkpnt(ea: c_ulonglong, delta: c_longlong) -> bool;
        unsafe fn idalib_del_stkpnt(func_ea: c_ulonglong, ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_frame_info(func_ea: c_ulonglong) -> String;
        unsafe fn idalib_delete_wrong_frame_info(func_ea: c_ulonglong) -> c_int;
        unsafe fn idalib_recalc_spd(ea: c_ulonglong) -> bool;

        // Fixup (relocations/fixups) functions
        unsafe fn idalib_exists_fixup(source: c_ulonglong) -> bool;
        unsafe fn idalib_get_fixup(source: c_ulonglong) -> String;
        unsafe fn idalib_del_fixup(source: c_ulonglong);
        unsafe fn idalib_get_first_fixup_ea() -> c_ulonglong;
        unsafe fn idalib_get_next_fixup_ea(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_prev_fixup_ea(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_apply_fixup(
            item_ea: c_ulonglong,
            fixup_ea: c_ulonglong,
            n: c_int,
            is_macro: bool,
        ) -> bool;
        unsafe fn idalib_get_fixup_value(ea: c_ulonglong, fixup_type: u16) -> c_ulonglong;
        unsafe fn idalib_calc_fixup_size(fixup_type: u16) -> c_int;
        unsafe fn idalib_get_fixup_desc(fixup_type: u16) -> String;
        unsafe fn idalib_enumerate_fixups(start_ea: c_ulonglong, end_ea: c_ulonglong) -> String;
        unsafe fn idalib_get_fixups_in_range(ea: c_ulonglong, size: c_ulonglong) -> String;
        unsafe fn idalib_count_fixups() -> usize;

        // Problems (problem tracking) functions
        unsafe fn idalib_get_problem_desc(prob_type: u8, ea: c_ulonglong) -> String;
        unsafe fn idalib_remember_problem(prob_type: u8, ea: c_ulonglong, msg: *const c_char);
        unsafe fn idalib_remember_problem_simple(prob_type: u8, ea: c_ulonglong);
        unsafe fn idalib_get_problem(prob_type: u8, lowea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_forget_problem(prob_type: u8, ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_problem_name(prob_type: u8) -> String;
        unsafe fn idalib_get_problem_name_short(prob_type: u8) -> String;
        unsafe fn idalib_is_problem_present(prob_type: u8, ea: c_ulonglong) -> bool;
        unsafe fn idalib_enumerate_problems(
            prob_type: u8,
            start_ea: c_ulonglong,
            end_ea: c_ulonglong,
        ) -> String;
        unsafe fn idalib_enumerate_all_problems() -> String;
        unsafe fn idalib_get_problems_at(ea: c_ulonglong) -> String;
    }
}

pub use ffi::{ea_t, range_t};
pub const BADADDR: ea_t = into_ea(0xffffffff_ffffffffu64);

#[inline(always)]
pub const fn into_ea(v: u64) -> ea_t {
    c_ulonglong(v)
}

#[inline(always)]
pub const fn from_ea(v: ea_t) -> u64 {
    v.0
}

pub mod entry {
    pub use super::ffi::{get_entry, get_entry_ordinal, get_entry_qty, uval_t};
    pub use super::ffix::idalib_entry_name;
}

pub mod insn {
    use std::mem::MaybeUninit;

    use super::ea_t;
    use super::ffi::decode_insn;

    pub use super::pod::insn_t;

    pub fn decode(ea: ea_t) -> Option<insn_t> {
        let mut insn = MaybeUninit::<insn_t>::zeroed();
        unsafe { (decode_insn(insn.as_mut_ptr(), ea).0 > 0).then(|| insn.assume_init()) }
    }

    pub mod op {
        pub use super::super::ffi::{
            IRI_EXTENDED, IRI_RET_LITERALLY, IRI_SKIP_RETTARGET, IRI_STRICT, dt_bitfild, dt_byte,
            dt_byte16, dt_byte32, dt_byte64, dt_code, dt_double, dt_dword, dt_float, dt_fword,
            dt_half, dt_ldbl, dt_packreal, dt_qword, dt_string, dt_tbyte, dt_unicode, dt_void,
            dt_word, o_displ, o_far, o_idpspec0, o_idpspec1, o_idpspec2, o_idpspec3, o_idpspec4,
            o_idpspec5, o_imm, o_mem, o_near, o_phrase, o_reg, o_void,
        };
        pub use super::super::pod::{
            OF_NO_BASE_DISP, OF_NUMBER, OF_OUTER_DISP, OF_SHOW, op_dtype_t, op_t, optype_t,
        };
    }

    pub mod arm {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_arm.rs"));
    }

    pub mod mips {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_mips.rs"));
    }

    pub mod x86 {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_x86.rs"));
    }
}

pub mod func {
    pub use super::ffi::{
        calc_thunk_func_target, fc_block_type_t, func_t, gdl_graph_t, get_func, get_func_num,
        get_func_qty, getn_func, lock_func, qbasic_block_t, qflow_chart_t,
    };
    pub use super::ffix::{
        idalib_func_flags, idalib_func_flow_chart, idalib_func_name, idalib_qbasic_block_preds,
        idalib_qbasic_block_succs, idalib_qflow_graph_getn_block,
    };

    pub mod flags {
        pub use super::super::ffi::{
            FUNC_BOTTOMBP, FUNC_FAR, FUNC_FRAME, FUNC_FUZZY_SP, FUNC_HIDDEN, FUNC_LIB, FUNC_LUMINA,
            FUNC_NORET, FUNC_NORET_PENDING, FUNC_OUTLINE, FUNC_PROLOG_OK, FUNC_PURGED_OK,
            FUNC_REANALYZE, FUNC_RESERVED, FUNC_SP_READY, FUNC_STATICDEF, FUNC_TAIL, FUNC_THUNK,
            FUNC_USERFAR,
        };
    }

    pub mod cfg_flags {
        pub use super::super::ffi::{
            FC_APPND, FC_CALL_ENDS, FC_CHKBREAK, FC_NOEXT, FC_NOPREDS, FC_OUTLINES, FC_PRINT,
            FC_RESERVED,
        };
    }
}

pub mod processor {
    pub use super::ffi::{get_ph, processor_t};
    pub use super::ffix::{
        idalib_is_thumb_at, idalib_ph_id, idalib_ph_long_name, idalib_ph_short_name,
    };

    pub use super::idp as ids;
}

pub mod segment {
    pub use super::ffi::{
        SEG_ABSSYM, SEG_BSS, SEG_CODE, SEG_COMM, SEG_DATA, SEG_GRP, SEG_IMEM, SEG_IMP,
        SEG_MAX_SEGTYPE_CODE, SEG_NORM, SEG_NULL, SEG_UNDF, SEG_XTRN, SEGPERM_EXEC, SEGPERM_MAXVAL,
        SEGPERM_READ, SEGPERM_WRITE, get_first_seg, get_last_seg, get_next_seg, get_segm_by_name,
        get_segm_qty, getnseg, getseg, lock_segment, saAbs, saGroup, saRel_MAX_ALIGN_CODE, saRel4K,
        saRel32Bytes, saRel64Bytes, saRel128Bytes, saRel512Bytes, saRel1024Bytes, saRel2048Bytes,
        saRelByte, saRelDble, saRelPage, saRelPara, saRelQword, saRelWord, segment_t,
    };

    pub use super::ffix::{
        idalib_segm_align, idalib_segm_bitness, idalib_segm_bytes, idalib_segm_name,
        idalib_segm_perm, idalib_segm_type,
    };
}

pub mod bytes {
    pub use super::ffi::{flags64_t, get_flags, is_code, is_data};
    pub use super::ffix::{
        idalib_get_byte, idalib_get_bytes, idalib_get_dword, idalib_get_qword, idalib_get_word,
        idalib_is_loaded, idalib_is_mapped,
    };
}

pub mod util {
    pub use super::ffi::{
        is_align_insn, is_basic_block_end, is_call_insn, is_indirect_jump_insn, is_ret_insn,
        next_head, prev_head, print_insn_mnem, str2reg,
    };
    pub use super::ffix::idalib_get_insn_mnem;
}

pub mod xref {
    pub use super::ffi::{
        XREF_ALL, XREF_BASE, XREF_DATA, XREF_FAR, XREF_MASK, XREF_PASTEND, XREF_TAIL, XREF_USER,
        cref_t, dref_t, get_first_dref_to, get_next_dref_to, has_external_refs, xrefblk_t,
        xrefblk_t_first_from, xrefblk_t_first_to, xrefblk_t_next_from, xrefblk_t_next_to,
    };

    // These are #define constants from xref.hpp that aren't exported by autocxx
    pub const XREF_FLOW: i32 = 0x00;
    pub const XREF_NOFLOW: i32 = 0x01;
    pub const XREF_CODE: i32 = 0x04;
}

pub mod comments {
    pub use super::ffi::{append_cmt, set_cmt};
    pub use super::ffix::idalib_get_cmt;
}

pub mod conversions {
    pub use super::ffix::idalib_ea2str;
}

pub mod bookmarks {
    pub use super::ffix::{
        idalib_bookmarks_t_erase, idalib_bookmarks_t_find_index, idalib_bookmarks_t_get,
        idalib_bookmarks_t_get_desc, idalib_bookmarks_t_mark, idalib_bookmarks_t_size,
    };
}

pub mod search {
    pub use super::ffix::{
        idalib_bin_search, idalib_find_binary, idalib_find_defined, idalib_find_imm,
        idalib_find_text, idalib_parse_binpat_str,
    };
}

pub mod strings {
    pub use super::ffi::{build_strlist, clear_strlist, get_strlist_qty};
    pub use super::ffix::{
        idalib_get_max_strlit_length, idalib_get_strlist_item_addr, idalib_get_strlist_item_length,
        idalib_get_strlit_contents,
    };
}

pub mod loader {
    pub use super::ffi::{find_plugin, plugin_t, run_plugin};
    pub use super::ffix::{idalib_plugin_flags, idalib_plugin_version};

    pub mod flags {
        pub use super::super::ffi::{
            PLUGIN_DBG, PLUGIN_DRAW, PLUGIN_FIX, PLUGIN_HIDE, PLUGIN_MOD, PLUGIN_MULTI,
            PLUGIN_PROC, PLUGIN_SCRIPTED, PLUGIN_SEG, PLUGIN_UNL,
        };
    }
}

pub mod nalt {
    pub use super::ffi::{
        retrieve_input_file_md5, retrieve_input_file_sha256, retrieve_input_file_size,
    };
    pub use super::ffix::{idalib_get_imports, idalib_get_input_file_path};
}

pub mod name {
    pub use super::ffi::{
        SN_AUTO, SN_CHECK, SN_DELTAIL, SN_FORCE, SN_IDBENC, SN_LOCAL, SN_NOCHECK, SN_NODUMMY,
        SN_NOLIST, SN_NON_AUTO, SN_NON_PUBLIC, SN_NON_WEAK, SN_NOWARN, SN_PUBLIC, SN_WEAK,
        get_nlist_ea, get_nlist_idx, get_nlist_name, get_nlist_size, is_in_nlist, is_public_name,
        is_weak_name,
    };
    pub use super::ffix::{
        idalib_del_global_name, idalib_del_local_name, idalib_force_ea_name, idalib_get_ea_name,
        idalib_set_ea_name,
    };
}

pub mod typeinf {
    pub use super::ffix::{
        idalib_apply_tinfo, idalib_del_tinfo, idalib_get_func_tinfo, idalib_get_named_type,
        idalib_get_numbered_type, idalib_get_tinfo, idalib_get_type_size, idalib_guess_func_tinfo,
        idalib_has_tinfo, idalib_parse_decl_name, idalib_parse_decl_type, idalib_print_type,
        idalib_set_named_type, idalib_set_tinfo_from_string,
    };
}

pub mod offset {
    pub use super::ffix::{
        idalib_calc_offset_base, idalib_calc_probable_base, idalib_calc_reference_base,
        idalib_calc_reference_target, idalib_can_be_off32, idalib_get_default_reftype,
        idalib_get_offset_expression, idalib_op_offset, idalib_op_offset_ex,
    };
}

pub mod demangle {
    pub use super::ffix::{
        idalib_can_demangle, idalib_demangle_name, idalib_demangle_name_at,
        idalib_demangle_name_at_long, idalib_demangle_name_long, idalib_demangle_name_short,
    };
}

pub mod jumptable {
    pub use super::ffix::{
        idalib_check_for_table_jump, idalib_del_switch_info, idalib_get_jump_table_addr,
        idalib_get_switch_case_count, idalib_get_switch_default, idalib_get_switch_info,
        idalib_get_switch_parent, idalib_is_switch,
    };
}

pub mod segregs {
    pub use super::ffix::{
        idalib_copy_sreg_ranges, idalib_del_sreg_range, idalib_get_prev_sreg_range,
        idalib_get_sreg, idalib_get_sreg_range, idalib_get_sreg_range_num,
        idalib_get_sreg_ranges_qty, idalib_getn_sreg_range, idalib_set_default_dataseg,
        idalib_set_default_sreg_value, idalib_set_default_sreg_value_all,
        idalib_set_sreg_at_next_code, idalib_split_sreg_range,
    };
}

pub mod tryblks {
    pub use super::ffix::{
        idalib_del_tryblks, idalib_find_syseh, idalib_get_tryblks, idalib_get_tryblks_count,
        idalib_is_ea_cpp_catch, idalib_is_ea_cpp_try, idalib_is_ea_seh_filter,
        idalib_is_ea_seh_handler, idalib_is_ea_seh_try, idalib_is_ea_tryblks,
    };
}

pub mod dbg {
    pub use super::ffix::{
        idalib_get_dbg_byte, idalib_get_dbg_byte_value, idalib_get_dbg_bytes,
        idalib_get_debugger_status, idalib_invalidate_dbgmem_config,
        idalib_invalidate_dbgmem_contents, idalib_is_debugger_memory, idalib_is_debugger_on,
        idalib_lock_dbgmem_config, idalib_put_dbg_byte, idalib_unlock_dbgmem_config,
    };
}

pub mod frame {
    pub use super::ffix::{
        idalib_add_auto_stkpnt, idalib_add_frame, idalib_add_user_stkpnt, idalib_build_stkvar_name,
        idalib_del_frame, idalib_del_stkpnt, idalib_delete_wrong_frame_info,
        idalib_get_effective_spd, idalib_get_frame_info, idalib_get_frame_part,
        idalib_get_frame_retsize, idalib_get_frame_size, idalib_get_func_frame,
        idalib_get_sp_delta, idalib_get_spd, idalib_recalc_spd, idalib_set_frame_size,
    };
}

pub mod fixup {
    pub use super::ffix::{
        idalib_apply_fixup, idalib_calc_fixup_size, idalib_count_fixups, idalib_del_fixup,
        idalib_enumerate_fixups, idalib_exists_fixup, idalib_get_first_fixup_ea, idalib_get_fixup,
        idalib_get_fixup_desc, idalib_get_fixup_value, idalib_get_fixups_in_range,
        idalib_get_next_fixup_ea, idalib_get_prev_fixup_ea,
    };
}

pub mod problems {
    pub use super::ffix::{
        idalib_enumerate_all_problems, idalib_enumerate_problems, idalib_forget_problem,
        idalib_get_problem, idalib_get_problem_desc, idalib_get_problem_name,
        idalib_get_problem_name_short, idalib_get_problems_at, idalib_is_problem_present,
        idalib_remember_problem, idalib_remember_problem_simple,
    };
}

pub mod ida {
    use std::env;
    use std::ffi::{CStr, CString};
    use std::path::Path;
    use std::ptr;

    use autocxx::prelude::*;

    use super::platform::is_main_thread;
    use super::{IDAError, ea_t, ffi, ffix};

    pub use ffi::auto_wait;

    pub fn is_license_valid() -> bool {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffix::idalib_check_license() }
    }

    pub fn license_id() -> Result<[u8; 6], IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        let mut lid = [0u8; 6];
        if unsafe { ffix::idalib_get_license_id(&mut lid) } {
            Ok(lid)
        } else {
            Err(IDAError::InvalidLicense)
        }
    }

    // NOTE: once; main thread
    pub fn init_library() -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { env::set_var("TVHEADLESS", "1") };

        let res = unsafe { ffix::init_library(c_int(0), ptr::null_mut()) };

        if res != c_int(0) {
            Err(IDAError::Init(res))
        } else {
            Ok(())
        }
    }

    pub fn make_signatures(only_pat: bool) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if unsafe { ffi::make_signatures(only_pat) } {
            Ok(())
        } else {
            Err(IDAError::MakeSigs)
        }
    }

    pub fn enable_console_messages(enable: bool) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::enable_console_messages(enable) }
    }

    pub fn set_screen_ea(ea: ea_t) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::set_screen_ea(ea) }
    }

    pub fn open_database(path: impl AsRef<Path>) -> Result<(), IDAError> {
        open_database_with(path, true)
    }

    // NOTE: main thread
    pub fn open_database_with(path: impl AsRef<Path>, auto_analysis: bool) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if !is_license_valid() {
            return Err(IDAError::InvalidLicense);
        }

        let path = CString::new(path.as_ref().to_string_lossy().as_ref()).map_err(IDAError::ffi)?;

        let res = unsafe { ffi::open_database(path.as_ptr(), auto_analysis, std::ptr::null()) };

        if res != c_int(0) {
            Err(IDAError::OpenDb(res))
        } else {
            Ok(())
        }
    }

    pub fn open_database_quiet(
        path: impl AsRef<Path>,
        auto_analysis: bool,
        args: &[impl AsRef<str>],
    ) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if !is_license_valid() {
            return Err(IDAError::InvalidLicense);
        }

        let mut args = args
            .iter()
            .map(|s| CString::new(s.as_ref()).map_err(IDAError::ffi))
            .collect::<Result<Vec<_>, _>>()?;

        let path = CString::new(path.as_ref().to_string_lossy().as_ref()).map_err(IDAError::ffi)?;
        args.push(path);

        let idalib0 = CStr::from_bytes_with_nul(b"idalib\0").map_err(IDAError::ffi)?;

        let argv = std::iter::once(idalib0.as_ptr())
            .chain(args.iter().map(|s| s.as_ptr()))
            .collect::<Vec<_>>();
        let argc = argv.len();

        let res = unsafe {
            ffix::idalib_open_database_quiet(c_int(argc as _), argv.as_ptr(), auto_analysis)
        };

        if res != c_int(0) {
            Err(IDAError::OpenDb(res))
        } else {
            Ok(())
        }
    }

    pub fn close_database() {
        close_database_with(true);
    }

    pub fn close_database_with(save: bool) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::close_database(save) }
    }

    pub fn library_version() -> Result<(i32, i32, i32), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        let mut major = c_int(0);
        let mut minor = c_int(0);
        let mut build = c_int(0);

        if unsafe { ffix::idalib_get_library_version(&mut major, &mut minor, &mut build) } {
            Ok((major.0 as _, minor.0 as _, build.0 as _))
        } else {
            Err(IDAError::GetVersion)
        }
    }
}
