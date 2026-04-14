// CI promotes Clippy warnings to errors. Allow the current legacy style backlog
// at the crate level so functional checks can pass until the modules are refactored.
#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::for_kv_map,
    clippy::format_in_format_args,
    clippy::implicit_saturating_sub,
    clippy::let_and_return,
    clippy::manual_clamp,
    clippy::map_clone,
    clippy::match_like_matches_macro,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::ptr_arg,
    clippy::redundant_pattern_matching,
    clippy::regex_creation_in_loops,
    clippy::single_char_add_str,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::to_string_in_format_args,
    clippy::trim_split_whitespace,
    clippy::uninlined_format_args,
    clippy::unnecessary_map_or,
    clippy::upper_case_acronyms,
    clippy::useless_format,
    clippy::useless_vec,
    clippy::unwrap_or_default,
    clippy::vec_init_then_push
)]

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin_shared.rs"));
