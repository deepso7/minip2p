//! The quick-run switch, its own file so benches built without the features
//! the rest of `support` needs can include it by path.

/// Whether `MINIP2P_BENCH_QUICK=1` asks for a shorter run. PR comparison
/// runs set it (`scripts/run-bench-container.sh`); the benches that honor it
/// measure less but still report rates, medians and percentiles, never
/// totals, so base and head stay comparable.
pub fn quick() -> bool {
    std::env::var_os("MINIP2P_BENCH_QUICK").is_some_and(|value| value == "1")
}
