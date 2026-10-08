#[path = "../mldsa_wide_verify.rs"]
mod benchmark;

use aws_lc_rs::signature::{ML_DSA_65, ML_DSA_65_SIGNING};

fn main() {
    benchmark::run::<3309>(
        &ML_DSA_65,
        &ML_DSA_65_SIGNING,
        0x65,
        "mldsa65",
        include_str!("../../../testdata/mldsa65_signature.hex"),
    );
}
