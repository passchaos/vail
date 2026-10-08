#[path = "../mldsa_wide_verify.rs"]
mod benchmark;

use aws_lc_rs::signature::{ML_DSA_87, ML_DSA_87_SIGNING};

fn main() {
    benchmark::run::<4627>(
        &ML_DSA_87,
        &ML_DSA_87_SIGNING,
        0x87,
        "mldsa87",
        include_str!("../../../testdata/mldsa87_signature.hex"),
    );
}
