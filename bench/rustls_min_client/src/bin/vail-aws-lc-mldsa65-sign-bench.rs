#[path = "../mldsa_wide_sign.rs"]
mod benchmark;

use aws_lc_rs::signature::ML_DSA_65_SIGNING;

fn main() {
    benchmark::run(&ML_DSA_65_SIGNING, "mldsa65");
}
