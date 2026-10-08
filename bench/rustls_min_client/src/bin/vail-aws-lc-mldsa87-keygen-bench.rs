#[path = "../mldsa_wide_keygen.rs"]
mod benchmark;

use aws_lc_rs::signature::ML_DSA_87_SIGNING;

fn main() {
    benchmark::run(&ML_DSA_87_SIGNING, "mldsa87");
}
