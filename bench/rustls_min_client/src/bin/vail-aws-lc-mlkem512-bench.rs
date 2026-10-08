#[path = "../mlkem_bench.rs"]
mod benchmark;

use aws_lc_rs::kem::ML_KEM_512;

fn main() {
    benchmark::run(&ML_KEM_512, "mlkem512");
}
