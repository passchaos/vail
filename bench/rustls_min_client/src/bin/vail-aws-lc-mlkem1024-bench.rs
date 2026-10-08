#[path = "../mlkem_bench.rs"]
mod benchmark;

use aws_lc_rs::kem::ML_KEM_1024;

fn main() {
    benchmark::run(&ML_KEM_1024, "mlkem1024");
}
