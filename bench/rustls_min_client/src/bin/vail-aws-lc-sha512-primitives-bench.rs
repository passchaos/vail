use std::{ffi::c_void, hint::black_box, ptr, time::Instant};

const SHORT_ITERATIONS: usize = 1_000_000;
const BULK_ITERATIONS: usize = 100_000;
const ONE_SHOT_HMAC_ITERATIONS: usize = 500_000;
const WARMUP_ITERATIONS: usize = 4_096;

type DigestFn = unsafe extern "C" fn(*const u8, usize, *mut u8) -> *mut u8;

fn main() {
    benchmark_digest::<64, 48>(
        "sha384-digest-64",
        SHORT_ITERATIONS,
        "53c31096e92945814b6670bb8d694d1a0e7c449b005351a6393ccc28e342bfa2b256faeb56671aacd6ff3a5ed950c18e",
        aws_lc_sys::SHA384,
    );
    benchmark_digest::<1024, 48>(
        "sha384-digest-1024",
        BULK_ITERATIONS,
        "2c48db2b260a7c9bafd83a138c927212f176ba7e615d8f36b8b35864c8da590fdf31abd151f343b6dd281af0fd537290",
        aws_lc_sys::SHA384,
    );
    benchmark_digest::<32, 64>(
        "sha512-digest-32",
        SHORT_ITERATIONS,
        "35bff78944368fe2796e30c990a5c34f41b4837de3c87f0f72b6c92b8f6d60bd539aea989e10413d3fc797324b7af8789fdaff7490c33323caa4267aa92f9537",
        aws_lc_sys::SHA512,
    );
    benchmark_digest::<1024, 64>(
        "sha512-digest-1024",
        BULK_ITERATIONS,
        "5b303ae22dc225150714da9ea3c81738beacd7683c3d94766c90c6a3063ddafeaef0800ac7f95771a316ac04cafa39d30dfd7acd986841e71ce893bdd64be426",
        aws_lc_sys::SHA512,
    );

    let sha384 = unsafe { aws_lc_sys::EVP_sha384() };
    benchmark_one_shot_hmac::<64, 48>(
        "hmac-sha384-one-shot-64",
        ONE_SHOT_HMAC_ITERATIONS,
        "654cb9188748e111ff1608e07e2c38d5aa38a641f79e4359bf393b6d10767b3a5cf9162f22f40793b9ce74fa663bb758",
        sha384,
    );
    benchmark_prepared_hmac::<64, 48>(
        "hmac-sha384-prepared-64",
        SHORT_ITERATIONS,
        "654cb9188748e111ff1608e07e2c38d5aa38a641f79e4359bf393b6d10767b3a5cf9162f22f40793b9ce74fa663bb758",
        sha384,
    );
    benchmark_prepared_hmac::<1024, 48>(
        "hmac-sha384-prepared-1024",
        BULK_ITERATIONS,
        "8e8a251e358fefd781232b376f5d203ed72b8a042faf993e9940e55e2ee9a98195827f209224a67127eca398c513736b",
        sha384,
    );

    let sha512 = unsafe { aws_lc_sys::EVP_sha512() };
    benchmark_one_shot_hmac::<64, 64>(
        "hmac-sha512-one-shot-64",
        ONE_SHOT_HMAC_ITERATIONS,
        "7569253a81ace72dc795f05e10009c713a5f5ec32c68b2faba48329b6932a697fce0c9c7b94c6b5a1e8f1bfec9173b79e189a68159f3c59292c13e88d970c752",
        sha512,
    );
    benchmark_prepared_hmac::<64, 64>(
        "hmac-sha512-prepared-64",
        SHORT_ITERATIONS,
        "7569253a81ace72dc795f05e10009c713a5f5ec32c68b2faba48329b6932a697fce0c9c7b94c6b5a1e8f1bfec9173b79e189a68159f3c59292c13e88d970c752",
        sha512,
    );
    benchmark_prepared_hmac::<1024, 64>(
        "hmac-sha512-prepared-1024",
        BULK_ITERATIONS,
        "dbfde5e172706a7d851c232d3ea5263c93cbcacf48e689d95e0deb34176d75d4f80097d923f16bb5fa0a7b323dbc5e361b804528ea7cd001b7dea2c90998b5b9",
        sha512,
    );
}

fn benchmark_digest<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    label: &str,
    iterations: usize,
    expected_hex: &str,
    digest: DigestFn,
) {
    let mut input = benchmark_input::<INPUT_LEN>();
    let mut output = [0u8; DIGEST_LEN];
    call_digest(digest, &input, &mut output);
    assert_eq!(output, decode_hex(expected_hex));

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        input[0] = iteration as u8;
        call_digest(digest, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_digest(digest, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "aws-lc-{label}={} ns/op ({} ps/op) checksum={checksum}",
        elapsed / iterations as u128,
        elapsed * 1_000 / iterations as u128,
    );
}

fn call_digest<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    digest: DigestFn,
    input: &[u8; INPUT_LEN],
    output: &mut [u8; DIGEST_LEN],
) {
    let result = unsafe { digest(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    assert!(!result.is_null());
}

fn benchmark_one_shot_hmac<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    label: &str,
    iterations: usize,
    expected_hex: &str,
    md: *const aws_lc_sys::EVP_MD,
) {
    let key = [0x42u8; DIGEST_LEN];
    let mut input = benchmark_input::<INPUT_LEN>();
    let mut output = [0u8; DIGEST_LEN];
    call_one_shot_hmac(md, &key, &input, &mut output);
    assert_eq!(output, decode_hex(expected_hex));

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        input[0] = iteration as u8;
        call_one_shot_hmac(md, &key, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_one_shot_hmac(md, &key, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "aws-lc-{label}={} ns/op ({} ps/op) checksum={checksum}",
        elapsed / iterations as u128,
        elapsed * 1_000 / iterations as u128,
    );
}

fn call_one_shot_hmac<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    md: *const aws_lc_sys::EVP_MD,
    key: &[u8; DIGEST_LEN],
    input: &[u8; INPUT_LEN],
    output: &mut [u8; DIGEST_LEN],
) {
    let result = unsafe {
        aws_lc_sys::HMAC(
            md,
            key.as_ptr().cast::<c_void>(),
            key.len(),
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            ptr::null_mut(),
        )
    };
    assert!(!result.is_null());
}

fn benchmark_prepared_hmac<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    label: &str,
    iterations: usize,
    expected_hex: &str,
    md: *const aws_lc_sys::EVP_MD,
) {
    let key = [0x42u8; DIGEST_LEN];
    let ctx = unsafe { aws_lc_sys::HMAC_CTX_new() };
    assert!(!ctx.is_null());
    let initialized = unsafe {
        aws_lc_sys::HMAC_Init_ex(
            ctx,
            key.as_ptr().cast::<c_void>(),
            key.len(),
            md,
            ptr::null_mut(),
        )
    };
    assert_eq!(initialized, 1);

    let mut input = benchmark_input::<INPUT_LEN>();
    let mut output = [0u8; DIGEST_LEN];
    call_prepared_hmac(ctx, &input, &mut output);
    assert_eq!(output, decode_hex(expected_hex));

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        input[0] = iteration as u8;
        call_prepared_hmac(ctx, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_prepared_hmac(ctx, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % DIGEST_LEN] as u64);
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "aws-lc-{label}={} ns/op ({} ps/op) checksum={checksum}",
        elapsed / iterations as u128,
        elapsed * 1_000 / iterations as u128,
    );

    unsafe { aws_lc_sys::HMAC_CTX_free(ctx) };
}

fn call_prepared_hmac<const INPUT_LEN: usize, const DIGEST_LEN: usize>(
    ctx: *mut aws_lc_sys::HMAC_CTX,
    input: &[u8; INPUT_LEN],
    output: &mut [u8; DIGEST_LEN],
) {
    let reset =
        unsafe { aws_lc_sys::HMAC_Init_ex(ctx, ptr::null(), 0, ptr::null(), ptr::null_mut()) };
    assert_eq!(reset, 1);
    let updated = unsafe { aws_lc_sys::HMAC_Update(ctx, input.as_ptr(), input.len()) };
    assert_eq!(updated, 1);
    let finalized = unsafe { aws_lc_sys::HMAC_Final(ctx, output.as_mut_ptr(), ptr::null_mut()) };
    assert_eq!(finalized, 1);
}

fn benchmark_input<const LEN: usize>() -> [u8; LEN] {
    let mut input = [0u8; LEN];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(131).wrapping_add(17);
    }
    input
}

fn decode_hex<const LEN: usize>(encoded: &str) -> [u8; LEN] {
    assert_eq!(encoded.len(), LEN * 2);
    let mut result = [0u8; LEN];
    for (index, byte) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap();
    }
    result
}
