use std::{ffi::c_void, hint::black_box, ptr, time::Instant};

const SHORT_ITERATIONS: usize = 2_000_000;
const BULK_ITERATIONS: usize = 250_000;
const ONE_SHOT_HMAC_ITERATIONS: usize = 1_000_000;
const WARMUP_ITERATIONS: usize = 4_096;
const DIGEST_LEN: usize = 32;

fn main() {
    benchmark_digest::<32>(
        "sha256-digest-32",
        SHORT_ITERATIONS,
        "43599ef388fde687ef9376c222e271b733efb0b6982a7810af4a0cbd5a0050e3",
    );
    benchmark_digest::<1024>(
        "sha256-digest-1024",
        BULK_ITERATIONS,
        "575383deff0775797e1ff4c82da069141937c843a81cbe50959a96bcfa88140e",
    );
    benchmark_one_shot_hmac::<32>(
        "hmac-sha256-one-shot-32",
        ONE_SHOT_HMAC_ITERATIONS,
        "0e5c3c8cea349b9ca69197a5670ca018bdf024ee5c8311d5d29bb6bd06fdf099",
    );
    benchmark_prepared_hmac::<32>(
        "hmac-sha256-prepared-32",
        SHORT_ITERATIONS,
        "0e5c3c8cea349b9ca69197a5670ca018bdf024ee5c8311d5d29bb6bd06fdf099",
    );
    benchmark_prepared_hmac::<1024>(
        "hmac-sha256-prepared-1024",
        BULK_ITERATIONS,
        "b2c8dace2ebb0b077a7ce4e7120657aef4053a93da369ee7bea48b4c2d6a79a9",
    );
}

fn benchmark_digest<const INPUT_LEN: usize>(label: &str, iterations: usize, expected_hex: &str) {
    let mut input = benchmark_input::<INPUT_LEN>();
    let mut output = [0u8; DIGEST_LEN];
    call_digest(&input, &mut output);
    assert_eq!(output, decode_hex(expected_hex));

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        input[0] = iteration as u8;
        call_digest(black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_digest(black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / iterations as u128;
    println!("aws-lc-{label}={elapsed} ns/op checksum={checksum}");
}

fn call_digest<const INPUT_LEN: usize>(input: &[u8; INPUT_LEN], output: &mut [u8; 32]) {
    let result = unsafe { aws_lc_sys::SHA256(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    assert!(!result.is_null());
}

fn benchmark_one_shot_hmac<const INPUT_LEN: usize>(
    label: &str,
    iterations: usize,
    expected_hex: &str,
) {
    let key = [0x42u8; DIGEST_LEN];
    let mut input = benchmark_input::<INPUT_LEN>();
    let mut output = [0u8; DIGEST_LEN];
    call_one_shot_hmac(&key, &input, &mut output);
    assert_eq!(output, decode_hex(expected_hex));

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        input[0] = iteration as u8;
        call_one_shot_hmac(&key, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_one_shot_hmac(&key, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / iterations as u128;
    println!("aws-lc-{label}={elapsed} ns/op checksum={checksum}");
}

fn call_one_shot_hmac<const INPUT_LEN: usize>(
    key: &[u8; DIGEST_LEN],
    input: &[u8; INPUT_LEN],
    output: &mut [u8; DIGEST_LEN],
) {
    let result = unsafe {
        aws_lc_sys::HMAC(
            aws_lc_sys::EVP_sha256(),
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

fn benchmark_prepared_hmac<const INPUT_LEN: usize>(
    label: &str,
    iterations: usize,
    expected_hex: &str,
) {
    let key = [0x42u8; DIGEST_LEN];
    let md = unsafe { aws_lc_sys::EVP_sha256() };
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
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..iterations {
        input[0] = iteration as u8;
        call_prepared_hmac(ctx, black_box(&input), &mut output);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / iterations as u128;
    println!("aws-lc-{label}={elapsed} ns/op checksum={checksum}");

    unsafe { aws_lc_sys::HMAC_CTX_free(ctx) };
}

fn call_prepared_hmac<const INPUT_LEN: usize>(
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
