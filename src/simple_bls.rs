use super::stats::{calculate_mean, calculate_median};
use blsttc::{hash_g1, hash_g2, PublicKeyG1, PublicKeyG2, SecretKey};
use std::time::Instant;

pub fn benchmark_normal_bls(nodes: usize) -> (f64, f64, f64, f64, f64, f64) {
    // for normal sign-verify
    let mut keypairs: Vec<(PublicKeyG1, PublicKeyG2, SecretKey)> = Vec::new();
    let msg = "hello, this is benchmark".as_bytes();
    let mut signs_g1 = Vec::new();
    let mut signs_g2 = Vec::new();

    for _ in 0..nodes {
        let sk = SecretKey::random();
        let pkg1 = sk.public_key_g1();
        let pkg2 = sk.public_key_g2();
        keypairs.push((pkg1, pkg2, sk));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating single sign in g1
    let mut time_to_create_normal_sign_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        let sign = keypairs[i].2.sign_g1(hash_g1(msg));

        let end_time = Instant::now();

        signs_g1.push(sign);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_normal_sign_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating single sign in g2
    let mut time_to_create_normal_sign_g2 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        let sign = keypairs[i].2.sign_g2(hash_g2(msg));

        let end_time = Instant::now();

        signs_g2.push(sign);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_normal_sign_g2.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single sign g1
    let mut time_to_verify_normal_sign_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        keypairs[i].1.verify(&signs_g1[i], msg);

        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_normal_sign_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single sign g2
    let mut time_to_verify_normal_sign_g2 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        keypairs[i].0.verify(&signs_g2[i], msg);

        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_normal_sign_g2.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for f+1 sign g1
    let mut time_to_verify_fplus1_independent_signs_g1 = 0.0;
    let n = (nodes - 1) / 3 + 1;

    let start_time = Instant::now();

    for i in 0..n {
        keypairs[i].1.verify(&signs_g1[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_fplus1_independent_signs_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for f+1 sign g2
    let mut time_to_verify_fplus1_independent_signs_g2 = 0.0;
    let n = (nodes - 1) / 3 + 1;

    let start_time = Instant::now();

    for i in 0..n {
        keypairs[i].0.verify(&signs_g2[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_fplus1_independent_signs_g2 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign g1
    let mut time_to_verify_all_independent_signs_g1 = 0.0;

    let start_time = Instant::now();

    for i in 0..nodes {
        keypairs[i].1.verify(&signs_g1[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign g2
    let mut time_to_verify_all_independent_signs_g2 = 0.0;

    let start_time = Instant::now();

    for i in 0..nodes {
        keypairs[i].0.verify(&signs_g2[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs_g2 = elapsed_time.as_secs_f64();

    let mean_single_sign_creation_g1 = calculate_mean(&time_to_create_normal_sign_g1) * 1000.0;
    let median_single_sign_creation_g1 =
        calculate_median(&mut time_to_create_normal_sign_g1) * 1000.0;
    let mean_single_sign_verify_g1 = calculate_mean(&time_to_verify_normal_sign_g1) * 1000.0;
    let median_single_sign_verify_g1 =
        calculate_median(&mut time_to_verify_normal_sign_g1) * 1000.0;
    let fplusq_sign_verify_g1 = time_to_verify_fplus1_independent_signs_g1 * 1000.0;
    let n_sign_verify_g1 = time_to_verify_all_independent_signs_g1 * 1000.0;

    let mean_single_sign_creation_g2 = calculate_mean(&time_to_create_normal_sign_g2) * 1000.0;
    let median_single_sign_creation_g2 =
        calculate_median(&mut time_to_create_normal_sign_g2) * 1000.0;
    let mean_single_sign_verify_g2 = calculate_mean(&time_to_verify_normal_sign_g2) * 1000.0;
    let median_single_sign_verify_g2 =
        calculate_median(&mut time_to_verify_normal_sign_g2) * 1000.0;
    let fplusq_sign_verify_g2 = time_to_verify_fplus1_independent_signs_g2 * 1000.0;
    let n_sign_verify_g2 = time_to_verify_all_independent_signs_g2 * 1000.0;

    //OUTPUT
    println!("for sign in g1 : ");
    println!(
        "mean time to create single bls sign in g1: {:.4} ms",
        mean_single_sign_creation_g1
    );
    println!(
        "median time to create single bls signin g1: {:.4} ms",
        median_single_sign_creation_g1
    );
    println!(
        "mean time to verify single bls sign in g1: {:.4} ms",
        mean_single_sign_verify_g1
    );
    println!(
        "meadian time to verify single bls sign in g1: {:.4} ms",
        median_single_sign_verify_g1
    );
    println!(
        "time takes to verify f+1 signs in g1: {:.4} ms",
        fplusq_sign_verify_g1
    );
    println!(
        "time takes to verify n signs in g1: {:.4} ms",
        n_sign_verify_g1
    );
    println!("");

    println!("for sign in g2 : ");
    println!(
        "mean time to create single bls sign in g2: {:.4} ms",
        mean_single_sign_creation_g2
    );
    println!(
        "median time to create single bls sign in g2: {:.4} ms",
        median_single_sign_creation_g2
    );
    println!(
        "mean time to verify single bls sign in g2: {:.4} ms",
        mean_single_sign_verify_g2
    );
    println!(
        "meadian time to verify single bls sign in g2: {:.4} ms",
        median_single_sign_verify_g2
    );
    println!(
        "time takes to verify f+1 signs in g2: {:.4} ms",
        fplusq_sign_verify_g2
    );
    println!(
        "time takes to verify n signs in g2: {:.4} ms",
        n_sign_verify_g2
    );
    println!("");

    (
        mean_single_sign_creation_g1,
        mean_single_sign_creation_g2,
        mean_single_sign_verify_g1,
        mean_single_sign_verify_g2,
        n_sign_verify_g1,
        n_sign_verify_g2,
    )
}
