use super::stats::{calculate_mean, calculate_median};
use blsttc::{
    PublicKeyShareG1, PublicKeyShareG2, SecretKeySet, SecretKeyShare, SignatureShareG1,
    SignatureShareG2,
};
use std::time::Instant;

pub fn benchmark_threshold_bls(nodes: usize) -> (f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) {
    let threshold = (nodes - 1) / 3;

    let mut keypairs: Vec<(PublicKeyShareG1, PublicKeyShareG2, SecretKeyShare)> = Vec::new();
    let msg = "hello, this is benchmark".as_bytes();
    let mut signs_g1 = Vec::new();
    let mut signs_g2 = Vec::new();

    let mut rng = blsttc::rand::rngs::OsRng;
    // Generate a set of secret key shares
    let sk_set = SecretKeySet::random(threshold, &mut rng);
    // Get the corresponding public key set
    let pk_set_g1 = sk_set.public_keys();
    let pk_set_g2 = sk_set.public_keys_g2();

    for node in 0..nodes {
        let sk_share = sk_set.secret_key_share(node);
        let pk_share_g1 = pk_set_g1.public_key_share(node);
        let pk_share_g2 = pk_set_g2.public_key_share(node);

        keypairs.push((pk_share_g1, pk_share_g2, sk_share));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating sign share in g1
    let mut time_to_create_sign_share_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        let sign = keypairs[i].2.sign_g1(msg);

        let end_time = Instant::now();

        signs_g1.push(sign);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_sign_share_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating sign share in g2
    let mut time_to_create_sign_share_g2 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        let sign = keypairs[i].2.sign_g2(msg);

        let end_time = Instant::now();

        signs_g2.push(sign);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_sign_share_g2.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single g1 sign share
    let mut time_to_verify_single_sign_share_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        keypairs[i].1.verify(&signs_g1[i], msg);

        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_single_sign_share_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single g2 sign share
    let mut time_to_verify_single_sign_share_g2 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        keypairs[i].0.verify(&signs_g2[i], msg);

        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_single_sign_share_g2.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign share in g1
    let mut time_to_verify_all_independent_signs_g1 = 0.0;

    let start_time = Instant::now();

    for i in 0..nodes {
        keypairs[i].1.verify(&signs_g1[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign share in g2
    let mut time_to_verify_all_independent_signs_g2 = 0.0;

    let start_time = Instant::now();

    for i in 0..nodes {
        keypairs[i].0.verify(&signs_g2[i], msg);
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs_g2 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating threshold sign g1
    let mut time_to_create_threshold_sign_g1 = 0.0;

    let mut signatures: Vec<(_, SignatureShareG1)> = Vec::new();
    for i in 0..nodes {
        signatures.push((i, signs_g1[i].clone()));
    }

    let start_time = Instant::now();
    let combined_sign_g1 = pk_set_g2
        .combine_signatures(signatures.into_iter())
        .unwrap();
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_create_threshold_sign_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating threshold sign g2
    let mut time_to_create_threshold_sign_g2 = 0.0;

    let mut signatures: Vec<(_, SignatureShareG2)> = Vec::new();
    for i in 0..nodes {
        signatures.push((i, signs_g2[i].clone()));
    }

    let start_time = Instant::now();
    let combined_sign_g2 = pk_set_g1
        .combine_g2_signatures(signatures.into_iter())
        .unwrap();
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_create_threshold_sign_g2 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying threshold sign g1
    let mut time_to_verify_threshold_sign_g1 = 0.0;

    let start_time = Instant::now();
    pk_set_g2.public_key().verify(&combined_sign_g1, msg);
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_threshold_sign_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying threshold sign g2
    let mut time_to_verify_threshold_sign_g2 = 0.0;

    let start_time = Instant::now();
    pk_set_g1.public_key().verify(&combined_sign_g2, msg);
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_threshold_sign_g2 = elapsed_time.as_secs_f64();

    let mean_single_sign_creation_g1 = calculate_mean(&time_to_create_sign_share_g1) * 1000.0;
    let median_single_sign_creation_g1 =
        calculate_median(&mut time_to_create_sign_share_g1) * 1000.0;
    let mean_single_sign_verify_g1 = calculate_mean(&time_to_verify_single_sign_share_g1) * 1000.0;
    let median_single_sign_verify_g1 =
        calculate_median(&mut time_to_verify_single_sign_share_g1) * 1000.0;
    let n_sign_verify_g1 = time_to_verify_all_independent_signs_g1 * 1000.0;
    let creation_threshold_sign_g1 = time_to_create_threshold_sign_g1 * 1000.0;
    let verify_threshold_sign_g1 = time_to_verify_threshold_sign_g1 * 1000.0;

    let mean_single_sign_creation_g2 = calculate_mean(&time_to_create_sign_share_g2) * 1000.0;
    let median_single_sign_creation_g2 =
        calculate_median(&mut time_to_create_sign_share_g2) * 1000.0;
    let mean_single_sign_verify_g2 = calculate_mean(&time_to_verify_single_sign_share_g2) * 1000.0;
    let median_single_sign_verify_g2 =
        calculate_median(&mut time_to_verify_single_sign_share_g2) * 1000.0;
    let n_sign_verify_g2 = time_to_verify_all_independent_signs_g2 * 1000.0;
    let creation_threshold_sign_g2 = time_to_create_threshold_sign_g2 * 1000.0;
    let verify_threshold_sign_g2 = time_to_verify_threshold_sign_g2 * 1000.0;

    //OUTPUT
    println!("for signshare in g1 : ");
    println!(
        "mean time to create single  bls sign share in g1: {:.4} ms",
        mean_single_sign_creation_g1
    );
    println!(
        "median time to create single bls sign share in g1: {:.4} ms",
        median_single_sign_creation_g1
    );
    println!(
        "mean time to verify single bls sign share in g1: {:.4} ms",
        mean_single_sign_verify_g1
    );
    println!(
        "meadian time to verify single bls sign share in g1: {:.4} ms",
        median_single_sign_verify_g1
    );
    println!(
        "time takes to verify n independent signs share in g1: {:.4} ms",
        n_sign_verify_g1
    );
    println!(
        "time takes to create threshold sign in g1: {:.4} ms",
        creation_threshold_sign_g1
    );
    println!(
        "time takes to verify threshold sign in g1: {:.4} ms",
        verify_threshold_sign_g1
    );
    println!("");

    println!("for signshare in g2 : ");
    println!(
        "mean time to create single  bls sign share in g2: {:.4} ms",
        mean_single_sign_creation_g2
    );
    println!(
        "median time to create single bls sign share in g2: {:.4} ms",
        median_single_sign_creation_g2
    );
    println!(
        "mean time to verify single bls sign share in g2: {:.4} ms",
        mean_single_sign_verify_g2
    );
    println!(
        "meadian time to verify single bls sign share in g2: {:.4} ms",
        median_single_sign_verify_g2
    );
    println!(
        "time takes to verify n independent signs share in g2: {:.4} ms",
        n_sign_verify_g2
    );
    println!(
        "time takes to create threshold sign in g2: {:.4} ms",
        creation_threshold_sign_g2
    );
    println!(
        "time takes to verify threshold sign in g21: {:.4} ms",
        verify_threshold_sign_g2
    );
    println!("");

    (
        mean_single_sign_creation_g1,
        mean_single_sign_creation_g2,
        mean_single_sign_verify_g1,
        mean_single_sign_verify_g2,
        n_sign_verify_g1,
        n_sign_verify_g2,
        creation_threshold_sign_g1,
        creation_threshold_sign_g2,
        verify_threshold_sign_g1,
        verify_threshold_sign_g2,
    )
}
