use frost_ed25519_blake2b::Ed25519Blake2b512;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = rand::rngs::OsRng;

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Ed25519Blake2b512, _>(rng);
}
