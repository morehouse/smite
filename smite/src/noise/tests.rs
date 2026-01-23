//! BOLT 8 test vectors for Noise protocol implementation.

use secp256k1::{PublicKey, SecretKey};

use super::cipher::{ENCRYPTED_LENGTH_SIZE, NoiseCipher};
use super::handshake::{ACT_ONE_SIZE, ACT_THREE_SIZE, ACT_TWO_SIZE, NoiseHandshake};

/// Helper to decode hex strings to byte arrays.
fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), N, "hex string has wrong length");
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

/// Helper to decode hex strings to Vec.
fn hex_to_vec(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).expect("valid hex")
}

/// Helper to create a `SecretKey` from hex.
fn secret_key(hex: &str) -> SecretKey {
    SecretKey::from_byte_array(hex_to_array(hex)).expect("valid secret key")
}

/// Helper to create a `PublicKey` from hex.
fn public_key(hex: &str) -> PublicKey {
    PublicKey::from_slice(&hex_to_vec(hex)).expect("valid public key")
}

// =============================================================================
// Initiator Tests (from BOLT 8 Appendix A)
// =============================================================================

#[test]
fn initiator_successful_handshake() {
    // Test vector keys
    let rs_pub = public_key("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let ls_priv = secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let e_priv = secret_key("1212121212121212121212121212121212121212121212121212121212121212");

    let mut initiator = NoiseHandshake::new_initiator(ls_priv, e_priv, rs_pub);

    // Act One
    let act_one = initiator.get_act_one().expect("act one successful");
    let expected_act_one = hex_to_vec(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );
    assert_eq!(act_one[..], expected_act_one[..], "Act One mismatch");

    // Act Two (from responder)
    let act_two: [u8; ACT_TWO_SIZE] = hex_to_array(
        "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae",
    );

    // Process Act Two -> get Act Three
    let act_three = initiator
        .process_act_two(&act_two)
        .expect("act two successful");
    let expected_act_three = hex_to_vec(
        "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba",
    );
    assert_eq!(act_three[..], expected_act_three[..], "Act Three mismatch");

    // Verify final keys
    let (send_key, recv_key) = initiator.get_final_keys().expect("final keys");
    let expected_send =
        hex_to_vec("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
    let expected_recv =
        hex_to_vec("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");
    assert_eq!(send_key[..], expected_send[..], "send key mismatch");
    assert_eq!(recv_key[..], expected_recv[..], "recv key mismatch");
}

#[test]
fn initiator_act2_bad_version() {
    let rs_pub = public_key("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let ls_priv = secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let e_priv = secret_key("1212121212121212121212121212121212121212121212121212121212121212");

    let mut initiator = NoiseHandshake::new_initiator(ls_priv, e_priv, rs_pub);
    let _ = initiator.get_act_one().expect("act one successful");

    // Act Two with bad version (0x01 instead of 0x00)
    let act_two: [u8; ACT_TWO_SIZE] = hex_to_array(
        "0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae",
    );

    let err = initiator
        .process_act_two(&act_two)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT2_BAD_VERSION 1");
}

#[test]
fn initiator_act2_bad_pubkey() {
    let rs_pub = public_key("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let ls_priv = secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let e_priv = secret_key("1212121212121212121212121212121212121212121212121212121212121212");

    let mut initiator = NoiseHandshake::new_initiator(ls_priv, e_priv, rs_pub);
    let _ = initiator.get_act_one().expect("act one successful");

    // Act Two with bad key serialization (0x04 prefix instead of 0x02/0x03)
    let act_two: [u8; ACT_TWO_SIZE] = hex_to_array(
        "0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae",
    );

    let err = initiator
        .process_act_two(&act_two)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT2_BAD_PUBKEY");
}

#[test]
fn initiator_act2_bad_mac() {
    let rs_pub = public_key("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let ls_priv = secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let e_priv = secret_key("1212121212121212121212121212121212121212121212121212121212121212");

    let mut initiator = NoiseHandshake::new_initiator(ls_priv, e_priv, rs_pub);
    let _ = initiator.get_act_one().expect("act one successful");

    // Act Two with corrupted MAC (last byte changed from 0xae to 0xaf)
    let act_two: [u8; ACT_TWO_SIZE] = hex_to_array(
        "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af",
    );

    let err = initiator
        .process_act_two(&act_two)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT2_BAD_TAG");
}

// =============================================================================
// Responder Tests (from BOLT 8 Appendix A)
// =============================================================================

#[test]
fn responder_successful_handshake() {
    // Test vector keys
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    // Act One (from initiator)
    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );

    // Process Act One -> get Act Two
    let act_two = responder
        .process_act_one(&act_one)
        .expect("act one successful");
    let expected_act_two = hex_to_vec(
        "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae",
    );
    assert_eq!(act_two[..], expected_act_two[..], "Act Two mismatch");

    // Act Three (from initiator)
    let act_three: [u8; ACT_THREE_SIZE] = hex_to_array(
        "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba",
    );

    // Process Act Three -> get remote static pubkey
    let remote_static = responder
        .process_act_three(&act_three)
        .expect("act three successful");
    let expected_remote =
        public_key("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    assert_eq!(
        remote_static, expected_remote,
        "remote static pubkey mismatch"
    );

    // Verify final keys (note: reversed for responder)
    let (send_key, recv_key) = responder.get_final_keys().expect("final keys");
    // Responder's keys are swapped compared to initiator
    let expected_recv =
        hex_to_vec("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
    let expected_send =
        hex_to_vec("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");
    assert_eq!(send_key[..], expected_send[..], "send key mismatch");
    assert_eq!(recv_key[..], expected_recv[..], "recv key mismatch");
}

#[test]
fn responder_act1_bad_version() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    // Act One with bad version (0x01 instead of 0x00)
    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );

    let err = responder
        .process_act_one(&act_one)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT1_BAD_VERSION 1");
}

#[test]
fn responder_act1_bad_pubkey() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    // Act One with bad key serialization (0x04 prefix)
    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );

    let err = responder
        .process_act_one(&act_one)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT1_BAD_PUBKEY");
}

#[test]
fn responder_act1_bad_mac() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    // Act One with corrupted MAC (last byte changed from 0x6a to 0x6b)
    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b",
    );

    let err = responder
        .process_act_one(&act_one)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT1_BAD_TAG");
}

#[test]
fn responder_act3_bad_version() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );
    let _ = responder
        .process_act_one(&act_one)
        .expect("act one successful");

    // Act Three with bad version (0x01 instead of 0x00)
    let act_three: [u8; ACT_THREE_SIZE] = hex_to_array(
        "01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba",
    );

    let err = responder
        .process_act_three(&act_three)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT3_BAD_VERSION 1");
}

#[test]
fn responder_act3_bad_ciphertext() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );
    let _ = responder
        .process_act_one(&act_one)
        .expect("act one successful");

    // Act Three with corrupted ciphertext (first byte of c changed from 0xb9 to 0xc9)
    let act_three: [u8; ACT_THREE_SIZE] = hex_to_array(
        "00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba",
    );

    let err = responder
        .process_act_three(&act_three)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT3_BAD_CIPHERTEXT");
}

#[test]
fn responder_act3_bad_pubkey() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );
    let _ = responder
        .process_act_one(&act_one)
        .expect("act one successful");

    // Act Three with invalid pubkey (decrypts to key starting with 0x04)
    let act_three: [u8; ACT_THREE_SIZE] = hex_to_array(
        "00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c",
    );

    let err = responder
        .process_act_three(&act_three)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT3_BAD_PUBKEY");
}

#[test]
fn responder_act3_bad_mac() {
    let ls_priv = secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let e_priv = secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let mut responder = NoiseHandshake::new_responder(ls_priv, e_priv);

    let act_one: [u8; ACT_ONE_SIZE] = hex_to_array(
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
    );
    let _ = responder
        .process_act_one(&act_one)
        .expect("act one successful");

    // Act Three with corrupted final tag (last byte changed from 0xba to 0xbb)
    let act_three: [u8; ACT_THREE_SIZE] = hex_to_array(
        "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb",
    );

    let err = responder
        .process_act_three(&act_three)
        .expect_err("should fail");
    assert_eq!(err.to_string(), "ACT3_BAD_TAG");
}

// =============================================================================
// Message Encryption Tests (from BOLT 8 Appendix A)
// =============================================================================

#[test]
fn message_encryption() {
    // From the test vector, after handshake completes:
    // ck = 0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01
    // sk = 0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9
    // rk = 0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442

    let ck = hex_to_array::<32>("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01");
    let sk = hex_to_array::<32>("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
    let rk = hex_to_array::<32>("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");

    let mut cipher = NoiseCipher::new(sk, rk, ck);

    // Test message: "hello" (5 bytes)
    let hello = b"hello";

    // Output 0
    let encrypted = cipher.encrypt(hello);
    let expected_0 = hex_to_vec(
        "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95",
    );
    assert_eq!(encrypted, expected_0, "output 0 mismatch");

    // Output 1
    let encrypted = cipher.encrypt(hello);
    let expected_1 = hex_to_vec(
        "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1",
    );
    assert_eq!(encrypted, expected_1, "output 1 mismatch");

    // Encrypt messages 2-499 to reach first key rotation
    for _ in 2..500 {
        let _ = cipher.encrypt(hello);
    }

    // Output 500 (after first key rotation)
    let encrypted = cipher.encrypt(hello);
    let expected_500 = hex_to_vec(
        "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8",
    );
    assert_eq!(encrypted, expected_500, "output 500 mismatch");

    // Output 501
    let encrypted = cipher.encrypt(hello);
    let expected_501 = hex_to_vec(
        "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd",
    );
    assert_eq!(encrypted, expected_501, "output 501 mismatch");

    // Encrypt messages 502-999 to reach second key rotation
    for _ in 502..1000 {
        let _ = cipher.encrypt(hello);
    }

    // Output 1000 (after second key rotation)
    let encrypted = cipher.encrypt(hello);
    let expected_1000 = hex_to_vec(
        "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09",
    );
    assert_eq!(encrypted, expected_1000, "output 1000 mismatch");

    // Output 1001
    let encrypted = cipher.encrypt(hello);
    let expected_1001 = hex_to_vec(
        "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36",
    );
    assert_eq!(encrypted, expected_1001, "output 1001 mismatch");
}

// =============================================================================
// End-to-End Tests
// =============================================================================

#[test]
fn full_handshake_both_sides() {
    // Use the test vector keys for determinism
    let initiator_static =
        secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let initiator_ephemeral =
        secret_key("1212121212121212121212121212121212121212121212121212121212121212");
    let responder_static =
        secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let responder_ephemeral =
        secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let secp = secp256k1::Secp256k1::new();
    let responder_static_pub = PublicKey::from_secret_key(&secp, &responder_static);

    // Create both sides
    let mut initiator =
        NoiseHandshake::new_initiator(initiator_static, initiator_ephemeral, responder_static_pub);
    let mut responder = NoiseHandshake::new_responder(responder_static, responder_ephemeral);

    // Act One: initiator -> responder
    let act_one = initiator.get_act_one().expect("act one successful");
    let act_two = responder
        .process_act_one(&act_one)
        .expect("process act one successful");

    // Act Two + Three: responder -> initiator, initiator -> responder
    let act_three = initiator
        .process_act_two(&act_two)
        .expect("process act two successful");
    let _remote_static = responder
        .process_act_three(&act_three)
        .expect("process act three successful");

    // Get ciphers
    let mut initiator_cipher = initiator
        .into_cipher()
        .expect("initiator cipher successful");
    let mut responder_cipher = responder
        .into_cipher()
        .expect("responder cipher successful");

    // Test bidirectional communication
    let msg1 = b"hello from initiator";
    let encrypted1 = initiator_cipher.encrypt(msg1);

    // Responder decrypts
    let len1 = responder_cipher
        .decrypt_length(encrypted1[..ENCRYPTED_LENGTH_SIZE].try_into().unwrap())
        .expect("length decryption successful");
    assert_eq!(len1, u16::try_from(msg1.len()).unwrap());
    let decrypted1 = responder_cipher
        .decrypt_message(&encrypted1[ENCRYPTED_LENGTH_SIZE..])
        .expect("message decryption successful");
    assert_eq!(decrypted1, msg1);

    // Responder sends back
    let msg2 = b"hello from responder";
    let encrypted2 = responder_cipher.encrypt(msg2);

    // Initiator decrypts
    let len2 = initiator_cipher
        .decrypt_length(encrypted2[..ENCRYPTED_LENGTH_SIZE].try_into().unwrap())
        .expect("length decryption successful");
    assert_eq!(len2, u16::try_from(msg2.len()).unwrap());
    let decrypted2 = initiator_cipher
        .decrypt_message(&encrypted2[ENCRYPTED_LENGTH_SIZE..])
        .expect("message decryption successful");
    assert_eq!(decrypted2, msg2);
}

// =============================================================================
// NoiseConnection Integration Tests
// =============================================================================

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use super::cipher::MAC_SIZE;
use super::connection::NoiseConnection;

#[test]
fn noise_connection_handshake_and_messages() {
    let timeout = Duration::from_secs(5);

    // Use BOLT 8 test vector keys for determinism
    let initiator_static =
        secret_key("1111111111111111111111111111111111111111111111111111111111111111");
    let initiator_ephemeral =
        secret_key("1212121212121212121212121212121212121212121212121212121212121212");
    let responder_static =
        secret_key("2121212121212121212121212121212121212121212121212121212121212121");
    let responder_ephemeral =
        secret_key("2222222222222222222222222222222222222222222222222222222222222222");

    let secp = secp256k1::Secp256k1::new();
    let responder_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &responder_static);

    // Bind to a random available port
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener bind successful");
    let addr = listener.local_addr().expect("bound address");

    // Spawn responder thread
    let responder_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection accepted");
        stream.set_read_timeout(Some(timeout)).unwrap();
        stream.set_write_timeout(Some(timeout)).unwrap();

        // Perform handshake as responder
        let mut handshake = NoiseHandshake::new_responder(responder_static, responder_ephemeral);

        let mut act_one = [0u8; ACT_ONE_SIZE];
        stream
            .read_exact(&mut act_one)
            .expect("read act one successful");

        let act_two = handshake
            .process_act_one(&act_one)
            .expect("process act one successful");
        stream
            .write_all(&act_two)
            .expect("write act two successful");

        let mut act_three = [0u8; ACT_THREE_SIZE];
        stream
            .read_exact(&mut act_three)
            .expect("read act three successful");

        handshake
            .process_act_three(&act_three)
            .expect("process act three successful");

        let mut cipher = handshake
            .into_cipher()
            .expect("cipher conversion successful");

        // Receive message from initiator
        let mut encrypted_len = [0u8; ENCRYPTED_LENGTH_SIZE];
        stream
            .read_exact(&mut encrypted_len)
            .expect("read encrypted length successful");
        let msg_len = cipher
            .decrypt_length(&encrypted_len)
            .expect("length decryption successful");

        let mut encrypted_msg = vec![0u8; usize::from(msg_len) + MAC_SIZE];
        stream
            .read_exact(&mut encrypted_msg)
            .expect("read message successful");
        let msg = cipher
            .decrypt_message(&encrypted_msg)
            .expect("message decryption successful");

        assert_eq!(msg, b"hello from initiator");

        // Send response
        let response = cipher.encrypt(b"hello from responder");
        stream
            .write_all(&response)
            .expect("write response successful");

        // Receive second message
        stream
            .read_exact(&mut encrypted_len)
            .expect("read length successful");
        let msg_len = cipher
            .decrypt_length(&encrypted_len)
            .expect("length decryption successful");

        let mut encrypted_msg = vec![0u8; usize::from(msg_len) + MAC_SIZE];
        stream
            .read_exact(&mut encrypted_msg)
            .expect("read message successful");
        let msg = cipher
            .decrypt_message(&encrypted_msg)
            .expect("message decryption successful");

        assert_eq!(msg, b"goodbye");
    });

    // Connect as initiator using NoiseConnection
    let mut conn = NoiseConnection::connect(
        addr,
        responder_pubkey,
        initiator_static,
        initiator_ephemeral,
        timeout,
    )
    .expect("noise connection successful");

    // Send message
    conn.send_message(b"hello from initiator")
        .expect("send message successful");

    // Receive response
    let response = conn.recv_message().expect("receive message successful");
    assert_eq!(response, b"hello from responder");

    // Send another message
    conn.send_message(b"goodbye")
        .expect("send message successful");

    // Wait for responder thread
    responder_handle
        .join()
        .expect("responder thread finished cleanly");
}
