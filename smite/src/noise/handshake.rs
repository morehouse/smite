//! Noise protocol handshake implementation.

// All panics in this module are unreachable: state checks before each expect()
// guarantee the value is set.
#![allow(clippy::missing_panics_doc)]

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use sha2::{Digest, Sha256};

use super::cipher::{NoiseCipher, decrypt_with_ad, encrypt_with_ad, hkdf_two_keys};
use super::error::NoiseError;

/// Protocol name used to initialize the handshake hash.
const PROTOCOL_NAME: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";

/// Prologue mixed into handshake hash after protocol name.
const PROLOGUE: &[u8] = b"lightning";

/// Handshake version byte (0 = no deviation from spec).
const VERSION: u8 = 0;

/// Act One message size: 1 (version) + 33 (pubkey) + 16 (MAC)
pub const ACT_ONE_SIZE: usize = 50;

/// Act Two message size: 1 (version) + 33 (pubkey) + 16 (MAC)
pub const ACT_TWO_SIZE: usize = 50;

/// Act Three message size: 1 (version) + 33 (encrypted pubkey) + 16 (MAC) + 16 (MAC)
pub const ACT_THREE_SIZE: usize = 66;

/// Role in the handshake.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// State machine for the Noise handshake.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    /// Initiator: ready to generate Act One
    InitiatorStart,
    /// Initiator: sent Act One, awaiting Act Two
    InitiatorAwaitingActTwo,
    /// Responder: ready to receive Act One
    ResponderStart,
    /// Responder: sent Act Two, awaiting Act Three
    ResponderAwaitingActThree,
    /// Handshake complete
    Complete,
}

/// Noise protocol handshake for Lightning (BOLT 8).
///
/// Implements the `Noise_XK` pattern where:
/// - Initiator knows responder's static public key beforehand
/// - Responder's identity is hidden (never transmitted)
/// - Initiator's identity is encrypted in Act Three
pub struct NoiseHandshake {
    role: Role,
    state: HandshakeState,
    /// Chaining key - accumulated ECDH outputs
    ck: [u8; 32],
    /// Handshake hash - accumulated transcript
    h: [u8; 32],
    /// Our static keypair
    local_static: SecretKey,
    /// Our ephemeral keypair
    local_ephemeral: SecretKey,
    /// Remote static public key (known beforehand for initiator, learned in Act Three for responder)
    remote_static: Option<PublicKey>,
    /// Remote ephemeral public key (learned during handshake)
    remote_ephemeral: Option<PublicKey>,
    /// Temporary key from Act Two HKDF (needed for Act Three)
    temp_k2: Option<[u8; 32]>,
    /// secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl NoiseHandshake {
    /// Creates a new handshake as the initiator.
    ///
    /// # Arguments
    /// - `local_static` - Our static private key (node identity)
    /// - `local_ephemeral` - Our ephemeral private key (must be random for security)
    /// - `remote_static` - The responder's known static public key
    #[must_use]
    pub fn new_initiator(
        local_static: SecretKey,
        local_ephemeral: SecretKey,
        remote_static: PublicKey,
    ) -> Self {
        let secp = Secp256k1::new();
        let (ck, h) = Self::initialize_state(&remote_static);

        Self {
            role: Role::Initiator,
            state: HandshakeState::InitiatorStart,
            ck,
            h,
            local_static,
            local_ephemeral,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            temp_k2: None,
            secp,
        }
    }

    /// Creates a new handshake as the responder.
    ///
    /// # Arguments
    /// - `local_static` - Our static private key (node identity)
    /// - `local_ephemeral` - Our ephemeral private key (must be random for security)
    #[must_use]
    pub fn new_responder(local_static: SecretKey, local_ephemeral: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let local_static_pub = PublicKey::from_secret_key(&secp, &local_static);
        let (ck, h) = Self::initialize_state(&local_static_pub);

        Self {
            role: Role::Responder,
            state: HandshakeState::ResponderStart,
            ck,
            h,
            local_static,
            local_ephemeral,
            remote_static: None,
            remote_ephemeral: None,
            temp_k2: None,
            secp,
        }
    }

    /// Initialize handshake state per BOLT 8.
    fn initialize_state(responder_static: &PublicKey) -> ([u8; 32], [u8; 32]) {
        // h = SHA256(protocolName)
        // ck = h
        let ck: [u8; 32] = Sha256::digest(PROTOCOL_NAME).into();

        // h = SHA256(h || prologue)
        let h: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(ck);
            hasher.update(PROLOGUE);
            hasher.finalize().into()
        };

        // h = SHA256(h || rs.pub.serializeCompressed())
        let h: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(h);
            hasher.update(responder_static.serialize());
            hasher.finalize().into()
        };

        (ck, h)
    }

    // ===== Initiator Methods =====

    /// Generates Act One message (initiator).
    ///
    /// Returns 50 bytes: `version || ephemeral_pubkey || MAC`
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::InvalidState` if not in the correct state.
    pub fn get_act_one(&mut self) -> Result<[u8; ACT_ONE_SIZE], NoiseError> {
        if self.state != HandshakeState::InitiatorStart {
            return Err(NoiseError::InvalidState);
        }

        let e_pub = PublicKey::from_secret_key(&self.secp, &self.local_ephemeral);

        // h = SHA256(h || e.pub)
        self.mix_hash(&e_pub.serialize());

        // es = ECDH(e.priv, rs)
        let rs = self.remote_static.expect("remote static key");
        let es = ecdh(&self.local_ephemeral, &rs);

        // ck, temp_k1 = HKDF(ck, es)
        let (ck, temp_k1) = hkdf_two_keys(&self.ck, &es);
        self.ck = ck;

        // c = encryptWithAD(temp_k1, 0, h, empty)
        let c = encrypt_with_ad(&temp_k1, 0, &self.h, &[]);

        // h = SHA256(h || c)
        self.mix_hash(&c);

        // Build message: version || e.pub || c
        let mut msg = [0u8; ACT_ONE_SIZE];
        msg[0] = VERSION;
        msg[1..34].copy_from_slice(&e_pub.serialize());
        msg[34..].copy_from_slice(&c);

        self.state = HandshakeState::InitiatorAwaitingActTwo;
        Ok(msg)
    }

    /// Processes Act Two message and generates Act Three (initiator).
    ///
    /// Returns the Act Three message (66 bytes) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if version is invalid, public key is malformed, or MAC verification fails.
    pub fn process_act_two(
        &mut self,
        act_two: &[u8; ACT_TWO_SIZE],
    ) -> Result<[u8; ACT_THREE_SIZE], NoiseError> {
        if self.state != HandshakeState::InitiatorAwaitingActTwo {
            return Err(NoiseError::InvalidState);
        }

        // Parse: version || re || c
        let version = act_two[0];
        let re_bytes = &act_two[1..34];
        let c = &act_two[34..];

        // Check version
        if version != VERSION {
            return Err(NoiseError::ActTwoBadVersion(version));
        }

        // Parse remote ephemeral public key
        let re = PublicKey::from_slice(re_bytes).map_err(|_| NoiseError::ActTwoBadPubkey)?;
        self.remote_ephemeral = Some(re);

        // h = SHA256(h || re)
        self.mix_hash(re_bytes);

        // ee = ECDH(e.priv, re)
        let ee = ecdh(&self.local_ephemeral, &re);

        // ck, temp_k2 = HKDF(ck, ee)
        let (ck, temp_k2) = hkdf_two_keys(&self.ck, &ee);
        self.ck = ck;
        self.temp_k2 = Some(temp_k2);

        // Decrypt and verify MAC
        decrypt_with_ad(&temp_k2, 0, &self.h, c).map_err(|_| NoiseError::ActTwoBadTag)?;

        // h = SHA256(h || c)
        self.mix_hash(c);

        // Build Act Three
        Ok(self.build_act_three())
    }

    /// Builds Act Three message (initiator).
    fn build_act_three(&mut self) -> [u8; ACT_THREE_SIZE] {
        let temp_k2 = self.temp_k2.expect("temp_k2 from process_act_two");

        // Get our static public key
        let s_pub = PublicKey::from_secret_key(&self.secp, &self.local_static);

        // c = encryptWithAD(temp_k2, 1, h, s.pub)
        let c = encrypt_with_ad(&temp_k2, 1, &self.h, &s_pub.serialize());

        // h = SHA256(h || c)
        self.mix_hash(&c);

        // se = ECDH(s.priv, re)
        let re = self
            .remote_ephemeral
            .expect("remote_ephemeral from process_act_two");
        let se = ecdh(&self.local_static, &re);

        // ck, temp_k3 = HKDF(ck, se)
        let (ck, temp_k3) = hkdf_two_keys(&self.ck, &se);
        self.ck = ck;

        // t = encryptWithAD(temp_k3, 0, h, empty)
        let t = encrypt_with_ad(&temp_k3, 0, &self.h, &[]);

        // Build message: version || c || t
        let mut msg = [0u8; ACT_THREE_SIZE];
        msg[0] = VERSION;
        msg[1..50].copy_from_slice(&c);
        msg[50..].copy_from_slice(&t);

        self.state = HandshakeState::Complete;
        msg
    }

    // ===== Responder Methods =====

    /// Processes Act One message and generates Act Two (responder).
    ///
    /// Returns the Act Two message (50 bytes) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if version is invalid, public key is malformed, or MAC verification fails.
    pub fn process_act_one(
        &mut self,
        act_one: &[u8; ACT_ONE_SIZE],
    ) -> Result<[u8; ACT_TWO_SIZE], NoiseError> {
        if self.state != HandshakeState::ResponderStart {
            return Err(NoiseError::InvalidState);
        }

        // Parse: version || re || c
        let version = act_one[0];
        let re_bytes = &act_one[1..34];
        let c = &act_one[34..];

        // Check version
        if version != VERSION {
            return Err(NoiseError::ActOneBadVersion(version));
        }

        // Parse remote ephemeral public key
        let re = PublicKey::from_slice(re_bytes).map_err(|_| NoiseError::ActOneBadPubkey)?;
        self.remote_ephemeral = Some(re);

        // h = SHA256(h || re)
        self.mix_hash(re_bytes);

        // es = ECDH(s.priv, re)
        let es = ecdh(&self.local_static, &re);

        // ck, temp_k1 = HKDF(ck, es)
        let (ck, temp_k1) = hkdf_two_keys(&self.ck, &es);
        self.ck = ck;

        // Decrypt and verify MAC
        decrypt_with_ad(&temp_k1, 0, &self.h, c).map_err(|_| NoiseError::ActOneBadTag)?;

        // h = SHA256(h || c)
        self.mix_hash(c);

        // Build Act Two
        Ok(self.build_act_two())
    }

    /// Builds Act Two message (responder).
    fn build_act_two(&mut self) -> [u8; ACT_TWO_SIZE] {
        let e_pub = PublicKey::from_secret_key(&self.secp, &self.local_ephemeral);

        // h = SHA256(h || e.pub)
        self.mix_hash(&e_pub.serialize());

        // ee = ECDH(e.priv, re)
        let re = self
            .remote_ephemeral
            .expect("remote_ephemeral from process_act_one");
        let ee = ecdh(&self.local_ephemeral, &re);

        // ck, temp_k2 = HKDF(ck, ee)
        let (ck, temp_k2) = hkdf_two_keys(&self.ck, &ee);
        self.ck = ck;
        self.temp_k2 = Some(temp_k2);

        // c = encryptWithAD(temp_k2, 0, h, empty)
        let c = encrypt_with_ad(&temp_k2, 0, &self.h, &[]);

        // h = SHA256(h || c)
        self.mix_hash(&c);

        // Build message: version || e.pub || c
        let mut msg = [0u8; ACT_TWO_SIZE];
        msg[0] = VERSION;
        msg[1..34].copy_from_slice(&e_pub.serialize());
        msg[34..].copy_from_slice(&c);

        self.state = HandshakeState::ResponderAwaitingActThree;
        msg
    }

    /// Processes Act Three message (responder).
    ///
    /// Returns the remote's static public key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if version is invalid, ciphertext MAC fails, public key is malformed,
    /// or final MAC verification fails.
    pub fn process_act_three(
        &mut self,
        act_three: &[u8; ACT_THREE_SIZE],
    ) -> Result<PublicKey, NoiseError> {
        if self.state != HandshakeState::ResponderAwaitingActThree {
            return Err(NoiseError::InvalidState);
        }

        // Parse: version || c || t
        let version = act_three[0];
        let c = &act_three[1..50];
        let t = &act_three[50..];

        // Check version
        if version != VERSION {
            return Err(NoiseError::ActThreeBadVersion(version));
        }

        let temp_k2 = self.temp_k2.expect("temp_k2 from build_act_two");

        // rs = decryptWithAD(temp_k2, 1, h, c)
        let rs_bytes = decrypt_with_ad(&temp_k2, 1, &self.h, c)
            .map_err(|_| NoiseError::ActThreeBadCiphertext)?;

        // Parse remote static public key
        let rs = PublicKey::from_slice(&rs_bytes).map_err(|_| NoiseError::ActThreeBadPubkey)?;
        self.remote_static = Some(rs);

        // h = SHA256(h || c)
        self.mix_hash(c);

        // se = ECDH(e.priv, rs)
        let se = ecdh(&self.local_ephemeral, &rs);

        // ck, temp_k3 = HKDF(ck, se)
        let (ck, temp_k3) = hkdf_two_keys(&self.ck, &se);
        self.ck = ck;

        // Decrypt and verify final MAC
        decrypt_with_ad(&temp_k3, 0, &self.h, t).map_err(|_| NoiseError::ActThreeBadTag)?;

        self.state = HandshakeState::Complete;
        Ok(rs)
    }

    // ===== Cipher Extraction =====

    /// Returns the final send and receive keys, adjusted for role.
    ///
    /// Returns `(send_key, recv_key)` for this party.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::HandshakeIncomplete` if the handshake is not complete.
    pub fn get_final_keys(&self) -> Result<([u8; 32], [u8; 32]), NoiseError> {
        if self.state != HandshakeState::Complete {
            return Err(NoiseError::HandshakeIncomplete);
        }

        // Derive keys: sk, rk = HKDF(ck, empty)
        // sk = initiator's send key, rk = initiator's recv key
        let (sk, rk) = hkdf_two_keys(&self.ck, &[]);

        // Adjust for role
        match self.role {
            Role::Initiator => Ok((sk, rk)),
            Role::Responder => Ok((rk, sk)),
        }
    }

    /// Extracts the cipher for post-handshake message encryption.
    ///
    /// Consumes the handshake and returns a `NoiseCipher` for encrypting/decrypting messages.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::HandshakeIncomplete` if the handshake is not complete.
    pub fn into_cipher(self) -> Result<NoiseCipher, NoiseError> {
        let (send_key, recv_key) = self.get_final_keys()?;
        Ok(NoiseCipher::new(send_key, recv_key, self.ck))
    }

    // ===== Helper Methods =====

    /// Mix data into the handshake hash.
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }
}

/// Perform ECDH: returns SHA256(x-coordinate of shared point).
fn ecdh(secret: &SecretKey, public: &PublicKey) -> [u8; 32] {
    SharedSecret::new(public, secret).secret_bytes()
}
