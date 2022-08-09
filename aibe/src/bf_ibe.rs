use crate::errors::IbeError;
use crate::traits::IdentityBasedEncryption;

use crate::utils::{baby_step_giant_step, hash_to_g2};

use bn::{pairing, Fr as Scalar, Group, Gt, G1, G2};

use rand::Rng;

pub type CipherText = (G1, Gt);
pub type PlainData = Scalar;
pub type MasterSecretKey = Scalar;
pub type MasterPublicKey = G1;
pub type IdSecretKey = G2;

/// Dan Boneh and Matthew K. Franklin. Identity-based encryption from the weil pairing. SIAM J. Comput., 32(3):586{615, 2003.
///
///
/// # Examples
///
/// ```
/// use aibe::traits::{IdentityBasedEncryption};
/// use aibe::bf_ibe::{BFIbe};
/// use rand::Rng;
/// let mut rng = rand::thread_rng();
/// let mut ibe = BFIbe::new(rng);
/// ```
#[derive(Debug)]
pub struct BFIbe<R> {
    rng: R,
}

impl<R> BFIbe<R>
where
    R: Rng,
{
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    pub fn encrypt_internal(
        &mut self,
        msg: &PlainData,
        id: &str,
        mpk: &MasterPublicKey,
    ) -> (CipherText, G2, Scalar) {
        let hash_id = hash_to_g2(id.as_bytes());
        let r = Scalar::random(&mut self.rng);
        let c1 = G1::one() * r;
        let c2_part1 = pairing(G1::one(), G2::one()).pow(*msg);
        let c2_part2 = pairing(*mpk, hash_id).pow(r);
        let c2 = c2_part1 * c2_part2;

        ((c1, c2), hash_id, r)
    }

    pub fn encrypt_correlated_internal(
        &mut self,
        msg: &PlainData,
        ids: (&str, &str),
        mpks: (&MasterPublicKey, &MasterPublicKey),
    ) -> ((CipherText, CipherText), (G2, G2), Scalar) {
        let r = Scalar::random(&mut self.rng);
        let c1 = G1::one() * r;
        let c2_part1 = pairing(G1::one(), G2::one() * *msg);

        let hash_id1 = hash_to_g2(ids.0.as_bytes());
        let c2_part2 = pairing(*mpks.0, hash_id1 * r);
        let cipher_1 = (c1, c2_part1 * c2_part2);

        let hash_id2 = hash_to_g2(ids.1.as_bytes());
        let c2_part2 = pairing(*mpks.1, hash_id2 * r);
        let cipher_2 = (c1, c2_part1 * c2_part2);

        ((cipher_1, cipher_2), (hash_id1, hash_id2), r)
    }
}

impl<R> IdentityBasedEncryption for BFIbe<R>
where
    R: Rng,
{
    type CipherText = (G1, Gt);
    type PlainData = Scalar;
    type MasterSecretKey = Scalar;
    type MasterPublicKey = G1;
    type IdSecretKey = G2;

    /// Generate a pair of master secret key and master public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use aibe::traits::IdentityBasedEncryption;
    /// # use aibe::bf_ibe::BFIbe;
    /// # use rand::Rng;
    /// let mut rng = rand::thread_rng();
    /// let mut ibe = BFIbe::new(rng);
    /// let (msk, mpk) = ibe.generate_key();
    /// ```
    fn generate_key(&mut self) -> (Self::MasterSecretKey, Self::MasterPublicKey) {
        let msk = Scalar::random(&mut self.rng);
        let mpk = G1::one() * msk;
        (msk, mpk)
    }

    /// Encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// # use aibe::traits::IdentityBasedEncryption;
    /// # use aibe::bf_ibe::BFIbe;
    /// # use rand::Rng;
    /// # use aibe::utils::u64_to_scalar;
    /// let mut rng = rand::thread_rng();
    /// let mut ibe = BFIbe::new(rng);
    /// let (_, mpk) = ibe.generate_key();
    /// let cipher = ibe.encrypt(&u64_to_scalar(35), "alice", &mpk);
    /// ```
    fn encrypt(
        &mut self,
        msg: &Self::PlainData,
        id: &str,
        mpk: &Self::MasterPublicKey,
    ) -> Self::CipherText {
        let (c, _, _) = self.encrypt_internal(msg, id, mpk);

        c
    }

    /// Correlated encryption of the same message, such that two ciphertexts have the same 1st component (randomness).
    ///
    /// # Examples
    ///
    /// ```
    /// # use aibe::traits::IdentityBasedEncryption;
    /// # use aibe::bf_ibe::BFIbe;
    /// # use rand::Rng;
    /// # use aibe::utils::u64_to_scalar;
    /// let mut rng = rand::thread_rng();
    /// let mut ibe = BFIbe::new(rng);
    /// let (_, mpk1) = ibe.generate_key();
    /// let (_, mpk2) = ibe.generate_key();
    /// let (cipher1, cipher2) = ibe.encrypt_correlated(&u64_to_scalar(35), ("alice", "bob"), (&mpk1, &mpk2));
    /// ```
    fn encrypt_correlated(
        &mut self,
        msg: &Self::PlainData,
        ids: (&str, &str),
        mpks: (&Self::MasterPublicKey, &Self::MasterPublicKey),
    ) -> (Self::CipherText, Self::CipherText) {
        let (c, _, _) = self.encrypt_correlated_internal(msg, ids, mpks);

        c
    }

    /// Extract secret key for an ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use aibe::traits::IdentityBasedEncryption;
    /// # use aibe::bf_ibe::BFIbe;
    /// # use rand::Rng;
    /// let mut rng = rand::thread_rng();
    /// let mut ibe = BFIbe::new(rng);
    /// let (msk, _) = ibe.generate_key();
    /// let sk = ibe.extract("alice", &msk);
    /// ```
    fn extract(&mut self, id: &str, msk: &Self::MasterSecretKey) -> Self::IdSecretKey {
        let hash_id = hash_to_g2(id.as_bytes());
        hash_id * *msk
    }

    /// Decryption.
    ///
    /// # Examples
    ///
    /// ```
    /// # use aibe::traits::IdentityBasedEncryption;
    /// # use aibe::bf_ibe::BFIbe;
    /// # use rand::Rng;
    /// # use aibe::utils::u64_to_scalar;
    /// # let mut rng = rand::thread_rng(); 
    /// # let mut ibe = BFIbe::new(rng); 
    /// # let (msk, mpk) = ibe.generate_key();
    /// # let cipher = ibe.encrypt(&u64_to_scalar(35), "alice", &mpk);
    /// # let sk = ibe.extract("alice", &msk);
    /// // Following the examples of `encrypt` and `extract`
    /// let result = ibe.decrypt(&cipher, "alice", &sk, 100);
    /// # result.unwrap();
    /// ```

    fn decrypt(
        &mut self,
        cipher: &Self::CipherText,
        _id: &str,
        sk: &Self::IdSecretKey,
        bound: u64,
    ) -> Result<Self::PlainData, IbeError> {
        let (c1, c2) = cipher;
        let result = pairing(*c1, *sk)
            .inverse()
            .ok_or(IbeError::GtInverseError)?;
        let result = *c2 * result;

        baby_step_giant_step(result, pairing(G1::one(), G2::one()), bound)
    }
}
