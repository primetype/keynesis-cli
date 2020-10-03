use keynesis::memsec::Scrubbed as _;
pub use rand_chacha::ChaChaRng;
use rand_core::{OsRng, RngCore as _, SeedableRng as _};
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// a Randomly generated seed or retrieved from a given input
#[derive(Debug, Clone)]
pub struct Seed(Vec<u8>);

impl Seed {
    /// generate a 256bits long random Seed
    ///
    /// It may be that calling this function blocks if called for the first time.
    /// this is because `OsRng` may fill up some internal buffer and perform
    /// some I/O with the operating system.
    ///
    /// # Error
    ///
    /// this function may return an error if the `OsRng` fails.
    ///
    pub fn try_random() -> Result<Self, rand_core::Error> {
        let mut bytes = vec![0; 32];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// generate a 256bits long random Seed
    ///
    /// It may be that calling this function blocks if called for the first time.
    /// this is because `OsRng` may fill up some internal buffer and perform
    /// some I/O with the operating system.
    ///
    /// # Panic
    ///
    /// this function may panic an error if the `OsRng` fails.
    ///
    pub fn random() -> Self {
        match Self::try_random() {
            Err(error) => panic!("{}", error),
            Ok(seed) => seed,
        }
    }

    /// to hexadecimal
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// from hexadecimal
    ///
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(s).map(Self)
    }

    /// get the `ChaChaRng`, a secure Pseudo Random Number Generator (PRNG).
    ///
    /// the advantage of using `ChaChaRng` is that it cannot fail to generate
    /// a random number.
    ///
    /// the first 32bytes (or less) of the `Seed` will be used. If less than
    /// 32 bytes are in the `Seed` then the remaining will be set to 0. If more
    /// then 32bytes then the left overs will be ignored.
    pub fn into_cha_cha_rng(self) -> ChaChaRng {
        debug_assert!(self.0.len() <= 32, "only the first 32bytes are used");
        let mut seed = [0; 32];
        seed[..self.0.len()].copy_from_slice(&self.0);
        ChaChaRng::from_seed(seed)
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.scrub()
    }
}

impl Default for Seed {
    fn default() -> Self {
        Self::random()
    }
}

impl Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_hex().fmt(f)
    }
}

impl FromStr for Seed {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Seed {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = vec![0; 32];
            g.fill_bytes(&mut bytes);
            Self(bytes)
        }
    }
}
