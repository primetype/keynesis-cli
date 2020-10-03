use keynesis::{PrivateIdentity, PublicIdentity, Seed};
use rand_core::{CryptoRng, RngCore};
use tokio::io;

#[derive(Debug)]
pub struct Identity {
    seed: Seed,
    identity: PrivateIdentity,
}

impl Identity {
    /// generate a new identity with the given RNG
    ///
    pub fn generate_new<RNG>(rng: &mut RNG) -> Self
    where
        RNG: CryptoRng + RngCore,
    {
        let seed = Seed::generate(rng);
        let identity = PrivateIdentity::from_seed(seed.clone());
        Self { seed, identity }
    }

    pub async fn import<IN>(reader: &mut IN) -> io::Result<Self>
    where
        IN: io::AsyncReadExt + Unpin,
    {
        let mut bytes = [0; Seed::SIZE * 2];
        let mut seed = [0; Seed::SIZE];
        reader.read_exact(&mut bytes).await?;

        hex::decode_to_slice(bytes.as_ref(), &mut seed)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let seed = Seed::from(seed);
        let identity = PrivateIdentity::from_seed(seed.clone());
        Ok(Self { seed, identity })
    }

    pub async fn export<OUT>(&self, out: &mut OUT) -> io::Result<u64>
    where
        OUT: io::AsyncWrite + Unpin,
    {
        let export = self.seed.to_string();
        let mut export = export.as_bytes();
        io::copy(&mut export, out).await
    }

    pub(crate) fn private_key(&self) -> &PrivateIdentity {
        &self.identity
    }

    pub fn public_id(&self) -> PublicIdentity {
        self.identity.public_id()
    }
}
