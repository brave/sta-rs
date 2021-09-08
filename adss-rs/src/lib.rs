use sharks::Sharks;
use std::error::Error;
use std::fmt;
use strobe_rs::{SecParam, Strobe};

mod rng;
use crate::rng::StrobeRng;

#[derive(Debug, Clone, Copy)]
pub struct AccessStructure {
    threshold: u32,
}

/// An `AccessStructure` defines how a message is to be split among multiple parties
///
/// In particular this determines how many shares will be issued and what threshold of the shares
/// are needed to reconstruct the original `Commune`
impl AccessStructure {
    /// Convert this `AccessStructure` to a byte array.
    pub fn to_bytes(&self) -> [u8; 4] {
        self.threshold.to_le_bytes()
    }
}

#[allow(non_snake_case)]
impl From<AccessStructure> for Sharks {
    fn from(A: AccessStructure) -> Sharks {
        Sharks(A.threshold)
    }
}

/// A `Commune` is a unique instance of sharing across multiple parties
///
/// It consists of an access structure defining the parameters of the sharing, a secret message
/// which will be shared, "random coins" which provide strong but possibly non-uniform entropy
/// and an optional STROBE transcript which can include extra data which will be authenticated.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Commune {
    /// `A` is an `AccessStructure` defining the sharing
    A: AccessStructure,
    /// `M` is the message to be shared
    M: Vec<u8>,
    /// `R` are the "random coins" which may not be uniform
    R: Vec<u8>,
    /// `T` is a `Strobe` transcript which forms optional tags to be authenticated
    T: Option<Strobe>,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Share {
    A: AccessStructure,
    S: sharks::Share,
    /// C is the encrypted message
    C: Vec<u8>,
    /// D is the encrypted randomness
    D: Vec<u8>,
    /// J is a MAC showing knowledge of A, M, R, and T
    J: [u8; 64],
    T: (),
}
impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
         .field("S", &self.S)
         .finish()
    }
}

#[allow(non_snake_case)]
impl Commune {
    pub fn new(threshold: u32, message: Vec<u8>, randomness: Vec<u8>, transcript: Option<Strobe>) -> Self {
        Commune{ A: AccessStructure{ threshold }, M: message, R: randomness, T: transcript }
    }

    pub fn share(self) -> Share {
        // H4κ = (A, M, R, T)
        let mut transcript = self
            .T
            .unwrap_or_else(|| Strobe::new(b"adss", SecParam::B128));
        transcript.ad(&self.A.to_bytes(), false);
        transcript.ad(&self.M, false);
        transcript.key(&self.R, false);

        // J is a MAC which authenticates A, M, R, and T
        let mut J = [0u8; 64];
        transcript.send_mac(&mut J, false);

        // K is the derived key used to encrypt the message and our "random coins"
        let mut K = [0u8; 16];
        transcript.prf(&mut K, false);

        // L is the randomness to be fed to secret sharing polynomial generation
        let mut L: StrobeRng = transcript.into();

        let mut key = Strobe::new(b"adss encrypt", SecParam::B128);
        key.key(&K, false);

        // C is the encrypted message
        let mut C: Vec<u8> = vec![0; self.M.len()];
        C.copy_from_slice(&self.M);
        key.send_enc(&mut C, false);

        // D is the encrypted randomness
        let mut D: Vec<u8> = vec![0; self.R.len()];
        D.copy_from_slice(&self.R);
        key.send_enc(&mut D, false);

        // Generate a random share
        let mut K_vec: Vec<u8> = K.to_vec();
        K_vec.extend(vec![0u8; 16]);
        let polys = Sharks::from(self.A).dealer_rng(&K_vec, &mut L);
        let S = polys.gen(&mut rand::thread_rng());
        Share {
            A: self.A,
            S,
            C,
            D,
            J,
            T: (),
        }
    }

    pub fn get_message(&self) -> Vec<u8> {
        self.M.clone()
    }

    fn verify(&self, J: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let mut transcript = self
            .clone()
            .T
            .unwrap_or_else(|| Strobe::new(b"adss", SecParam::B128));
        transcript.ad(&self.A.to_bytes(), false);
        transcript.ad(&self.M, false);
        transcript.key(&self.R, false);


        transcript
            .recv_mac(J)
            .map_err(|_| "Mac validation failed".into())
    }
}

#[allow(non_snake_case)]
pub fn recover<'a, T>(shares: T) -> Result<Commune, Box<dyn Error>>
where
    T: IntoIterator<Item = &'a Share>,
    T::IntoIter: Iterator<Item = &'a Share>,
{
    let mut shares = shares.into_iter().peekable();
    let s = &(*shares.peek().ok_or("no shares passed")?).clone();
    let shares: Vec<sharks::Share> = shares.cloned().map(|s| s.S).collect();
    let key = Sharks::from(s.A).recover(&shares)?;
    let K = key[..16].to_vec();

    let mut key = Strobe::new(b"adss encrypt", SecParam::B128);
    key.key(&K, false);

    // M is the message
    let mut M: Vec<u8> = vec![0; s.C.len()];
    M.copy_from_slice(&s.C);
    key.recv_enc(&mut M, false);

    // R are the "random coins"
    let mut R: Vec<u8> = vec![0; s.D.len()];
    R.copy_from_slice(&s.D);
    key.recv_enc(&mut R, false);

    let c = Commune {
        A: s.A,
        M,
        R,
        T: None,
    };

    c.verify(&mut s.J.clone())?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use core::iter;

    use crate::*;

    #[test]
    fn it_works() {
        let c = Commune {
            A: AccessStructure { threshold: 50 },
            M: vec![1, 2, 3, 4],
            R: vec![5, 6, 7, 8],
            T: None,
        };

        let shares: Vec<Share> = iter::repeat_with(|| c.clone().share()).take(150).collect();

        let recovered = recover(&shares).unwrap();

        assert_eq!(c.M, recovered.M);
    }
}
