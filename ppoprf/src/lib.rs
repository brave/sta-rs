//! This module defines the combined functionality for producing a
//! puncturable partially oblivious pseudorandom function (PPOPRF)
//! protocol. The protocol combines the PPOPRF of [Tyagi et
//! al.](https://eprint.iacr.org/2021/864.pdf) with the classic GGM
//! puncturable PRF.
//!
//! The result is a POPRF that can provide forward-security guarantees
//! related to the pseudorandomness of client-side outputs, by allowing
//! the puncturing of metadata tags from the server secret key. Such
//! guarantees hold when clients reveal POPRF outputs for a metadata tag
//! `t`, after `t` has been punctured from the secret key. This
//! functionality is used to provide forward-secure randomness to
//! clients in the STAR protocol.

pub mod ggm;
pub mod ppoprf;

pub trait PPRF {
    fn setup() -> Self;
    fn eval(&self, input: &[u8], output: &mut [u8]);
    fn puncture(&mut self, input: &[u8]);
}
