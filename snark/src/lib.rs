use ark_ff::{PrimeField, ToBytes};
use core::fmt::Debug;
use ark_relations::r1cs::ConstraintSynthesizer;
use rand::{CryptoRng, RngCore};

pub type Error = Box<dyn ark_std::error::Error>;

pub trait SNARK<F: PrimeField> {
    type ProvingKey: Clone;
    type VerifyingKey: Clone + ToBytes;
    type Proof: Clone;
    type ProcessedVerifyingKey: Clone + Default;

    fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<
        (
            <Self as SNARK<F>>::ProvingKey,
            <Self as SNARK<F>>::VerifyingKey,
        ),
        Error,
    >;

    fn prove<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit_pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        circuit_vk: &Self::VerifyingKey,
        public_input: &Vec<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;

    fn process_vk(circuit_vk: &Self::VerifyingKey) -> Result<Self::ProcessedVerifyingKey, Error>;

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        public_input: &Vec<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}

pub trait CircuitSpecificSetupSNARK<F: PrimeField>: SNARK<F> {
    fn setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<
        (
            <Self as SNARK<F>>::ProvingKey,
            <Self as SNARK<F>>::VerifyingKey,
        ),
        Error,
    > {
        <Self as SNARK<F>>::circuit_specific_setup(circuit, rng)
    }
}

pub enum UniversalSetupIndexResult<KeyPair, Bound> {
    Successful(KeyPair),
    NeedLargerBound(Bound),
}

pub trait UniversalSetupSNARK<F: PrimeField>: SNARK<F> {
    type ComputationBound: Clone + Default + Debug;
    type PublicParameters: Clone + Debug;

    fn universal_setup<R: RngCore + CryptoRng>(
        compute_bound: &Self::ComputationBound,
        rng: &mut R,
    ) -> Result<Self::PublicParameters, Error>;

    fn index<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        pp: &Self::PublicParameters,
        circuit: C,
        rng: &mut R,
    ) -> Result<
        UniversalSetupIndexResult<
            (
                <Self as SNARK<F>>::ProvingKey,
                <Self as SNARK<F>>::VerifyingKey,
            ),
            Self::ComputationBound,
        >,
        Error,
    >;
}
