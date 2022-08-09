#![cfg_attr(not(feature = "std"), no_std)]

/// This file defines a substrate pallet for the Faceless protocol.
/// It includes the cryptographic verification logic for the following 
/// relevant zero-knowledge proofs:
/// 1. Verification of burn proof
/// 2. Verification of transfer proof

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use aibe::zk::burn::{BurnStatement, BurnProof, BurnVerifier};
    use aibe::zk::transfer::{TransferStatement, TransferProof, TransferVerifier};
    use borsh::de::BorshDeserialize;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
    // 'without_storage_info' is needed for storing variable-length Vec<u8> data in the StorageMap (Proofs below).
    #[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	// The pallet's runtime storage items.
	// https://docs.substrate.io/v3/runtime/storage
	#[pallet::storage]
    pub(super) type Proofs<T: Config> = StorageMap<_, Blake2_128Concat, Vec<u8>, (T::AccountId, T::BlockNumber)>; 

	// Pallets use events to inform users when important changes are made.
	// https://docs.substrate.io/v3/runtime/events-and-errors
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        BurnVerificationSuccess(T::AccountId, Vec<u8>),
        TransferVerificationSuccess(T::AccountId, Vec<u8>),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
        BurnVerificationFailure,
        TransferVerificationFailure,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
        /// A dispatchable that takes a burn statement and a burn proof as inputs, verifies the proof, and 
        /// emits an event that denotes the verification status.
		#[pallet::weight(1_000)]
		pub fn verify_burn(origin: OriginFor<T>, statement: Vec<u8>, proof: Vec<u8>) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://docs.substrate.io/v3/runtime/origins
			let sender = ensure_signed(origin)?;

            let bs = BurnStatement::try_from_slice(base64::decode(statement.as_slice()).unwrap().as_slice()).unwrap();
            let bp = BurnProof::try_from_slice(base64::decode(proof.as_slice()).unwrap().as_slice()).unwrap();

            let result = BurnVerifier::verify_proof(bs, bp);

            match result {
                Ok(()) => {
                    Self::deposit_event(Event::BurnVerificationSuccess(sender, proof));
                    Ok(())
                },
                Err(_) => {
                    Err(Error::<T>::BurnVerificationFailure.into())
                }
            }
		}

        /// A dispatchable that takes a transfer statement and a transfer proof as inputs, verifies the proof, and 
        /// emits an event that denotes the verification status.
		#[pallet::weight(10_000)]
		pub fn verify_transfer(origin: OriginFor<T>, statement: Vec<u8>, proof: Vec<u8>) -> DispatchResult {
            // Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://docs.substrate.io/v3/runtime/origins
			let sender = ensure_signed(origin)?;

            let bs = TransferStatement::try_from_slice(base64::decode(statement.as_slice()).unwrap().as_slice()).unwrap();
            let bp = TransferProof::try_from_slice(base64::decode(proof.as_slice()).unwrap().as_slice()).unwrap();

            let result = TransferVerifier::verify_proof(bs, bp);

            match result {
                Ok(()) => {
                    Self::deposit_event(Event::TransferVerificationSuccess(sender, proof));
                    Ok(())
                },
                Err(_) => {
                    Err(Error::<T>::TransferVerificationFailure.into())
                }
            }
		}
	}
}
