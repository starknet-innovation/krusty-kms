use super::{
    shared::{create_affine_point, verify_cipher_encrypts_balance},
    Audit, TransferParams, TransferProof,
};
use crate::{crypto::encrypt_for_auditor, TongoAccount};
use krusty_kms_common::{ElGamalCiphertext, KmsError, ProofOfTransfer, Range, Result};
use krusty_kms_crypto::{poseidon_hash_many, range, AuditPrefixData, AuditProver, StarkCurve};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

const TRANSFER_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7472616e73666572");

#[cfg(not(feature = "parallel"))]
fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (a(), b())
}

/// Validated inputs shared by each transfer construction phase.
pub(super) struct TransferBuildState<'a> {
    params: TransferParams,
    secret: &'a Felt,
    owner: ProjectivePoint,
    amount: u128,
    leftover: u128,
    generator: ProjectivePoint,
    generator_h: ProjectivePoint,
}

struct PreparedCiphertexts {
    randomness: Felt,
    leftover_randomness: Felt,
    amount_randomness: Vec<Felt>,
    leftover_randomness_values: Vec<Felt>,
    transfer_balance_l: ProjectivePoint,
    transfer_balance_r: ProjectivePoint,
    transfer_balance_self_l: ProjectivePoint,
    transfer_balance_self_r: ProjectivePoint,
    auxiliar_cipher: ElGamalCiphertext,
    auxiliar_cipher2: ElGamalCiphertext,
}

impl<'a> TransferBuildState<'a> {
    pub(super) fn new(account: &'a TongoAccount, params: TransferParams) -> Result<Self> {
        if params.amount == 0 {
            return Err(KmsError::InvalidAmount(
                "Amount must be greater than zero".to_string(),
            ));
        }
        if !account.has_sufficient_balance(params.amount) {
            return Err(KmsError::InsufficientBalance);
        }

        let secret = account.owner_private_key().expose_secret();
        let generator = StarkCurve::generator();
        verify_cipher_encrypts_balance(
            &params.current_balance,
            secret,
            account.balance(),
            &generator,
        )?;

        Ok(Self {
            amount: params.amount,
            leftover: account.balance() - params.amount,
            owner: account.owner_public_key().clone(),
            generator,
            generator_h: StarkCurve::generator_h(),
            secret,
            params,
        })
    }

    /// Run the phases in the same order as the TypeScript reference.
    pub(super) fn execute(self) -> Result<TransferProof> {
        let prepared = self.prepare_ciphertexts()?;
        let prefix = self.protocol_prefix(&prepared)?;
        let (range, range2) = self.prove_ranges(&prepared, &prefix)?;
        let proof = self.build_protocol_proof(&prepared, &prefix, range, range2)?;
        let new_balance_cipher = self.new_balance_cipher(&prepared)?;
        let (audit_balance, audit_transfer) = self.build_audits(&prepared, &new_balance_cipher)?;

        Ok(TransferProof {
            transfer_balance_l: prepared.transfer_balance_l,
            transfer_balance_r: prepared.transfer_balance_r,
            transfer_balance_self_l: prepared.transfer_balance_self_l,
            transfer_balance_self_r: prepared.transfer_balance_self_r,
            proof,
            auxiliar_cipher: prepared.auxiliar_cipher,
            auxiliar_cipher2: prepared.auxiliar_cipher2,
            new_balance_cipher,
            audit_balance,
            audit_transfer,
        })
    }

    fn prepare_ciphertexts(&self) -> Result<PreparedCiphertexts> {
        use krusty_kms_crypto::random::random_felts;

        let amount_randomness = random_felts(self.params.bit_size);
        let leftover_randomness_values = random_felts(self.params.bit_size);
        let randomness = range::compute_total_randomness(&amount_randomness)?;
        let leftover_randomness = range::compute_total_randomness(&leftover_randomness_values)?;
        let amount = Felt::from(self.amount);
        let leftover = Felt::from(self.leftover);
        let transfer_balance_self_l =
            add_scaled(&amount, &self.generator, &randomness, &self.owner);
        let transfer_balance_self_r = StarkCurve::mul(&randomness, Some(&self.generator));
        let transfer_balance_l = add_scaled(
            &amount,
            &self.generator,
            &randomness,
            &self.params.recipient_public_key,
        );
        let transfer_balance_r = StarkCurve::mul(&randomness, Some(&self.generator));
        let auxiliar_cipher = ElGamalCiphertext {
            l: add_scaled(&amount, &self.generator, &randomness, &self.generator_h),
            r: StarkCurve::mul(&randomness, Some(&self.generator)),
        };
        let auxiliar_cipher2 = ElGamalCiphertext {
            l: add_scaled(
                &leftover,
                &self.generator,
                &leftover_randomness,
                &self.generator_h,
            ),
            r: StarkCurve::mul(&leftover_randomness, Some(&self.generator)),
        };

        Ok(PreparedCiphertexts {
            randomness,
            leftover_randomness,
            amount_randomness,
            leftover_randomness_values,
            transfer_balance_l,
            transfer_balance_r,
            transfer_balance_self_l,
            transfer_balance_self_r,
            auxiliar_cipher,
            auxiliar_cipher2,
        })
    }

    fn protocol_prefix(&self, prepared: &PreparedCiphertexts) -> Result<Felt> {
        let owner = affine(&self.owner)?;
        let recipient = affine(&self.params.recipient_public_key)?;
        let current_l = affine(&self.params.current_balance.l)?;
        let current_r = affine(&self.params.current_balance.r)?;
        let tbs_l = affine(&prepared.transfer_balance_self_l)?;
        let tbs_r = affine(&prepared.transfer_balance_self_r)?;
        let tb_l = affine(&prepared.transfer_balance_l)?;
        let tb_r = affine(&prepared.transfer_balance_r)?;
        let auxiliary = affine(&prepared.auxiliar_cipher.l)?;
        let auxiliary_r = affine(&prepared.auxiliar_cipher.r)?;
        let auxiliary2 = affine(&prepared.auxiliar_cipher2.l)?;
        let auxiliary2_r = affine(&prepared.auxiliar_cipher2.r)?;

        Ok(poseidon_hash_many(&[
            self.params.chain_id,
            self.params.tongo_address,
            self.params.sender_address,
            TRANSFER_CAIRO_STRING,
            owner.x(),
            owner.y(),
            recipient.x(),
            recipient.y(),
            self.params.nonce,
            current_l.x(),
            current_l.y(),
            current_r.x(),
            current_r.y(),
            tbs_l.x(),
            tbs_l.y(),
            tbs_r.x(),
            tbs_r.y(),
            tb_l.x(),
            tb_l.y(),
            tb_r.x(),
            tb_r.y(),
            auxiliary.x(),
            auxiliary.y(),
            auxiliary_r.x(),
            auxiliary_r.y(),
            auxiliary2.x(),
            auxiliary2.y(),
            auxiliary2_r.x(),
            auxiliary2_r.y(),
        ]))
    }

    fn prove_ranges(
        &self,
        prepared: &PreparedCiphertexts,
        prefix: &Felt,
    ) -> Result<(Range, Range)> {
        #[cfg(feature = "parallel")]
        let (amount, leftover) = rayon::join(
            || self.prove_range(self.amount, &prepared.amount_randomness, prefix),
            || self.prove_range(self.leftover, &prepared.leftover_randomness_values, prefix),
        );
        #[cfg(not(feature = "parallel"))]
        let (amount, leftover) = join(
            || self.prove_range(self.amount, &prepared.amount_randomness, prefix),
            || self.prove_range(self.leftover, &prepared.leftover_randomness_values, prefix),
        );
        Ok((amount?.0, leftover?.0))
    }

    fn prove_range(
        &self,
        value: u128,
        randomness: &[Felt],
        prefix: &Felt,
    ) -> Result<(Range, Felt)> {
        range::prove_with_randomness(
            value,
            self.params.bit_size,
            &self.generator,
            &self.generator_h,
            prefix,
            randomness,
        )
    }

    fn build_protocol_proof(
        &self,
        prepared: &PreparedCiphertexts,
        prefix: &Felt,
        range: Range,
        range2: Range,
    ) -> Result<ProofOfTransfer> {
        let transfer_r = StarkCurve::projective_to_affine(&prepared.transfer_balance_self_r)?;
        let g_point = StarkCurve::add(
            &self.params.current_balance.r,
            &StarkCurve::affine_to_projective(&create_affine_point(
                transfer_r.x(),
                -transfer_r.y(),
            )?),
        );
        let kx = krusty_kms_crypto::scalar::random_felt();
        let kb = krusty_kms_crypto::scalar::random_felt();
        let kr = krusty_kms_crypto::scalar::random_felt();
        let kb2 = krusty_kms_crypto::scalar::random_felt();
        let kr2 = krusty_kms_crypto::scalar::random_felt();
        let a_x = StarkCurve::mul(&kx, Some(&self.generator));
        let a_r = StarkCurve::mul(&kr, Some(&self.generator));
        let a_r2 = StarkCurve::mul(&kr2, Some(&self.generator));
        let a_b = add_scaled(&kb, &self.generator, &kr, &self.owner);
        let a_bar = add_scaled(&kb, &self.generator, &kr, &self.params.recipient_public_key);
        let a_v = add_scaled(&kb, &self.generator, &kr, &self.generator_h);
        let a_b2 = add_scaled(&kb2, &self.generator, &kx, &g_point);
        let a_v2 = add_scaled(&kb2, &self.generator, &kr2, &self.generator_h);
        let challenge = krusty_kms_crypto::hash::compute_poseidon_challenge(
            prefix,
            &[&a_x, &a_r, &a_r2, &a_b, &a_b2, &a_v, &a_v2, &a_bar],
        )?;

        Ok(ProofOfTransfer {
            a_x: krusty_kms_common::SerializablePoint::try_from_projective(&a_x)?,
            a_r: krusty_kms_common::SerializablePoint::try_from_projective(&a_r)?,
            a_r2: krusty_kms_common::SerializablePoint::try_from_projective(&a_r2)?,
            a_b: krusty_kms_common::SerializablePoint::try_from_projective(&a_b)?,
            a_b2: krusty_kms_common::SerializablePoint::try_from_projective(&a_b2)?,
            a_v: krusty_kms_common::SerializablePoint::try_from_projective(&a_v)?,
            a_v2: krusty_kms_common::SerializablePoint::try_from_projective(&a_v2)?,
            a_bar: krusty_kms_common::SerializablePoint::try_from_projective(&a_bar)?,
            s_x: response(&kx, &challenge, self.secret)?,
            s_r: response(&kr, &challenge, &prepared.randomness)?,
            s_b: response(&kb, &challenge, &Felt::from(self.amount))?,
            s_b2: response(&kb2, &challenge, &Felt::from(self.leftover))?,
            s_r2: response(&kr2, &challenge, &prepared.leftover_randomness)?,
            range,
            range2,
        })
    }

    fn new_balance_cipher(&self, prepared: &PreparedCiphertexts) -> Result<ElGamalCiphertext> {
        Ok(ElGamalCiphertext {
            l: subtract_point(
                &self.params.current_balance.l,
                &prepared.transfer_balance_self_l,
            )?,
            r: subtract_point(
                &self.params.current_balance.r,
                &prepared.transfer_balance_self_r,
            )?,
        })
    }

    fn build_audits(
        &self,
        prepared: &PreparedCiphertexts,
        new_balance: &ElGamalCiphertext,
    ) -> Result<(Option<Audit>, Option<Audit>)> {
        let Some(auditor) = self.params.auditor_pub_key.as_ref() else {
            return Ok((None, None));
        };
        let prefix = AuditPrefixData {
            chain_id: self.params.chain_id,
            tongo_address: self.params.tongo_address,
            sender_address: self.params.sender_address,
            user_pub_key: self.owner.clone(),
        };
        let (balance_proof, audited_balance) = AuditProver::prove_with_validation(
            self.secret,
            self.leftover,
            new_balance,
            auditor,
            false,
            Some(&prefix),
        )?;
        let (balance_hint, balance_nonce) =
            encrypt_for_auditor(self.leftover, self.secret, auditor)?;
        let transfer_self = ElGamalCiphertext {
            l: prepared.transfer_balance_self_l.clone(),
            r: prepared.transfer_balance_self_r.clone(),
        };
        let (transfer_proof, audited_transfer) = AuditProver::prove(
            self.secret,
            self.amount,
            &transfer_self,
            auditor,
            Some(&prefix),
        )?;
        let (transfer_hint, transfer_nonce) =
            encrypt_for_auditor(self.amount, self.secret, auditor)?;

        Ok((
            Some(Audit {
                audited_balance,
                hint_ciphertext: balance_hint,
                hint_nonce: balance_nonce,
                proof: balance_proof,
            }),
            Some(Audit {
                audited_balance: audited_transfer,
                hint_ciphertext: transfer_hint,
                hint_nonce: transfer_nonce,
                proof: transfer_proof,
            }),
        ))
    }
}

fn affine(point: &ProjectivePoint) -> Result<starknet_types_core::curve::AffinePoint> {
    point.to_affine().map_err(|_| KmsError::PointAtInfinity)
}

fn add_scaled(
    first_scalar: &Felt,
    first_point: &ProjectivePoint,
    second_scalar: &Felt,
    second_point: &ProjectivePoint,
) -> ProjectivePoint {
    StarkCurve::add(
        &StarkCurve::mul(first_scalar, Some(first_point)),
        &StarkCurve::mul(second_scalar, Some(second_point)),
    )
}

fn response(randomness: &Felt, challenge: &Felt, value: &Felt) -> Result<Felt> {
    krusty_kms_crypto::scalar::scalar_add(
        randomness,
        &krusty_kms_crypto::scalar::scalar_mul(challenge, value)?,
    )
}

fn subtract_point(
    minuend: &ProjectivePoint,
    subtrahend: &ProjectivePoint,
) -> Result<ProjectivePoint> {
    let affine = StarkCurve::projective_to_affine(subtrahend)?;
    let negated = StarkCurve::affine_to_projective(&create_affine_point(affine.x(), -affine.y())?);
    Ok(StarkCurve::add(minuend, &negated))
}
