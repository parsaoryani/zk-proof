# Cryptographic Specification: Regulated ZK-Mixer

**Version:** 1.0.0  
**Date:** February 1, 2026  
**Status:** Alpha / Implementation Specification  
**Classification:** Confidential / Internal Technical Document

---

## 1. Introduction

This document specifies the cryptographic protocols, primitives, and security models used in the **Regulated ZK-Mixer**. The system implements a privacy-preserving cryptocurrency mixer based on the **Zerocash** protocol, augmented with **Reversible Unlinkability** (Morales et al.) to enable regulatory compliance through conditional identity disclosure.

### 1.1 Goals

1.  **Sender Anonymity:** Computations should not leak the origin of funds.
2.  **Transaction Unlinkability:** It should be computationally infeasible to link a withdrawal to a specific deposit without the auditor's trapdoor.
3.  **Double-Spend Prevention:** No coin can be spent more than once.
4.  **Regulatory Compliance:** An authorized auditor can decrypt the identity of a transaction originator under strict policy constraints.

---

## 2. Cryptographic Primitives

The system utilizes standard, auditable cryptographic primitives to ensure security and broad compatibility.

| Component | Primitive | Parameters |
|-----------|-----------|------------|
| **Hash Function** | SHA-256 | Output: 256 bits |
| **Commitment Scheme** | SHA-256 (Pedersen-style) | H(k \|\| r \|\| v) |
| **Merkle Tree** | Binary SHA-256 Tree | Height: 32 (optimized for ~4B users) |
| **Digital Signatures** | ECDSA / Schnorr | Curve: P-256 / secp256k1 |
| **Asymmetric Encryption**| RSA-OAEP | Key Size: 2048-bit (Auditor Identity) |
| **Symmetric Encryption** | AES-256-GCM | Data payloads |
| **Randomness** | OS CSPRNG | `secrets` module (Python) |

---

## 3. Core Protocols

### 3.1 The Coin Structure

A coin $c$ represents value in the system. It is constructed as a tuple:

$$c = (k, r, v)$$

Where:
*   $k$: **Spending Key** (256-bit). A secret key required to spend the coin.
*   $r$: **Randomness** (256-bit). A blinding factor to hide the commitment.
*   $v$: **Value** (64-bit integer). The monetary value of the coin.

### 3.2 Commitment Scheme

When a coin is deposited, a commitment $cm$ is published to the Merkle Tree. This commits to the coin's existence without revealing $k$, $r$, or $v$.

$$cm = \text{SHA256}(k \parallel r \parallel v)$$

Implementation guarantees:
*   **Hiding:** Given $cm$, it is infeasible to find $k, r, v$.
*   **Binding:** It is infeasible to find $k', r', v'$ such that $H(k' \parallel r' \parallel v') = cm$ where $(k,r,v) \neq (k',r',v')$.

### 3.3 Merkle Tree & Membership Proofs

*   **Structure:** Fixed-height binary tree.
*   **Leaves:** Commitments $cm_i$ are inserted sequentially.
*   **Root:** The Merkle Root $\text{rt}$ acts as a "digest" of the entire system state.
*   **Path:** A Merkle Path $\pi$ consists of sibling hashes from the leaf to the root.

To spend a coin, a user must provide a Zero-Knowledge Proof (ZKP) that they know a path from some $cm$ (derived from their secret $k, r, v$) to the current public root $\text{rt}$.

### 3.4 Nullifiers (Double-Spend Prevention)

To prevent reusing the same coin, a **Nullifier** $nf$ is revealed upon withdrawal.

$$nf = \text{SHA256}(k \parallel \rho)$$

*   $\rho$ (Rho) is a unique serial number derived/assigned during coin generation.
*   The set of revealed nullifiers $\mathcal{N}$ is public.
*   **Rule:** A transaction is valid only if $nf \notin \mathcal{N}$.
*   **Unlinkability:** $nf$ cannot be linked to $cm$ without knowledge of $k$ and $r$.

---

## 4. Zero-Knowledge Proof System

The system uses a non-interactive zero-knowledge proof (NIZK) system (modeled after Bulletproofs/zk-SNARKs) to prove validity without revealing secrets.

### 4.1 Bulletproofs Proof System

The system implements a professional ZK-SNARK-like proving system using **Bulletproofs** (Bünz et al., 2017). Unlike traditional SNARKs, Bulletproofs do not require a trusted setup.

*   **Curve:** NIST P-256 (prime order group).
*   **Domain Separation:** Uses SHA-512 for hashing to scalars to avoid cross-protocol attacks.
*   **Range Proofs:** Proves that the value $v$ is in the range $[0, 2^{64}-1]$ without revealing $v$.
*   **Pedersen Commitments:** $C = g^v \cdot h^r$ where $g, h$ are independent generators on the P-256 curve.

### 4.2 Withdrawal Circuit Logic

The prover $P$ convinces the verifier $V$ of the following statement:

*"I know secret values $(k, r, v, \pi, \text{idx})$ such that:"*

1.  **Membership:** The commitment $cm = H(k \parallel r \parallel v)$ exists in the Merkle Tree at index $\text{idx}$ with path $\pi$ leading to public root $\text{rt}$.
2.  **Nullifier Integrity:** The nullifier $nf$ is correctly computed as $H(k \parallel \rho)$.
3.  **Value Preservation:** The output value equals the input value (minus fees).
4.  **Bulletproof Verification:** The inner-product argument and range proof are valid for the commitment $cm$.

### 4.3 Proof Structure (`ZKSNARKProof`)

The serialized proof object contains:

```python
class ZKSNARKProof:
    commitment_proof: bytes      # Proof of knowledge of cm pre-image
    merkle_root: bytes          # Public input
    nullifier: bytes            # Public input
    nullifier_proof: bytes      # Proof of valid nullification
    value_proof: bytes          # Proof of conservation of value
    output_commitment: bytes    # New coin commitment (if change is generated)
```

---

## 5. Reversible Unlinkability (Regulatory Compliance)

This component implements the **Morales et al.** scheme for "conditional anonymity." It ensures that while the public cannot link transactions, a designated **Auditor** can decrypt the identity of the sender under specific conditions.

### 5.1 The Auditor

*   **Role:** Trusted third party (e.g., Regulatory Body).
*   **Keys:** RSA Keypair $(PK_{auditor}, SK_{auditor})$.
*   $PK_{auditor}$: Public, used by the mixer to encrypt identities during deposit.
*   $SK_{auditor}$: Private, held in HSM (Hardware Security Module), used to decrypt identities.

### 5.2 Identity Encryption

During a deposit, the user's identity $ID$ (e.g., IP address, account ID, or wallet address) is encrypted.

$$C_{ID} = \text{RSA-OAEP}(PK_{auditor}, ID, \text{label}=\text{tx\_hash})$$

*   **Ciphertext Binding:** The ciphertext $C_{ID}$ is cryptographically bound to the deposit transaction.
*   **Proof of Encryption:** The user provides a ZK-proof that $C_{ID}$ is a valid encryption of their real identity $ID$.

### 5.3 Disclosure Policies

The system supports granular privacy policies defined in `DisclosurePolicy`. Users can configure exactly what data is accessible to which auditor:

*   **Privacy Levels**:
    - `HIGH`: Absolute privacy. No fields can be decrypted.
    - `MEDIUM`: Partial privacy. Selective fields (e.g., amount) may be revealed.
    - `LOW`: Minimum privacy. Full identity and transaction history accessible to the Auditor.
*   **Granular Flags**:
    - `can_reveal_sender`: Boolean flag for identity decryption.
    - `can_reveal_amount`: Boolean flag for transaction volume recovery.
    - `can_reveal_recipient`: Boolean flag for destination tracing.
*   **Policy Constraints**:
    - `allowed_auditors`: Whitelist of public key identifiers.
    - `expiry_time`: Time-bound audit permission; once expired, the policy defaults to `HIGH`.

### 5.4 The "Trapdoor" Mechanism

If a transaction is flagged (e.g., court order):
1.  Admin queries database for $C_{ID}$ associated with the transaction.
2.  Auditor uses $SK_{auditor}$ to compute $ID = \text{Dec}(C_{ID})$.
3.  The decrypted identity is logged in the `AuditRecord` table (immutable audit trail).

---

## 6. Security Analysis

### 6.1 Anonymity Set
The anonymity set size corresponds to the number of non-spent commitments in the Merkle Tree.
*   **Current Capacity:** $2^{32}$ leaves.
*   **Mixing Quality:** Dependent on transaction volume and temporal distribution.

### 6.2 Pre-image Resistance
The security of funds relies on the pre-image resistance of SHA-256.
*   Attack cost: $\approx 2^{256}$ operations (infeasible).

### 6.3 Trapdoor Security
*   **Risk:** Compromise of $SK_{auditor}$ destroys privacy for *past* transactions.
*   **Mitigation:** Key rotation and HSM isolation. The system supports key versioning (though implemented simply in v1).

### 6.4 Randomness
*   Critical dependency on System CSPRNG (`secrets` module/`os.urandom`) for generating $k$ and $r$.
*   Weak randomness would allow attackers to satisfy the KDA (Known Discrete Log / Pre-image) assumption and steal funds.

---

## 7. Implementation Notes

### 7.1 Python `zkm.crypto` Module

*   `coin.py`: Handles coin generation and derivation of commitments.
*   `merkle_tree.py`: Implements sparse/dense Merkle Tree logic and path verification.
*   `zk_snark.py`: Mock implementation of Bulletproofs for architectural demonstration. *Note: For production, this should be replaced with `libsnark` or `bellman` bindings.*
*   `reversible_unlinkability.py`: Manages policies and RSA integration.

### 7.2 Performance Targets

*   **Proof Generation:** < 3.0s (Client-side)
*   **Proof Verification:** < 0.1s (Server-side)
*   **Merkle Update:** $O(\log n)$
*   **Identity Decryption:** < 0.05s

---

## 8. References

1.  *Ben-Sasson, E., et al. "Zerocash: Decentralized Anonymous Payments from Bitcoin." S&P 2014.*
2.  *Morales, et al. "Zero-Knowledge Bitcoin Mixer with Reversible Unlinkability." 2020.*
3.  *Bunz, B., et al. "Bulletproofs: Short Proofs for Confidential Transactions and More." S&P 2018.*
