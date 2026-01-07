// ecdsa-circuit.cpp
// Educational implementation of ECDSA signature verification with
// Zero-Knowledge Proofs
//
// This file demonstrates how to build a zkSNARK circuit that proves: "I know a
// valid ECDSA signature for this message and public key" WITHOUT revealing the
// signature itself to the verifier.
//
// Key Concepts:
// - Circuit: A mathematical representation of the ECDSA verification algorithm
// - Witness: The private data (signature) that satisfies the circuit
// - Proof: Cryptographic evidence that you know a valid witness
// - Verifier: Actor who can validate the proof without seeing the signature

#include "ecdsa-circuit.h"

namespace proofs
{

    bool parsePublicKey(const char *pkx, const char *pky, Elt &pkX, Elt &pkY)
    {
        auto pk_x = p256_base.of_untrusted_string(pkx);
        auto pk_y = p256_base.of_untrusted_string(pky);
        if (!pk_x.has_value() || !pk_y.has_value())
        {
            return false;
        }
        pkX = pk_x.value();
        pkY = pk_y.value();
        return true;
    }

    /**
     * CompileECDSACircuit - Builds the circuit for ECDSA signature verification
     *
     * Circuit is a "program" that the ZK system will execute:
     * - It has inputs (public key, message hash, signature)
     * - It has constraints (mathematical rules that must be satisfied)
     * - A valid witness is one that satisfies all constraints
     *
     * The circuit encodes: "Is signature (r,s) valid for public key (x,y) and
     * message hash h?"
     *
     * Returns: A compiled circuit that can be used to create and verify proofs
     */
    std::unique_ptr<Circuit<Fp256Base>> CompileECDSACircuit()
    {
        // For this demo, we verify 1 signature.
        size_t numSigs = 1;

        // === STEP 1: Set up the circuit builder layers ===
        // The Longfellow library uses a layered architecture:
        // QuadCircuit -> CompilerBackend -> Logic -> VerifyCircuit

        using CompilerBackend = CompilerBackend<Fp256Base>;
        using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
        using VerC = VerifyCircuit<LogicCircuit, Fp256Base, P256>;
        using EltW = LogicCircuit::EltW;

        // Layer 0: Base circuit - works with P-256 field elements
        QuadCircuit<Fp256Base> Q(p256_base);

        // Layer 1: Compiler backend - converts high-level operations to
        // constraints
        const CompilerBackend cbk(&Q);

        // Layer 2: Logic operations - provides field arithmetic and comparisons
        const LogicCircuit lc(&cbk, p256_base);

        // Layer 3: ECDSA verifier - implements signature verification algorithm
        VerC verc(lc, p256, n256_order);

        // === STEP 2: Define inputs to the circuit ===
        // Inputs are divided into PUBLIC (known to verifier) and PRIVATE
        // (hidden)

        std::vector<VerC::Witness> witnesses(numSigs);

        // PUBLIC INPUTS - The verifier knows these values
        // These become part of the proof statement: "I have a signature for
        // THIS data"
        std::vector<EltW> public_key_x, public_key_y, message_hashes;

        for (size_t i = 0; i < numSigs; ++i)
        {
            public_key_x.push_back(lc.eltw_input());   // Public key X coordinate
            public_key_y.push_back(lc.eltw_input());   // Public key Y coordinate
            message_hashes.push_back(lc.eltw_input()); // Hash of the message being signed
        }

        // PRIVATE INPUTS - The prover knows these, but they're hidden from the
        // verifier
        // The signature (r, s) values are secret - this is what makes it
        // zero-knowledge
        Q.private_input(); // Random salt for zero-knowledge property

        for (size_t i = 0; i < numSigs; ++i)
        {
            // Allocate circuit wires for the signature components (r, s)
            // These values will be in the witness but NOT in the proof
            witnesses[i].input(lc);
        }

        // === STEP 3: Build the verification logic ===
        // This is where we add the actual ECDSA verification constraints

        for (size_t i = 0; i < numSigs; ++i)
        {
            // verify_signature3() adds constraints that encode:
            // 1. Parse signature (r, s) and verify both are in valid range
            // 2. Compute point R = (message_hash/s)*G + (r/s)*PublicKey
            // 3. Verify that R.x mod n == r
            //
            // If all constraints pass, the signature is valid.
            verc.verify_signature3(
                public_key_x[i],
                public_key_y[i],
                message_hashes[i],
                witnesses[i]);
        }

        // === STEP 4: Finalize the circuit ===
        // Optimize and prepare for proving/verification
        auto circuit = Q.mkcircuit(1);

        std::cout << "[OK] Circuit compiled: "
                  << circuit->ninputs << " total inputs, "
                  << circuit->npub_in << " public inputs" << std::endl;

        return circuit;
    }

    /**
     * CreatePrivateWitness - Fills in ALL circuit inputs (public + private)
     *
     * The "witness" is the complete solution to the circuit - all the values
     * that, when plugged into the circuit, make all constraints evaluate to
     * true.
     *
     * This function is used by the PROVER who knows the signature.
     *
     * @param W             Output: Dense matrix to store witness values
     * @param circuit       The compiled circuit
     * @param public_key_x  Public key X coordinate (hex string)
     * @param public_key_y  Public key Y coordinate (hex string)
     * @param message_hash  Hash of signed message (hex string)
     * @param signature_r   Signature component r (hex string)
     * @param signature_s   Signature component s (hex string)
     */
    void CreatePrivateWitness(
        Dense<Fp256Base> &W,
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const char *signature_r,
        const char *signature_s)
    {
        using Nat = Fp256Base::N;
        using Verw = VerifyWitness3<P256, Fp256Scalar>;

        // === Parse input strings to field elements ===
        Elt pk_x, pk_y;

        if (!parsePublicKey(public_key_x, public_key_y, pk_x, pk_y))
        {
            log(ERROR, "invalid public key (x, y)");
            return;
        }

        auto e_opt = Nat::of_untrusted_string(message_hash);
        auto r_opt = Nat::of_untrusted_string(signature_r);
        auto s_opt = Nat::of_untrusted_string(signature_s);

        if (!e_opt || !r_opt || !s_opt)
        {
            log(ERROR, "invalid signature component string");
            return;
        }

        Nat e = *e_opt;
        Nat r = *r_opt;
        Nat s = *s_opt;

        // === Fill the witness vector ===
        DenseFiller<Fp256Base> filler(W);

        // First, add public inputs (these will also go in the proof)
        filler.push_back(p256_base.one());            // Constant 1
        filler.push_back(pk_x);                       // Public key X
        filler.push_back(pk_y);                       // Public key Y
        filler.push_back(p256_base.to_montgomery(e)); // Message hash

        // Next, compute and add private witness data (intermediate values) This
        // includes all the elliptic curve computations needed for verification
        Verw vw(p256_scalar, p256);
        vw.compute_witness(pk_x, pk_y, e, r, s);
        vw.fill_witness(filler);

        std::cout << "[OK] Private witness created (" << W.n1_ << " elements)" << std::endl;
    }

    /**
     * CreatePublicWitness - Fills in ONLY the public inputs
     *
     * This is used by the VERIFIER who doesn't know the signature.
     * The verifier only provides: public key + message hash
     *
     * @param pub           Output: Dense matrix to store public witness values
     * @param circuit       The compiled circuit
     * @param public_key_x  Public key X coordinate
     * @param public_key_y  Public key Y coordinate
     * @param message_hash  Hash of signed message
     */
    void CreatePublicWitness(
        Dense<Fp256Base> &pub,
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash)
    {
        using Nat = Fp256Base::N;

        // Parse the public inputs from hex strings
        Elt pk_x, pk_y;

        if (!parsePublicKey(public_key_x, public_key_y, pk_x, pk_y))
        {
            log(ERROR, "invalid public key (x, y)");
            return;
        }

        auto e_opt = Nat::of_untrusted_string(message_hash);
        if (!e_opt )
        {
            log(ERROR, "invalid signature component string");
            return;
        }
        Nat e = *e_opt;


        DenseFiller<Fp256Base> pub_filler(pub);

        // Fill ONLY public inputs - no signature or intermediate values
        pub_filler.push_back(p256_base.one());
        pub_filler.push_back(pk_x);
        pub_filler.push_back(pk_y);
        pub_filler.push_back(p256_base.to_montgomery(e));

        std::cout << "[OK] Public witness created (" << pub.n1_ << " elements)" << std::endl;
    }

    /**
     * CreateProof - Generates a zero-knowledge proof of signature validity
     *
     * The proof process has two phases:
     * 1. COMMIT: Prover commits to the witness using polynomial commitments
     * 2. PROVE: Prover responds to verifier's random challenges
     *
     * The result is a proof that can be sent to anyone to verify you have a
     * valid signature, WITHOUT revealing the signature itself.
     *
     * @param zkproof       Output: The generated proof
     * @param circuit       The compiled circuit
     * @param public_key_x  Public key X coordinate
     * @param public_key_y  Public key Y coordinate
     * @param message_hash  Hash of signed message
     * @param signature_r   Signature component r (PRIVATE)
     * @param signature_s   Signature component s (PRIVATE)
     */
    void CreateProof(
        ZkProof<Fp256Base> *zkproof,
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const char *signature_r,
        const char *signature_s)
    {
        std::cout << "[INFO] Creating ZK proof..." << std::endl;

        // === Create the complete witness (including the secret signature) ===
        auto PrivateWitness = Dense<Fp256Base>(1, circuit->ninputs);
        CreatePrivateWitness(
            PrivateWitness,
            circuit,
            public_key_x,
            public_key_y,
            message_hash,
            signature_r,
            signature_s);

        // === Set up cryptographic infrastructure ===
        // These parameters define the security properties of the proof system

        // Extension field for polynomial commitments (F_p^2)
        const f2_p256 p256_2(p256_base);
        const Elt2 omega = p256_2.of_string(kRootX, kRootY);

        // FFT factory for efficient polynomial operations
        const FftExtConvolutionFactory fft_factory(p256_base, p256_2, omega, 1ull << 31);

        // Reed-Solomon codes for proximity testing
        const RSFactory rs_factory(fft_factory, p256_base);

        // Fiat-Shamir transcript ensures non-interactivity and security The
        // label "ecdsa_proof" is a domain separator
        Transcript transcript((uint8_t *)"ecdsa_proof", 11);

        // Cryptographic randomness for hiding the witness
        SecureRandomEngine rng;

        // === Create the prover and generate proof ===
        ZkProver<Fp256Base, RSFactory> prover(*circuit, p256_base, rs_factory);

        // COMMIT PHASE: Create polynomial commitments to witness values
        // This binds the prover to their witness without revealing it
        prover.commit(*zkproof, PrivateWitness, transcript, rng);
        std::cout << "[OK] Commitment phase complete" << std::endl;

        // PROVE PHASE: Generate proof of constraint satisfaction
        // Uses Fiat-Shamir heuristic to derive challenges from transcript
        prover.prove(*zkproof, PrivateWitness, transcript);
        std::cout << "[OK] Proof created (size: " << zkproof->size() << " bytes)" << std::endl;
    }

    /**
     * VerifyProof - Verifies a zero-knowledge proof using only public inputs
     *
     * The verifier:
     * 1. Knows the public inputs (public key, message hash)
     * 2. Receives the proof from the prover
     * 3. Does NOT know the signature (r, s)
     * 4. Can still verify the signature was valid!
     *
     * This is the "zero-knowledge" magic: proving knowledge without revealing
     * it.
     *
     * @param circuit       The compiled circuit (must match prover's)
     * @param public_key_x  Public key X coordinate
     * @param public_key_y  Public key Y coordinate
     * @param message_hash  Hash of signed message
     * @param zkproof       The proof to verify
     * @return true if proof is valid, false otherwise
     */
    bool VerifyProof(
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        ZkProof<Fp256Base> &zkproof)
    {
        std::cout << "[INFO] Verifying ZK proof..." << std::endl;

        // === Create public witness (verifier's limited knowledge) ===
        auto PublicWitness = Dense<Fp256Base>(1, circuit->npub_in);
        CreatePublicWitness(
            PublicWitness,
            circuit,
            public_key_x,
            public_key_y,
            message_hash);

        // === Set up cryptographic infrastructure (must match prover) ===
        // These parameters are public and part of the proof system
        // specification
        const f2_p256 p256_2(p256_base);
        const Elt2 omega = p256_2.of_string(kRootX, kRootY);
        const FftExtConvolutionFactory fft_factory(p256_base, p256_2, omega, 1ull << 31);
        const RSFactory rs_factory(fft_factory, p256_base);

        // Transcript must use same domain separator as prover
        Transcript transcript((uint8_t *)"ecdsa_proof", 11);

        // === Create verifier with security parameters ===
        ZkVerifier<Fp256Base, RSFactory> verifier(
            *circuit,
            rs_factory,
            4,   // rho: Rate parameter for Reed-Solomon codes
            128, // Security level in bits (2^-128 soundness error)
            p256_base);

        // === Verification process ===

        // Receive and validate the polynomial commitments
        verifier.recv_commitment(zkproof, transcript);
        std::cout << "[OK] Commitment received" << std::endl;

        // Verify the proof using only public inputs
        // This checks:
        // 1. Polynomial commitments are well-formed
        // 2. Proof satisfies all circuit constraints
        // 3. Proof is consistent with public inputs
        // 4. No cheating is detected (soundness)
        bool result = verifier.verify(zkproof, PublicWitness, transcript);

        if (result)
        {
            std::cout << "[OK] Proof verification PASSED ✓" << std::endl;
            std::cout << "      The prover knows a valid ECDSA signature!" << std::endl;
        }
        else
        {
            std::cout << "[ERROR] Proof verification FAILED ✗" << std::endl;
            std::cout << "        Either the signature is invalid or the proof is malformed." << std::endl;
        }

        return result;
    }

} // namespace proofs