#ifndef ECDSA_CIRCUIT_H
#define ECDSA_CIRCUIT_H

#include <iostream>
#include <vector>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "ec/p256.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/logic.h"

#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "random/secure_random_engine.h"

namespace proofs
{
    // Type aliases for ZK system
    using f2_p256 = Fp2<Fp256Base>;
    using Elt2 = f2_p256::Elt;
    using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
    using RSFactory = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;
    using Elt = Fp256Base::Elt;

    constexpr char kRootX[] =
        "112649224146410281873500457609690258373018840430489408729223714171582664680802";
    constexpr char kRootY[] =
        "84087994358540907695740461427818660560182168997182378749313018254450460212908";

    // Circuit compilation
    std::unique_ptr<Circuit<Fp256Base>> CompileECDSACircuit();

    // CreateProof creates a ZK proof with only public inputs visible to verifier
    void CreateProof(
        ZkProof<Fp256Base> *zkproof,
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const char *signature_r,
        const char *signature_s);

    // VerifyProof verifies a ZK proof using only public inputs
    bool VerifyProof(
        Circuit<Fp256Base> *circuit,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        ZkProof<Fp256Base> &zkproof);

} // namespace proofs

#endif // ECDSA_CIRCUIT_H