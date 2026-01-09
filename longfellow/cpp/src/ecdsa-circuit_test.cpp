// ecdsa-circuit_test.cpp
#include "ecdsa-circuit.h"
#include "gtest/gtest.h"

namespace proofs
{
    namespace
    {
        struct ecdsa_testvec
        {
            const char *pk_x, *pk_y;
            const char *e, *r, *s;
        };

        static const struct ecdsa_testvec P256_TEST[] = {
            {
                "0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c",
                "0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75",
                "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                "0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671",
                "0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd40",
            },
            {"0x105ccb7bd3bcc142082519cbe5b740b31c1bc8d5db8cd694e6f0a20c4198cd1",
             "0x494c2641ebf3be217f8a9a53ce0fc9768b2403024cb3f7a54fd1a78e972bc991",
             "0x7d54b750c56c32c1ef1b2c96f40739895b06ca0638a461287e802498b53583ae",
             "0x2fb4dae21a614a417f9fe42a54861425c38d1b861e0eaa6bf0a45709f02c85c6",
             "0xfb6f08a3a1640292b3ad9fb713a08f2392995fbbb4c2c1cd3c36a212246a7b6c"},
            {"0xc054b53cd047893ac412dc779f50c7b00c38e5c3eceb29ecd8620999346d1503",
             "0x569881c1b54d03b28a083a8da37251b8e8fbc8dda44721f749176f6552d577e5",
             "0xf2ba08a9ad9e88d73538b01777dde3843182ad74e4ab80ac640049eecd027225",
             "0x40e11fee99753c42aa0327c102b53a49bf3654e2eb0cd09d2d54841aa1e33603",
             "0x25b8e6b6abb83cbdcc5d200cc9100f9e4ccee64420d27c21a5fe3b033636838d"},
            {"0x92b31ba01ef2e229bd26822ab3a8763d9da40d8750c7c1534e84c3f209489836",
             "0x0e03689aed2711eec3a278316fcc8e965a65d5779d66036fde17a7bb265328e0",
             "0x3ad98d5cf8b691729bb684d7067b409e79aaf9359ced9972600e528d93a17ad2",
             "0xcdaec1053293d385857eff2896c63ea63a897b1d5f9114b147220d24eb61f7b7",
             "0x2f9389d65d9995e37e81ac4bdd0691ca7f325beb7474ecd6bde8c7aca58ab32d"},
            {"0xdc1c1f55cff4cd5c76cf4169278f7217667f86ee81d8669b63f2e19bc12a0c9f",

             "0x12355dd0385fed3bc33bedc9781b9aad47b33e4c24704b8d14288b1b3cb45c28",

             "0x9e73b3df1394f4b17525fbe3d9f836b78d0f65840e7bf6b8c2b9b4972acbb780",

             "0x3D3197DE1E862DF865F04ACF13E72AE3DB4C8F6789049DB59C2C6B9F3BF7F460",

             "0x570FC235961E62E2A19A435E2F2802B1F10701E2E9D049A534C4535042DD8229"},
            {"0x6d375ca27ae82d882ef5f50db5e94102aea455d0af5bfdd47b1e3a60ed97edaa",

             "0x18f64ba26e6ec9694a61c925ccf0d3766ff4a6b58040b8a43607b6eef966dbb",

             "0xd05f71edcd81f3f181042db9367873d873a30e4bc6736c08640b022aeb199a8b",

             "0x94c00eb61d5947b5e9786e464243eb1aadb69bcd1b64852dd73721a6a187ee9e",

             "0x3e2908351b7d9b9feaefeb2f8b32ecdee42151d043e7f63491e6333c58dc507f"},
            {"0xe57ecf19f5790ceea156579531d258e025d3518c64ef8c353921cad45831420f",

             "0x551e76295ad864a3d057808ba9a57a61676d19700a5e5bfb8563a74057ed2295",

             "0x389f71c0bdad464e53c64628c1024967f3cd13e918367c352b2d24e845d21935",

             "0x5bb78d72deb16d1f6390b3d092e4bc95758e5c8f35a287f7d7785ef071204899",

             "0x19fc8d719596696401cb4e0dc28610957e34061788cc4cf099fab8bfbda00c0d"},
            {"0xe277dbbf59f37362111f61ae7ae8891a5fc8216cf058aede1d9922756f17fa45",

             "0x2077085f8a157ba4be3a8b9ea390439244db6201c737dd58fb83a9b19b388c1d",

             "0x9162600824eb1c62069bcb656722dedce2af636e1ff7cd0922fe29b5096ae3cd",

             "0xe29cc486a0d42472205d125ede804920d779452d7e96047b82d8d3633e87dfaf",

             "0xd640fc77a00db25e48c9f89734ad2a192069957819860c5d372a53d7c6a70b8e"},
            // smaller pk
            {
                "0x53556c0b8714f3dad02c3cdd570b7831182152df7265ab976725ea26c354f",

                "0x45eaaeb3cd6cfd67cb35b7a4efce2c80e38756f10f3fa631d332a6792f9c07b9",

                "0x215b9dbb044dc7d270f927887ae2e1ced888f3a609fe0eb8610e2f59f9f0456d",

                "0xb52d02cba797a9fecc4ad08286d3b411222da335cca301ff9af2a103351ab88a",

                "0x6d5e2cc8fb2f1ea3d781d36a6436a6b40c520c621cbfb6a76cfd88e50456a5f5"},
            // small pk and small e
            {
                "0x34ccea4289f78756697fccd5fe555ce37e45893c79b25ee5073f05cc30ce1",

                "0xa184f469cd90a80b5fb382cf6de4f89bbf67009039786e0de9e434edaffd9371",

                "0x0000000000000000000000000000000001000000000000000000000000000000",

                "0xc6d1f3abcad6c11412546695d6fc46d6e3237cfe2bc523909789595182ccfb40",

                "0x8c2992eb37d7b152d668bf6b35a2fdf6a580fc7eda31b77c2c6d67d6b2d7646f"},
            // small r value for sig
            {
                "0xbfb7fb8c8d241f2fa8ff70fa1799cde5796d1d316f17a556666b52c2bc2e7712",

                "0x65ddbe1fdeac4074d0f6b7b9e8987b44e0d962fa93a55d6fbae9eaf49e0b82c",

                "0x0000000000000000000000000000000001000000000000000000000000000000",

                "0x56bf962a6cc889cf1634e299cd8b44ae992790185b920dac52b8e0212b9f",

                "0x101736305e0c1be90981cd289c97a5c876b86d70cbe5f7342ff3ebd12cabdd30"},
        };

        static const struct ecdsa_testvec P256_FAILS[] = {
            // bad signature
            {
                "0x78903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e"
                "7c6368d9c",
                "0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f5862"
                "6767f9e75",
                "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e8"
                "86266e7ae",

                "0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671",
                "0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410"
                "ff4f6dd40",
            },
            // zero values, or values that are not on the curve
            {"0",

             "0x65ddbe1fdeac4074d0f6b7b9e8987b44e0d962fa93a55d6fbae9eaf49e0b82c",

             "0x0000000000000000000000000000000001000000000000000000000000000000",

             "0x56bf962a6cc889cf1634e299cd8b44ae992790185b920dac52b8e0212b9f",

             "0x101736305e0c1be90981cd289c97a5c876b86d70cbe5f7342ff3ebd12cabdd30"},
            {"0xbfb7fb8c8d241f2fa8ff70fa1799cde5796d1d316f17a556666b52c2bc2e7712",
             "0",

             "0x0000000000000000000000000000000001000000000000000000000000000000",

             "0x56bf962a6cc889cf1634e299cd8b44ae992790185b920dac52b8e0212b9f",

             "0x101736305e0c1be90981cd289c97a5c876b86d70cbe5f7342ff3ebd12cabdd30"},
            {"0xbfb7fb8c8d241f2fa8ff70fa1799cde5796d1d316f17a556666b52c2bc2e7712",

             "0x65ddbe1fdeac4074d0f6b7b9e8987b44e0d962fa93a55d6fbae9eaf49e0b82c",

             "0x0000000000000000000000000000000001000000000000000000000000000000",
             "0",

             "0x101736305e0c1be90981cd289c97a5c876b86d70cbe5f7342ff3ebd12cabdd30"},
            {"0xbfb7fb8c8d241f2fa8ff70fa1799cde5796d1d316f17a556666b52c2bc2e7712",

             "0x65ddbe1fdeac4074d0f6b7b9e8987b44e0d962fa93a55d6fbae9eaf49e0b82c",

             "0x0000000000000000000000000000000001000000000000000000000000000000",

             "0x56bf962a6cc889cf1634e299cd8b44ae992790185b920dac52b8e0212b9f",
             "0"},
            {"0xbfb7fb8c8d241f2fa8ff70fa1799cde5796d1d316f17a556666b52c2bc2e7712",

             "0x65ddbe1fdeac4074d0f6b7b9e8987b44e0d962fa93a55d6fbae9eaf49e0b82c",
             "0", "0", "0"},
            // pk not on curve
            {"0x1", "0x2",

             "0x0000000000000000000000000000000001000000000000000000000000000000",

             "0xc6d1f3abcad6c11412546695d6fc46d6e3237cfe2bc523909789595182ccfb40",

             "0x8c2992eb37d7b152d668bf6b35a2fdf6a580fc7eda31b77c2c6d67d6b2d7646f"},
        };

        TEST(ecdsa, p256_proof_creation_and_verification)
        {
            using Field = Fp256Base;

            // Step 1: Compile the circuit once
            auto circuit = CompileECDSACircuit();
            std::cout << "\n=== Testing ZK Proof System ===" << std::endl;
            std::cout << "Circuit has " << circuit->npub_in
                      << " public inputs (visible to verifier)" << std::endl;
            std::cout << "Circuit has " << (circuit->ninputs - circuit->npub_in)
                      << " private inputs (hidden from verifier)" << std::endl;

            // Step 2: Test with valid signatures
            for (const auto &test : P256_TEST)
            {
                ZkProof<Field> zkproof(*circuit, 4, 128);
                // Create a proof with the private witness (signature r, s)
                CreateProof(
                    &zkproof,
                    circuit.get(),
                    test.pk_x,
                    test.pk_y,
                    test.e,
                    test.r,
                    test.s);

                // Verify the proof with only public inputs (pk, message hash)
                EXPECT_NO_THROW({
                    VerifyProof(
                        circuit.get(),
                        test.pk_x,
                        test.pk_y,
                        test.e,
                        zkproof);
                });
            }
        }
        /*
        TEST(ecdsa, p256_proof_verification_should_fail_with_wrong_public_inputs)
        {
            using Field = Fp256Base;

            // Compile the circuit
            auto circuit = CompileECDSACircuit();

            // Use first valid test vector
            const auto &valid_test = P256_TEST[0];
            const auto &different_test = P256_TEST[1];

            // Create a proof with valid signature
            ZkProof<Field> zkproof(*circuit, 4, 128);
            CreateProof(
                &zkproof,
                circuit.get(),
                valid_test.pk_x,
                valid_test.pk_y,
                valid_test.e,
                valid_test.r,
                valid_test.s);

            // Try to verify with different public inputs (should fail)
            EXPECT_THROW({ VerifyProof(
                               circuit.get(),
                               different_test.pk_x, // Wrong public key
                               different_test.pk_y,
                               valid_test.e, // Same message hash
                               zkproof); }, std::exception);
        }

        TEST(ecdsa, p256_proof_creation_should_fail_with_invalid_signature)
        {
            using Field = Fp256Base;

            // Compile the circuit
            auto circuit = CompileECDSACircuit();

            // Use a failing test vector
            const auto &invalid_test = P256_FAILS[0];

            // Creating a proof should fail because the witness doesn't satisfy the circuit
            EXPECT_THROW({
            ZkProof<Field> zkproof(*circuit, 4, 128);
                        CreateProof(
                            &zkproof,
                            circuit.get(),
                            invalid_test.pk_x,
                            invalid_test.pk_y,
                            invalid_test.e,
                            invalid_test.r,
                            invalid_test.s
                        ); }, std::exception);
        }

        TEST(ecdsa, p256_multiple_proofs_same_circuit)
        {
            using Field = Fp256Base;

            // Compile the circuit once
            auto circuit = CompileECDSACircuit();

            // Create and verify multiple proofs with the same circuit
            std::vector<ZkProof<Field>> proofs;

            for (size_t i = 0; i < 3; ++i)
            {
                const auto &test = P256_TEST[i];

                ZkProof<Field> zkproof(*circuit, 4, 128);
                CreateProof(
                    &zkproof,
                    circuit.get(),
                    test.pk_x,
                    test.pk_y,
                    test.e,
                    test.r,
                    test.s);

                proofs.push_back(std::move(zkproof));
            }

            // Verify all proofs
            for (size_t i = 0; i < proofs.size(); ++i)
            {
                const auto &test = P256_TEST[i];
                EXPECT_NO_THROW({
                    VerifyProof(
                        circuit.get(),
                        test.pk_x,
                        test.pk_y,
                        test.e,
                        proofs[i]);
                });
            }
        }
*/
    } // namespace
} // namespace proofs
