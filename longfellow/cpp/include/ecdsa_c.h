#ifndef ECDSA_C_H
#define ECDSA_C_H
#include <stddef.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * Get the last error message from the library
     */
    const char *ecdsa_get_last_error(void);
    /**
     * Initialize a named circuit (compile once, reuse many times)
     * @param name Circuit name
     * @return true on success, false on failure
     */
    bool ecdsa_init_circuit(const char *name);
    /**
     * Free a named circuit
     * @param name Circuit name/identifier
     */
    void ecdsa_free_circuit(const char *name);
    /**
     * Create a ZK proof using a named circuit
     * @param proof_out    Output buffer for proof data
     * @param proof_size   Size of proof buffer (will be set to actual size)
     * @param circuit_name Name of previously initialized circuit
     * @param public_key_x Hex string
     * @param public_key_y Hex string
     * @param message_hash Hex string
     * @param signature_r  Hex string (private)
     * @param signature_s  Hex string (private)
     * @return true on success, false on failure
     */
    bool ecdsa_create_proof(
        void **proof_out,
        size_t *proof_size,
        const char *circuit_name,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const char *signature_r,
        const char *signature_s);
    /**
     * Verify a ZK proof using a named circuit
     * @param circuit_name Name of previously initialized circuit
     * @param public_key_x Hex string (public input)
     * @param public_key_y Hex string (public input)
     * @param message_hash Hex string (public input)
     * @param proof_data   Proof data to verify
     * @param proof_size   Size of proof data
     * @return true if valid, false otherwise
     */
    bool ecdsa_verify_proof(
        const char *circuit_name,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const void *proof_data,
        size_t proof_size);
    /**
     * Free proof data returned by ecdsa_create_proof
     */
    void ecdsa_free_proof_data(void *proof_data);
#ifdef __cplusplus
}
#endif
#endif // ECDSA_C_H