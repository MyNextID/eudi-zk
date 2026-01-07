#include "ecdsa_c.h"
#include "ecdsa-circuit.h"
#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <exception>
#include <vector>
#include <cstring>

// Thread-local error storage
static thread_local std::string g_last_error;

// Global circuit registry with thread-safe access
static std::map<std::string, std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>> g_circuits;
static std::mutex g_circuits_mutex;

static void set_error(const std::string &msg)
{
    g_last_error = msg;
}

#define TRY_CATCH_BEGIN \
    try                 \
    {
#define TRY_CATCH_END(ret)                                \
    }                                                     \
    catch (const std::exception &e)                       \
    {                                                     \
        set_error(std::string("Exception: ") + e.what()); \
        return ret;                                       \
    }                                                     \
    catch (...)                                           \
    {                                                     \
        set_error("Unknown exception");                   \
        return ret;                                       \
    }

extern "C"
{

    const char *ecdsa_get_last_error(void)
    {
        return g_last_error.c_str();
    }

    bool ecdsa_init_circuit(const char *name)
    {
        TRY_CATCH_BEGIN

        if (!name)
        {
            set_error("Circuit name is NULL");
            return false;
        }

        std::lock_guard<std::mutex> lock(g_circuits_mutex);

        std::string circuit_name(name);

        // Check if already exists
        if (g_circuits.find(circuit_name) != g_circuits.end())
        {
            set_error("Circuit '" + circuit_name + "' already initialized");
            return false;
        }

        // Compile the circuit
        auto circuit = proofs::CompileECDSACircuit();
        if (!circuit)
        {
            set_error("Failed to compile circuit");
            return false;
        }

        // Store in registry
        g_circuits[circuit_name] = std::move(circuit);

        return true;

        TRY_CATCH_END(false)
    }

    void ecdsa_free_circuit(const char *name)
    {
        if (!name)
            return;

        std::lock_guard<std::mutex> lock(g_circuits_mutex);
        g_circuits.erase(std::string(name));
    }

    bool ecdsa_create_proof(
        void **proof_out,
        size_t *proof_size,
        const char *circuit_name,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const char *signature_r,
        const char *signature_s)
    {
        TRY_CATCH_BEGIN

        if (!circuit_name || !proof_out || !proof_size)
        {
            set_error("Invalid parameters");
            return false;
        }

        if (!public_key_x || !public_key_y || !message_hash || !signature_r || !signature_s)
        {
            set_error("One or more string parameters are NULL");
            return false;
        }

        // Get circuit from registry
        proofs::Circuit<proofs::Fp256Base> *circuit = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_circuits_mutex);
            auto it = g_circuits.find(std::string(circuit_name));
            if (it == g_circuits.end())
            {
                set_error("Circuit '" + std::string(circuit_name) + "' not found. Did you call ecdsa_init_circuit()?");
                return false;
            }
            circuit = it->second.get();
        }

        // Create proof object
        // TODO: use params instead
        // Note: rate and nreq parameters must match what was used during proof generation
        proofs::ZkProof<proofs::Fp256Base> proof(*circuit, 4, 128);

        proofs::CreateProof(
            &proof,
            circuit,
            public_key_x,
            public_key_y,
            message_hash,
            signature_r,
            signature_s);

        // Serialize proof using write() method
        std::vector<uint8_t> buffer;
        buffer.reserve(proof.size());
        proof.write(buffer, proofs::p256_base);

        // Allocate and copy to output buffer
        *proof_size = buffer.size();
        *proof_out = malloc(*proof_size);
        if (!*proof_out)
        {
            set_error("Failed to allocate memory for proof");
            return false;
        }

        std::memcpy(*proof_out, buffer.data(), *proof_size);

        return true;

        TRY_CATCH_END(false)
    }

    bool ecdsa_verify_proof(
        const char *circuit_name,
        const char *public_key_x,
        const char *public_key_y,
        const char *message_hash,
        const void *proof_data,
        size_t proof_size)
    {
        TRY_CATCH_BEGIN

        if (!circuit_name || !proof_data)
        {
            set_error("Invalid parameters");
            return false;
        }

        if (!public_key_x || !public_key_y || !message_hash)
        {
            set_error("One or more string parameters are NULL");
            return false;
        }

        // Get circuit from registry
        proofs::Circuit<proofs::Fp256Base> *circuit = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_circuits_mutex);
            auto it = g_circuits.find(std::string(circuit_name));
            if (it == g_circuits.end())
            {
                set_error("Circuit '" + std::string(circuit_name) + "' not found");
                return false;
            }
            circuit = it->second.get();
        }

        // Create empty proof object with same parameters
        // NOTE: rate and nreq must match what was used during proof
        // creation
        proofs::ZkProof<proofs::Fp256Base> proof(*circuit, 4, 128);

        // Create ReadBuffer directly from the input data
        proofs::ReadBuffer read_buf(
            static_cast<const uint8_t *>(proof_data),
            proof_size);

        // Deserialize the proof using built-in read() method
        if (!proof.read(read_buf, proofs::p256_base))
        {
            // Get more details about where deserialization failed
            size_t consumed = proof_size - read_buf.remaining();
            set_error("Failed to deserialize proof at byte " + 
                     std::to_string(consumed) + " of " + 
                     std::to_string(proof_size));
            return false;
        }

        // Check if there's unexpected remaining data
        if (read_buf.remaining() != 0)
        {
            set_error("Proof contains extra data: " + std::to_string(read_buf.remaining()) + " bytes");
            return false;
        }

        // Verify the proof
        bool result = proofs::VerifyProof(
            circuit,
            public_key_x,
            public_key_y,
            message_hash,
            proof);

        if (!result)
        {
            set_error("Proof verification failed");
        }

        return result;

        TRY_CATCH_END(false)
    }

    void ecdsa_free_proof_data(void *proof_data)
    {
        if (proof_data)
        {
            free(proof_data);
        }
    }

} // extern "C"