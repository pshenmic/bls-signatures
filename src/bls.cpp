// Copyright 2020 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstring>

#include "bls.hpp"

#if BLSALLOC_MIMALLOC
#include "mimalloc.h"
#endif

#if BLSALLOC_SODIUM
#include "sodium.h"
#endif

namespace bls {

const size_t BLS::MESSAGE_HASH_LEN;

bool BLSInitResult = BLS::Init();

Util::SecureAllocCallback Util::secureAllocCallback;
Util::SecureFreeCallback Util::secureFreeCallback;

static void relic_core_initializer(void* ptr)
{
    core_init();
    if (err_get_code() != RLC_OK) {
        throw std::runtime_error("core_init() failed");
    }

    const int r = ep_param_set_any_pairf();
    if (r != RLC_OK) {
        throw std::runtime_error("ep_param_set_any_pairf() failed");
    }
}

bool BLS::Init()
{
    if (ALLOC != AUTO) {
        throw std::runtime_error("Must have ALLOC == AUTO");
    }
#if BLSALLOC_MIMALLOC
    SetSecureAllocator(mi_malloc, mi_free);
#elif BLSALLOC_SODIUM
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
    SetSecureAllocator(sodium_malloc, sodium_free);
#else
    SetSecureAllocator(malloc, free);
#endif

#if MULTI != RELIC_NONE
    core_set_thread_initializer(relic_core_initializer, nullptr);
#else
    relic_core_initializer(nullptr);
#endif
    
    return true;
}

void BLS::SetSecureAllocator(
    Util::SecureAllocCallback allocCb,
    Util::SecureFreeCallback freeCb)
{
    Util::secureAllocCallback = allocCb;
    Util::secureFreeCallback = freeCb;
}


void BLS::CheckRelicErrors(bool should_throw)
{
    if (!core_get()) {
        throw std::runtime_error("Library not initialized properly. Call BLS::Init()");
    }
    if (core_get()->code != RLC_OK) {
        core_get()->code = RLC_OK;
        if (should_throw) {
            throw std::invalid_argument("Relic library error");
        }
    }
}

}  // end namespace bls

extern "C"
{
    bool bls_basic_verify(unsigned char *pubkey, bool isLegacy, unsigned char *signature, unsigned char* message) {
        // pubkey
        auto pubkey_data_ptr = static_cast<uint8_t *>(pubkey);
        std::array<uint8_t, bls::G1Element::SIZE> pubkey_data;
        std::copy(pubkey_data_ptr, pubkey_data_ptr + bls::G1Element::SIZE, pubkey_data.data());
        bls::G1Element g1Element = bls::G1Element::FromBytesUnchecked(pubkey_data, isLegacy);

        // message
        std::vector<uint8_t> v(message, message + 32);

        // signature
        auto sig_data_ptr = static_cast<uint8_t *>(signature);
        std::array<uint8_t, bls::G2Element::SIZE> sig_data;
        std::copy(sig_data_ptr, sig_data_ptr + bls::G2Element::SIZE, sig_data.data());

        bls::G2Element g2Element = bls::G2Element::FromBytes(sig_data);

       return bls::BasicSchemeMPL().Verify(g1Element, v, g2Element);
    }

    typedef struct Signature {
        unsigned char data[bls::G2Element::SIZE];  // Assuming G2Element size is 96 bytes
    } Signature;
    
    Signature bls_basic_sign(
        const unsigned char* privkey,
        const unsigned char* message,
        size_t messageLen
    ) {
        std::array<uint8_t, bls::PrivateKey::PRIVATE_KEY_SIZE> privkey_data;
        std::copy(
            privkey,
            privkey + bls::PrivateKey::PRIVATE_KEY_SIZE,
            privkey_data.data()
        );

        std::vector<uint8_t> msgVec(message, message + messageLen);

        bls::PrivateKey sk = bls::PrivateKey::FromBytes(privkey_data);

        std::vector<uint8_t> signature_vec = bls::BasicSchemeMPL().Sign(sk, msgVec).Serialize();

        Signature result;
        std::memcpy(result.data, signature_vec.data(), signature_vec.size());

        return result;
    }

    typedef struct KeyPair {
        unsigned char privkey[bls::PrivateKey::PRIVATE_KEY_SIZE];
        unsigned char pubkey[bls::G1Element::SIZE];
    } KeyPair;

    KeyPair bls_basic_keygen(const unsigned char* seed){
        std::array<uint8_t, 32> seed_data;
        std::copy(
            seed,
            seed + 32,
            seed_data.data()
        );

        std::vector<uint8_t> seed_vec(seed_data.begin(), seed_data.end());

        bls::BasicSchemeMPL mpl;

        bls::PrivateKey privKey = mpl.KeyGen(seed_vec);
        std::vector<uint8_t> privVec = privKey.Serialize();

        bls::G1Element pubKey = privKey.GetG1Element();
        std::vector<uint8_t> pubVec = pubKey.Serialize();

        KeyPair result;
        std::memcpy(result.privkey, privVec.data(), privVec.size());
        std::memcpy(result.pubkey, pubVec.data(), pubVec.size());

        return result;

    }

}
