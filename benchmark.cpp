#include <array>
#include <cassert>
#include <iostream>
#include <bitcoin/system.hpp>
#include <secp256k1.h>
#ifdef DJB
    #include <crypto_scalarmult_curve25519.h>
#else
    #include <sodium.h>
    #include <hydrogen.c>
    #define SODIUM
#endif
#include <openssl/evp.h>
#include "external_calls.h"
#include "curve25519_dh.h"
#include "ed25519_signature.h"

constexpr auto test_iterations = 100'000;

namespace bcs = bc::system;

#ifdef SODIUM
using point25519 = std::array<unsigned char, crypto_core_ed25519_BYTES>;
using scalar25519 = std::array<unsigned char, crypto_core_ed25519_UNIFORMBYTES>;

auto random_point_25519()
{
    // Random x value
    scalar25519 x;
    randombytes_buf(x.data(), x.size());

    // Compute P where x_p = x
    point25519 P;
    crypto_core_ed25519_from_uniform(P.data(), x.data());
    return P;
}

bool test25519()
{
    sodium_init();
    auto P = random_point_25519();

    std::array<scalar25519, test_iterations> values;
    for (auto& x: values)
        randombytes_buf(x.data(), x.size());

    bcs::timer time;
    auto duration = time.execution([&]
        {
            point25519 result;
            for (auto& x: values)
            {
                auto success =
                    crypto_scalarmult(result.data(), x.data(), P.data()) == 0;
                assert(success);
            }

            //assert(crypto_core_ed25519_is_valid_point(P.data()));
        });
    std::cout << "sodium 25519 took: " << duration << " ms" << std::endl;

    std::cout << "sodium 25519 done." << std::endl;
    return true;
}

bool test25519_hydrogen()
{
    auto P = random_point_25519();

    std::array<scalar25519, test_iterations> values;
    for (auto& x: values)
        randombytes_buf(x.data(), x.size());

    bcs::timer time;
    auto duration = time.execution([&]
        {
            point25519 result;
            for (auto& x: values)
            {
                auto success =
                    hydro_x25519_scalarmult(result.data(), x.data(), P.data(), true) == 0;
                assert(success);
            }

            //assert(crypto_core_ed25519_is_valid_point(P.data()));
        });
    std::cout << "hydrogen 25519 took: " << duration << " ms" << std::endl;

    std::cout << "hydrogen 25519 done." << std::endl;
    return true;
}
#endif

#ifdef DJB
using point25519_2 = std::array<unsigned char, crypto_scalarmult_curve25519_SCALARBYTES>;
using scalar25519_2 = std::array<unsigned char, crypto_scalarmult_curve25519_BYTES>;

auto random_point_25519_2()
{
    // Random x value
    scalar25519_2 x;
    bcs::pseudo_random::fill(x);

    // P = x G
    point25519_2 P;
    crypto_scalarmult_curve25519_base(P.data(), x.data());
    return P;
}

bool test25519_2()
{
    auto P = random_point_25519_2();

    std::array<scalar25519_2, test_iterations> values;
    for (auto& x: values)
        bcs::pseudo_random::fill(x);

    bcs::timer time;
    auto duration = time.execution([&]
        {
            point25519_2 result;
            for (auto& x: values)
            {
                auto success =
                    crypto_scalarmult_curve25519(result.data(), x.data(), P.data()) == 0;
                assert(success);
            }

            //assert(crypto_core_is_valid_point(P.data()));
        });
    std::cout << "djb 25519 took: " << duration << " ms" << std::endl;

    std::cout << "djb 25519 done." << std::endl;
    return true;
}
#endif

using scalar_fast25519 = std::array<uint8_t, 32>;
using point_fast25519 = std::array<uint8_t, 64>;

auto random_point_fast25519()
{
    // Random x value
    scalar_fast25519 x;
    bcs::pseudo_random::fill(x);

    // P = x G
    point_fast25519 P;
    uint8_t buf1[64];
    curve25519_dh_CalculatePublicKey(P.data(), x.data());
    return P;
}

extern "C" {
typedef unsigned char       U8;

#define IN
#define OUT

void ecp_PointMultiply(OUT U8 *Q, IN const U8 *P, IN const U8 *K, IN int len);
}

bool test_fast25519()
{
    auto P = random_point_fast25519();

    std::array<scalar_fast25519, test_iterations> values;
    for (auto& x: values)
        bcs::pseudo_random::fill(x);

    bcs::timer time;
    auto duration = time.execution([&]
        {
            point_fast25519 result;
            for (auto& x: values)
            {
                //curve25519_dh_CreateSharedKey(result.data(), P.data(), x.data());
                ecp_PointMultiply(result.data(), P.data(), x.data(), 32);
            }

            //assert(crypto_core_is_valid_point(P.data()));
        });
    std::cout << "fast 25519 took: " << duration << " ms" << std::endl;

    std::cout << "fast 25519 done." << std::endl;
    return true;
}

auto random_secret()
{
    bcs::ec_secret secret;
    do
    {
        bcs::pseudo_random::fill(secret);
    } while (!bcs::verify(secret));
    return secret;
}

auto random_point_secp()
{
    return random_secret() * bcs::ec_point::G;
}

bool testsecp()
{
    auto P = random_point_secp();
    if (!bcs::verify(P))
        return false;

    std::array<bcs::ec_secret, test_iterations> values;
    for (auto& x: values)
        x = random_secret();

    auto context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey point;
    auto success =
        secp256k1_ec_pubkey_parse(context, &point, P.point().data(), 33) == 1;
    assert(success);

    bcs::timer time;
    auto duration = time.execution([&]
        {
            for (auto& x: values)
            {
                success = secp256k1_ec_pubkey_tweak_mul(context, &point, x.data()) == 1;
                assert(success);
            }
        });
    std::cout << "secp took: " << duration << " ms" << std::endl;

    std::cout << "secp done." << std::endl;
    return true;
}

auto random_point_ssl()
{
    // Random x value
    scalar_fast25519 x;
    bcs::pseudo_random::fill(x);

    // P = x G
    point_fast25519 P;

    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, x.data(), 32);

    size_t public_size = 32;
    int status = EVP_PKEY_get_raw_public_key(key, P.data(), &public_size);
    assert(status == 1);
    assert(public_size == 32);
    return P;
}

bool test_ssl25519()
{
    auto P = random_point_ssl();

    std::array<scalar_fast25519, test_iterations> values;
    for (auto& x: values)
        bcs::pseudo_random::fill(x);

    bcs::timer time;
    auto duration = time.execution([&]
        {
            point_fast25519 result;
            for (auto& x: values)
            {
  int status;
  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, x.data(), 32);
  EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, P.data(), 32);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);

  status = EVP_PKEY_derive_init(ctx);
  assert(status == 1);

  status = EVP_PKEY_derive_set_peer(ctx, peer_key);
  assert(status == 1);

  size_t size = 32;
  status = EVP_PKEY_derive(ctx, result.data(), &size);
  assert(status == 1);
  assert(size == 32);

            }

            //assert(crypto_core_is_valid_point(P.data()));
        });
    std::cout << "ssl 25519 took: " << duration << " ms" << std::endl;

    std::cout << "ssl 25519 done." << std::endl;
    return true;
}


int main()
{
#ifdef SODIUM
    test25519();
    test25519_hydrogen();
#endif
#ifdef DJB
    test25519_2();
#endif
    test_fast25519();
    test_ssl25519();
    testsecp();

    return 0;
}

