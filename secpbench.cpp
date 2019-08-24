#include <array>
#include <cassert>
#include <iostream>
#include <bitcoin/system.hpp>
#include <secp256k1.h>

constexpr auto test_iterations = 100'000;

namespace bcs = bc::system;

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

int main()
{
    testsecp();

    return 0;
}

