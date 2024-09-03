#include <bits/stdc++.h>
#include "Key.h"
using namespace std;

using namespace B256_56;
using namespace SECP256K1;

// int main()
// {
//     unsigned long ran;
//     char raw[100];
//     octet RAW = {0, sizeof(raw), raw};
//     csprng RNG;
//     time((time_t *)&ran);
//     RAW.len = 100;
//     RAW.val[0] = ran;
//     RAW.val[1] = ran >> 8;
//     RAW.val[2] = ran >> 16;
//     RAW.val[3] = ran >> 24;
//     for (int i = 4; i < 100; i++)
//         RAW.val[i] = i;
//     CREATE_CSPRNG(&RNG, &RAW);

//     // // octet privateKey;
//     // SECP256K1::ECP generator;
//     // Key::setGeneratorPoint(&generator);

//     // Prepare octets for the private and public keys
//     char privateKey_val[EGS_SECP256K1];        // EGS_SECP256K1 is the size of the private key
//     char publicKey_val[2 * EFS_SECP256K1 + 1]; // Public key is a point, so it's larger

//     octet privateKey = {0, sizeof(privateKey_val), privateKey_val};
//     octet publicKey = {0, sizeof(publicKey_val), publicKey_val};

//     // Generate the key pair
//     if (SECP256K1::ECP_KEY_PAIR_GENERATE(&RNG, &privateKey, &publicKey) != 0)
//     {
//         cerr << "Key generation failed!" << endl;
//         return 1;
//     }
//     BIG privKey, pubKey, r;
//     B256_56::BIG_rcopy(r, CURVE_Order);
//     B256_56::BIG_fromBytes(privKey, privateKey.val);
//     B256_56::BIG_fromBytes(pubKey, publicKey.val);
//     // Check if the private key is within the valid range
//     if (B256_56::BIG_iszilch(privKey) || B256_56::BIG_comp(privKey, r) >= 0)
//     {
//         cerr << "Invalid private key generated!" << endl;
//         return 1;
//     }

//     // Generate the public key
//     if (SECP256K1::ECP_PUBLIC_KEY_VALIDATE(&publicKey) != 0)
//     {
//         cerr << "Public key generation failed!" << endl;
//         return 1;
//     }

//     // Print the generated keys
//     cout << "Private Key: ";
//     OCT_output(&privateKey);
//     cout << endl;

//     cout << "Public Key: ";
//     OCT_output(&publicKey);
//     cout << endl;

//     // Clean up
//     KILL_CSPRNG(&RNG);
// }

int main()
{
    // Initialize random seed using a combination of time and random_device for better entropy
    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;

    // Improve seed generation by combining time and random_device
    std::random_device rd;
    ran = static_cast<unsigned long>(time(nullptr)) ^ rd();

    // Populate RAW with random data
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;

    // Fill the rest of RAW with high-entropy data
    for (int i = 4; i < 100; i++)
    {
        RAW.val[i] = rd() & 0xFF; // Use random_device to fill the remaining bytes
    }

    // Initialize CSPRNG
    core::CREATE_CSPRNG(&RNG, &RAW);

    // Use try-catch to handle potential exceptions
    try
    {
        Key key(&RNG);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        core::KILL_CSPRNG(&RNG);
        return -1;
    }

    // Clean up the CSPRNG
    core::KILL_CSPRNG(&RNG);

    return 0;
}
