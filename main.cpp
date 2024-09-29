#include <bits/stdc++.h>
#include "Key.h"
#include "Message.h"

using namespace std;
using namespace B256_56;
using namespace SECP256K1;

bool checkFunction(csprng *RNG, ECP *generatorPoint)
{
    Key pair1 = Key(RNG);
    Key pair2 = Key(RNG);

    octet alpha = pair1.getPrivateKey();
    octet beta = pair2.getPrivateKey();

    Key::setGeneratorPoint(generatorPoint);

    ECP A, B;
    BIG curve_order;

    BIG alpha_new, beta_new;
    BIG_fromBytes(alpha_new, alpha.val);
    BIG_fromBytes(beta_new, beta.val);

    BIG_rcopy(curve_order, CURVE_Order);
    ECP_copy(&A, generatorPoint);
    ECP_clmul(&A, alpha_new, curve_order);

    ECP_copy(&B, generatorPoint);
    ECP_clmul(&B, beta_new, curve_order);

    BIG combined;
    BIG_add(combined, alpha_new, beta_new);
    ECP lhs;
    ECP_copy(&lhs, generatorPoint);
    ECP_clmul(&lhs, combined, curve_order);

    ECP_add(&A, &B);
    ECP rhs;
    ECP_copy(&rhs, &A);

    if (ECP_equals(&lhs, &rhs))
    {
        return true;
    }
    else
    {
        return false;
    }
}

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

    Key key(&RNG);

    ECP G;
    Key::setGeneratorPoint(&G);

    // Store private key in a variable
    octet privateKey = key.getPrivateKey();

    // print private key
    cout << "Private Key: ";
    OCT_output(&privateKey);
    cout << endl;

    // Store public key in a variable
    octet publicKey = key.getPublicKey();

    if (ECP_PUBLIC_KEY_VALIDATE(&publicKey) == 0)
    {
        return 0;
    }

    // print public key
    cout << "Public Key: ";
    OCT_output(&publicKey);
    cout << endl;

    // Initialize Message
    string message = "Hello World!";
    cout << "Message: " << message << endl;
    Message msg(message, &key, &RNG);

    ECP gnpnt;
    Key::setGeneratorPoint(&gnpnt);

    bool check = checkFunction(&RNG, &gnpnt);
    cout << "Check: " << check << endl;

    // Clean up the CSPRNG
    core::KILL_CSPRNG(&RNG);

    return 0;
}
