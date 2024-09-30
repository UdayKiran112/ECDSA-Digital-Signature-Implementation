#include <bits/stdc++.h>
#include "Key.h"
using namespace std;

Key::~Key()
{
}

Key::Key(csprng *RNG)
{
    if (RNG == NULL)
    {
        throw invalid_argument("Random Number Generator is null");
    }

    SECP256K1::ECP G;
    setGeneratorPoint(&G);

    char priv[2 * EGS_SECP256K1];
    octet privval = {0, sizeof(priv), priv};

    // Generate private key
    if (generatePrivateKey(RNG, &privval) != 0)
    {
        throw runtime_error("Failed to generate private key");
    }
    this->setPrivateKey(privval);

    // Print private key--> DEBUG INFO
    cout << "!!!   Private Key in constructor: " << endl;
    OCT_output(&privval);
    cout << endl;

    // Initialise public key
    SECP256K1::ECP pub;

    // Generate public key
    if (generatePublicKey(&privval, &pub, &G) != 0)
    {
        throw runtime_error("Failed to generate public key");
    }
    this->setPublicKey(pub);
}

octet Key::getPrivateKey()
{
    return privateKey;
}

SECP256K1::ECP Key::getPublicKey()
{
    return publicKey;
}

void Key::setPrivateKey(octet privateKey)
{
    this->privateKey = privateKey;
}

void Key::setPublicKey(SECP256K1::ECP publicKey)
{
    this->publicKey = publicKey;
}

void Key::setGeneratorPoint(SECP256K1::ECP *G)
{
    using namespace SECP256K1;
    ECP P;
    bool gen = ECP_generator(&P);
    if (gen == 0)
    {
        throw invalid_argument("Failed to generate generator point");
    }

    if (ECP_isinf(&P) == 1)
    {
        throw runtime_error("Generator point is infinity");
    }
    else
    {
        ECP_copy(G, &P);
    }
}


int Key::generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey)
{
    using namespace SECP256K1;
    using namespace B256_56;

    BIG secret, r;

    BIG_rcopy(r, CURVE_Order);

    if (randomNumberGenerator != nullptr)
    {
        BIG_randomnum(secret, r, randomNumberGenerator);
    }
    else
    {
        throw runtime_error("Random Number Generator is null");
    }
    PrivateKey->len = 2 * EGS_SECP256K1;
    BIG_toBytes(PrivateKey->val, secret);

    return 0;
}

int Key::generatePublicKey(octet *PrivateKey, SECP256K1::ECP *publicKey, SECP256K1::ECP *generatorPoint)
{
    cout << "----------Generating Public Key----------" << endl;
    using namespace SECP256K1;
    using namespace B256_56;

    try
    {
        BIG secret, curve_order;
        ECP G;

        BIG_rcopy(curve_order, CURVE_Order);
        BIG_fromBytes(secret, PrivateKey->val);

        ECP_copy(&G, generatorPoint);
        ECP_clmul(&G, secret, curve_order);

        if (ECP_isinf(&G))
        {
            throw runtime_error("Generated point is at infinity.");
        }

        ECP_copy(publicKey, &G);

        // Print ECP public key
        cout << "!!!   Public Key as in generatePublicKey function: ";
        ECP_output(&G);
        cout << endl;

        cout << "----------Public Key Generated Successfully----------" << endl;

        return 0;
    }
    catch (const exception &e)
    {
        cerr << "Error in generating public key: " << e.what() << endl;
        return -1;
    }
}
