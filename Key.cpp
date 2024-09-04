#include <bits/stdc++.h>
#include "Key.h"
using namespace std;

Key::~Key()
{
    delete[] privateKey.val;
}

Key::Key(csprng *RNG)
{
    if (RNG == NULL)
    {
        throw invalid_argument("Random Number Generator is null");
    }

    // Initialise private key
    char priv_val[EGS_SECP256K1];
    octet priv = {0, sizeof(priv_val), priv_val};

    // Generate private key
    if (generatePrivateKey(RNG, &priv) != 0)
    {
        throw runtime_error("Failed to generate private key");
    }
    this->setPrivateKey(priv);

    // Initialise public key
    SECP256K1::ECP pub;

    // Generate public key
    SECP256K1::ECP G;
    setGeneratorPoint(&G);
    if (generatePublicKey(&priv, &pub, &G) != 0)
    {
        throw runtime_error("Failed to generate public key");
    }
    this->setPublicKey(pub);

    // Zero out sensitive data
    memset(priv.val, 0, priv.len);
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
        cout << "Generator Point :" << endl;
        ECP_output(G);
        cout << endl;
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
    PrivateKey->len = EGS_SECP256K1;
    BIG_toBytes(PrivateKey->val, secret);

    return 0;
}

int Key::generatePublicKey(octet *PrivateKey, SECP256K1::ECP *publicKey, SECP256K1::ECP *generatorPoint)
{
    using namespace SECP256K1;
    using namespace B256_56;

    int res = 0;
    BIG secret, curve_order;
    ECP G;

    BIG_rcopy(curve_order, CURVE_Order);

    BIG_fromBytes(secret, PrivateKey->val);
    ECP_copy(&G, generatorPoint);
    ECP_clmul(&G, secret, curve_order);

    // Print Public Key
    cout << "Public Key :" << endl;
    ECP_output(&G);
    cout << endl;
    octet PUBKEY;
    ECP_toOctet(&PUBKEY, &G, true);

    // Validating Public Key
    res = SECP256K1::ECP_PUBLIC_KEY_VALIDATE(&PUBKEY);
    if (res != 0)
    {
        cout << " ECP Public Key Validation Failed " << endl;
        return -1;
    }
    return res;
}