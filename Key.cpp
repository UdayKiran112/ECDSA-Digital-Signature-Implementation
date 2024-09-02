#include <bits/stdc++.h>
#include "Key.h"
using namespace std;

Key::Key() {}

Key::Key(csprng *RNG)
{
    if (RNG == NULL)
    {
        throw invalid_argument("Random Number Generator is null");
    }
    octet priv;
    priv.len = EGS_SECP256K1;
    priv.max = EGS_SECP256K1;
    priv.val = new char[priv.len];
    generatePrivateKey(RNG, &priv);
    this->setPrivateKey(priv);

    octet pub;
    pub.len = EFS_SECP256K1;
    pub.max = EFS_SECP256K1;
    pub.val = new char[pub.len];
    SECP256K1::ECP G;
    setGeneratorPoint(&G);
    generatePublicKey(&priv, &pub, &G);
    this->setPublicKey(pub);

    memset(priv.val, 0, priv.len);
    memset(pub.val, 0, pub.len);
}

octet Key::getPrivateKey()
{
    return privateKey;
}

octet Key::getPublicKey()
{
    return publicKey;
}

void Key::setPrivateKey(octet privateKey)
{
    this->privateKey = privateKey;
}

void Key::setPublicKey(octet publicKey)
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
        cout << "Point Generated" << endl;
        ECP_output(G);
    }
}

int Key::generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey)
{
    using namespace SECP256K1;
    using namespace B256_56;

    BIG secret;

    if (randomNumberGenerator != nullptr)
    {
        BIG_random(secret, randomNumberGenerator);
    }
    else
    {
        BIG_fromBytes(secret, PrivateKey->val);
    }

    BIG_toBytes(PrivateKey->val, secret);

    return 0;
}

int Key::generatePublicKey(octet *PrivateKey, octet *publicKey, SECP256K1::ECP *generatorPoint)
{
    using namespace SECP256K1;
    using namespace B256_56;

    int res = 0;
    BIG secret, curve_order;

    BIG_rcopy(curve_order, CURVE_Order);

    BIG_fromBytes(secret, PrivateKey->val);
    ECP_clmul(generatorPoint, secret, curve_order);
    ECP_toOctet(publicKey, generatorPoint, false);

    // Validating Public Key
    res = SECP256K1::ECP_PUBLIC_KEY_VALIDATE(publicKey);
    if (res != 0)
    {
        cout << " ECP Public Key Validation Failed " << endl;
        return -1;
    }
    return res;
}