#ifndef KEY_H // Check if KEY_H is not defined
#define KEY_H // Define KEY_H

#pragma once

#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/randapi.h"
#include "Lib/big_B256_56.h"
#include "Lib/ecp_SECP256K1.h"
#include "Lib/ecdh_SECP256K1.h"

class Key
{
private:
    octet privateKey;
    octet publicKey;

public:
    Key(csprng *RNG);
    Key();
    octet getPrivateKey();
    octet getPublicKey();
    void setPrivateKey(octet privateKey);
    void setPublicKey(octet publicKey);
    static void setGeneratorPoint(SECP256K1::ECP *G);
    static int generatePublicKey(octet *PrivateKey, octet *publicKey, SECP256K1::ECP *generatorPoint);
    static int generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey);
};

#endif // End of KEY_H