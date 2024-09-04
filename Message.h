#pragma once

#include <bits/stdc++.h>
#include "Key.h"
#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include "Lib/core.h"
#include "Lib/eddsa_SECP256K1.h"
#include "Lib/config_big_B256_56.h"
using namespace std;
using namespace SECP256K1;

class Message
{
private:
    core::octet message;
    core::octet Hashvalue;
    pair<FP,FP> Signature;

public:
    Message();
    ~Message();
    Message(string message);
    core::octet getMessage();
    core::octet getHashvalue();
    pair<SECP256K1::FP,SECP256K1::FP> getSignature();

    void setMessage(core::octet message);
    void setHashvalue(core::octet Hashvalue);
    void setSignature(pair<FP,FP> Signature);

    static void Concatenate_octet(octet *data1, octet *data2, octet *result);
    static void Hash_Function(octet *input, octet *output, int pad);
    static void add_octets(octet *data1, octet *data2, octet *result);
    static void multiply_octet(octet *data1, octet *data2, octet *result);
    bool generateSignature(csprng *RNG, octet *privateKey, Message *msg);
    bool verifySignature(Message *msg,SECP256K1::ECP *publicKey);
};

#endif // MESSAGE_H