#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message()
{
}

Message::~Message()
{
    delete[] message.val;
    delete[] Hashvalue.val;
}

Message::Message(string message)
{
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    this->Hashvalue.len = 32;
    this->Hashvalue.max = 32;
    this->Hashvalue.val = new char[32];
    Hash_Function(&this->message, &this->Hashvalue, 0);
}

core::octet Message::getMessage()
{
    return message;
}

void Message::setMessage(core::octet message)
{
    this->message = message;
}

using namespace core;
using namespace SECP256K1;
using namespace B256_56;

void Message::Hash_Function(octet *input, octet *output, int pad)
{
    int n = -1;
    GPhash(SHA256, 32, output, 32, pad, input, n, nullptr);

    BIG x, prime;
    BIG_fromBytes(x, output->val);
    BIG_zero(prime);
    BIG_rcopy(prime, Modulus);
    BIG_mod(x, prime);
    output->len = 32;
    output->max = 32;
    output->val = new char[32];
    BIG_toBytes(output->val, x);
}

void Message::Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;
    result->len = total_length;
    memcpy(result->val, data1->val, data1->len);
    memcpy(result->val + data1->len, data2->val, data2->len);
}

void Message::add_octets(octet *data1, octet *data2, octet *result)
{
    BIG point1, point2;
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    BIG sum;
    BIG_add(sum, point1, point2);
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, sum);
}

void Message::multiply_octet(octet *data1, octet *data2, octet *result)
{
    BIG point1, point2;
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    BIG product;
    BIG_mul(product, point1, point2);
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, product);
}