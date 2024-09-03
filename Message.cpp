#include <bits/stdc++.h>
#include "Message.h"

using namespace std;
using namespace B256_56;
using namespace SECP256K1;

// Default constructor
Message::Message()
{
    // Initialize message
    message.len = 0;
    message.max = 0;
    message.val = NULL;

    // Initialize Hashvalue
    Hashvalue.len = 0;
    Hashvalue.max = 0;
    Hashvalue.val = NULL;

    // Initialize Signature
    BIG_zero(Signature.first);
    Signature.second.len = 0;
    Signature.second.max = 0;
    Signature.second.val = NULL;
}

// Destructor
Message::~Message()
{
    // Freeing Dynamically allocated memory for octet values
    delete[] message.val;
    delete[] Hashvalue.val;
    delete[] Signature.second.val;
}

// Constructor which takes string as input
Message::Message(string message)
{
    // Initialize message
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    // Initialize Hashvalue
    this->Hashvalue.len = 32;
    this->Hashvalue.max = 32;
    this->Hashvalue.val = new char[32];

    // Functionalities done
    Hash_Function(&this->message, &this->Hashvalue, 0);
    // TO DO
}

/*
    Getter and Setter functions
*/

// Message getter
core::octet Message::getMessage()
{
    return message;
}

// Hashvalue getter
core::octet Message::getHashvalue()
{
    return Hashvalue;
}

// Signature getter
pair<BIG, octet> Message::getSignature()
{
    return Signature;
}

// Message setter
void Message::setMessage(octet message)
{
    this->message = message;
}

// Hashvalue setter
void Message::setHashvalue(octet Hashvalue)
{
    this->Hashvalue = Hashvalue;
}

// Signature setter
void Message::setSignature(pair<BIG, octet> Signature)
{
    BIG_copy(this->Signature.first, Signature.first);

    // Manage memory for the octet part (avoid memory leaks)
    if (this->Signature.second.val != nullptr)
    {
        delete[] this->Signature.second.val;
    }
    OCT_copy(&this->Signature.second, &Signature.second);
}

/*
    Other operations
*/

// Static method to compute a hash of an input octet and store it in the output octet
void Message::Hash_Function(octet *input, octet *output, int pad)
{
    int n = -1;
    // Perform hashing using the GPhash function (e.g., SHA256)
    GPhash(SHA256, 32, output, 32, pad, input, n, nullptr);

    // Convert the hash result into a BIG type for further manipulation
    BIG x, prime;
    BIG_fromBytes(x, output->val); // Convert bytes to BIG
    BIG_zero(prime);
    BIG_rcopy(prime, Modulus); // Load the curve modulus
    BIG_mod(x, prime);         // Apply modulo operation to the BIG value

    // Assign the resulting BIG value back to the octet
    output->len = 32;
    output->max = 32;
    output->val = new char[32];
    BIG_toBytes(output->val, x); // Convert BIG back to bytes
}

// Static method to concatenate two octets
void Message::Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;
    result->len = total_length;
    result->max = total_length;
    result->val = new char[total_length];

    // Copy the contents of data1 and data2 into the result
    memcpy(result->val, data1->val, data1->len);
    memcpy(result->val + data1->len, data2->val, data2->len);
}

// Static method to add two octets (interpreted as BIG integers)
void Message::add_octets(octet *data1, octet *data2, octet *result)
{
    BIG point1, point2, sum;
    // Convert the octets to BIG integers
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);

    // Perform the addition
    BIG_add(sum, point1, point2);

    // Convert the result back to an octet
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, sum);
}

// Static method to multiply two octets (interpreted as BIG integers)
void Message::multiply_octet(octet *data1, octet *data2, octet *result)
{
    BIG point1, point2, product;
    // Convert the octets to BIG integers
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);

    // Perform the multiplication
    BIG_mul(product, point1, point2);

    // Convert the result back to an octet
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, product);
}
