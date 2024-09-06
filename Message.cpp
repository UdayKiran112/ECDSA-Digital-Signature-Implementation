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
}

// Destructor
Message::~Message()
{
    // Freeing Dynamically allocated memory for octet values
    if (message.val != nullptr)
        delete[] message.val;
    if (Hashvalue.val != nullptr)
        delete[] Hashvalue.val;
}

// Constructor which takes string as input
Message::Message(string message, octet *privateKey, csprng *RNG)
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

    // hashing Message
    octet hash_val;
    Hash_Function(&this->message, &hash_val, 0);
    setHashvalue(hash_val);

    // Initialize Signature
    if (!generateSignature(RNG, privateKey, this))
    {
        cout << "Signature generation failed" << endl;
        exit(1);
    }

    cout << "Signature generated" << endl;
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
pair<FP, FP> Message::getSignature()
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
void Message::setSignature(pair<FP, FP> Signature)
{
    this->Signature = Signature;
}

/*
    Other operations
*/

// Function to convert octet to FP type
void octet_to_FP(FP *fp, octet *octet)
{
    BIG b;
    BIG_fromBytes(b, octet->val);
    FP_nres(fp, b);
}

// Function to convert FP to octet type
void FP_to_octet(octet *octet, FP *fp)
{
    BIG b;
    FP_redc(b, fp);
    BIG_toBytes(octet->val, b);
}

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

    output->val = new char[32];
    output->len = 32;
    output->max = 32;

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

bool Message::generateSignature(csprng *RNG, octet *privateKey, Message *msg)
{
    using namespace B256_56;
    Key random = Key(RNG);
    pair<FP, FP> signature_temp;

    octet hashval = msg->getHashvalue();

    cout << "Hashvalue: ";
    OCT_output(&hashval);
    cout << endl;

    octet k = random.getPrivateKey();
    octet R_oct = random.getPublicKey();
    // Convert k to BIG
    BIG kval;
    BIG_fromBytes(kval, k.val);

    // Convert hashval to BIG
    BIG hval;
    BIG_fromBytes(hval, hashval.val);

    // Convert privateKey to BIG
    BIG xval;
    BIG_fromBytes(xval, privateKey->val);

    // R_oct to ECP
    ECP R;
    ECP_fromOctet(&R, &R_oct);

    // Extract r from R
    FP r;
    r = R.x;

    // convert r to BIG
    BIG rval;
    FP_redc(rval, &r);

    // copy Modulus to non const BIG
    BIG mod;
    BIG_rcopy(mod, Modulus);

    // Now getting into equation s = k^-1 * (h + r* privKey)(mod n)

    // Convert k to k^-1
    BIG invk;
    BIG_invmodp(invk, kval, mod);

    // r * privKey
    BIG temp;
    BIG_modmul(temp, rval, xval, mod); // temp = r * privKey

    // h + r * privKey
    BIG temp2;
    BIG_modadd(temp2, hval, temp, mod); // temp2 = h + r * privKey

    // k^-1 * (h + r * privKey)
    BIG temp3;
    BIG_modmul(temp3, invk, temp2, mod); // temp3 = k^-1 * (h + r * privKey)

    // Convert BIG to FP
    signature_temp.first = r;
    FP_nres(&signature_temp.second, temp3);

    this->setSignature(signature_temp);
    return true;
}

bool Message::verifySignature(Message *msg, octet *publicKey)
{
    cout << "Verifying signature..." << endl;
    pair<FP, FP> signature = msg->getSignature();
    SECP256K1::ECP G;
    Key::setGeneratorPoint(&G);

    ECP pubKey;
    ECP_fromOctet(&pubKey, publicKey);

    octet hashval = msg->getHashvalue(); // h

    // Convert hashval to BIG
    BIG hashval_big;
    BIG_fromBytes(hashval_big, hashval.val);

    // COnvert Modulus to non const BIG
    BIG mod;
    BIG_rcopy(mod, Modulus);

    // convert r to BIG
    BIG r;
    FP_redc(r, &(signature.first));

    // convert s to BIG
    BIG s;
    FP_redc(s, &(signature.second));

    // get s1 = s^-1 mod n
    BIG s1;
    BIG_invmodp(s1, s, mod);

    // h* s1
    BIG temp1;
    BIG_modmul(temp1, hashval_big, s1, mod);

    //  r * s1
    BIG temp2;
    BIG_modmul(temp2, r, s1, mod);

    // temp1 * G + temp2 * pubKey
    ECP temp3;
    ECP_mul2(&G, &pubKey, temp1, temp2);
    ECP_copy(&temp3, &G);

    // get FP from ECP
    BIG r1;
    FP r_dash = temp3.x;
    FP_redc(r1, &r_dash);

    // check if r == r1
    if (BIG_comp(r, r1) == 0)
    {
        cout << "Signature verified" << endl;
        return true;
    }
    else
    {
        cout << "Signature not verified" << endl;
        return false;
    }
}
