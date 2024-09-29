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

    // Initialize Signature
    this->Signature.first.len = 32;
    this->Signature.first.max = 32;
    this->Signature.first.val = new char[32];
    this->Signature.second.len = 32;
    this->Signature.second.max = 32;
    this->Signature.second.val = new char[32];

    // hashing Message
    octet hash_val;
    hash_val.len = HASH_TYPE_SECP256K1;
    hash_val.max = HASH_TYPE_SECP256K1;
    hash_val.val = new char[HASH_TYPE_SECP256K1];

    Hash_Function(hash_val.len, &this->message, &hash_val);
    this->setHashvalue(hash_val);

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
pair<octet, octet> Message::getSignature()
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
void Message::setSignature(pair<octet, octet> Signature)
{
    this->Signature.first = Signature.first;
    this->Signature.second = Signature.second;
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
void Message::Hash_Function(int hlen, octet *input, octet *output)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, input);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);
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

    pair<octet, octet> sign;

    octet hashval = msg->getHashvalue();

    // All declarations
    BIG k, x, w, r, s, mod, invk, hval, masked_k, privval;
    ECP R, G;

    ECP_generator(&G);           // set Generator Point
    BIG_rcopy(mod, CURVE_Order); // copy curve order to mod

    BIG_fromBytes(privval, privateKey->val); // copy private key to privval

    // hash length check and copy hashval to hval
    int blen = hashval.len;
    if (hashval.len > EGS_SECP256K1)
    {
        blen = EGS_SECP256K1;
    }

    BIG_fromBytesLen(hval, hashval.val, blen); // copy hashval to hval

    // Actual Signature Generation Process loop
    do
    {
        BIG_randomnum(k, mod, RNG); // k = random number from [1, n-1]
        BIG_randomnum(w, mod, RNG); /* IMPORTANT - side channel masking to protect invmodp() */

        ECP_copy(&R, &G);      // set R = G
        ECP_clmul(&R, k, mod); // R = k * G

        ECP_get(x, x, &R); // x = R.x

        BIG_copy(r, x);  // r = x
        BIG_mod(r, mod); // r = x mod n

        if (BIG_iszilch(r))
            continue;

        // Now getting into equation s = k^-1 * (h + r* privKey)(mod n)

        BIG_modmul(masked_k, k, w, mod);  // masked_k = k * w
        BIG_invmodp(invk, masked_k, mod); // invk = k^-1 * w^-1

        BIG_modmul(s, r, privval, mod); // s = r * privKey
        BIG_modadd(s, hval, s, mod);    // s = h + r * privKey
        BIG_modmul(s, s, w, mod);       // s = h + r * privKey * w --> side channel masking

        BIG_modmul(s, invk, s, mod); // temp = k^-1 * (h + r * privKey)
    } while (BIG_iszilch(s));

    // Convert BIG to FP
    sign.first.len = EGS_SECP256K1;
    sign.first.max = EGS_SECP256K1;
    sign.first.val = new char[EGS_SECP256K1];

    sign.second.len = EGS_SECP256K1;
    sign.second.max = EGS_SECP256K1;
    sign.second.val = new char[EGS_SECP256K1];

    BIG_toBytes(sign.first.val, r);
    BIG_toBytes(sign.second.val, s);

    this->setSignature(sign);
    return true;
}

bool Message::verifySignature(Message *msg, octet *publicKey)
{
    using namespace B256_56;
    using namespace SECP256K1;

    pair<octet, octet> signature = msg->getSignature(); // get signature
    octet hashval = msg->getHashvalue();                // get hash value of message

    // All declarations
    BIG hashval_big, mod, r, r1, s, temp1, temp2;
    ECP G, pubKey;

    ECP_generator(&G);           // set Generator Point
    BIG_rcopy(mod, CURVE_Order); // copy curve order to mod

    int res = 0;
    int valid = ECP_fromOctet(&pubKey, publicKey); // set public key to pubKey

    // hash length check and copy hashval to hval
    int blen = hashval.len;
    if (hashval.len > EGS_SECP256K1)
    {
        blen = EGS_SECP256K1;
    }

    BIG_fromBytesLen(hashval_big, hashval.val, blen); // copy hashval to hval

    // Extract (r,s) from signature
    BIG_fromBytes(r, signature.first.val);
    BIG_fromBytes(s, signature.second.val);

    // Check if signature is valid
    if (BIG_iszilch(r) || BIG_comp(r, mod) >= 0 || BIG_iszilch(s) || BIG_comp(s, mod) >= 0)
    {
        cerr << "Error: Invalid signature" << endl;
        return false;
    }

    // Actual Signature Verification process loop
    if (res == 0)
    {
        BIG_invmodp(s, s, mod);                 // s = s^-1
        BIG_modmul(temp1, hashval_big, s, mod); // temp1 = h * s^-1
        BIG_modmul(temp2, r, s, mod);           // temp2 = r * s^-1

        valid = ECP_fromOctet(&pubKey, publicKey); // set public key to pubKey

        if (valid != 0)
        {
            res = ECDH_ERROR;
        }
        else
        {
            ECP_mul2(&pubKey, &G, temp2, temp1); // pubKey = G * temp1 + temp2 * pubKey

            if (ECP_isinf(&pubKey))
            {
                res = ECDH_ERROR;
            }
            else
            {
                ECP_get(r1, r1, &pubKey); // r1 = pubKey.x
                BIG_mod(r1, mod);         // r1 = r1 mod

                if (BIG_comp(r1, r) != 0)
                {
                    res = ECDH_ERROR;
                }
            }
        }
    }

    if (res == 0)
    {
        cout << "Signature verified successfully" << endl;
        return true;
    }
    else
    {
        cout << "Signature verification failed" << endl;
        return false;
    }
}