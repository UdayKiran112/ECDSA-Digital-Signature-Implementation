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
    hash_val.len = 128;
    hash_val.max = 128;
    hash_val.val = new char[128];

    Hash_Function(&this->message, &hash_val);
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
void Message::Hash_Function(octet *input, octet *output)
{
    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, 128, output, input);
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

    pair<octet, octet> signature_temp;

    octet hashval = msg->getHashvalue();

    cout << "Hashvalue: ";
    OCT_output(&hashval);
    cout << endl;

    // All declarations
    BIG kval, hval, x, mod, w, rval, maskedPrivKey, invk, temp;
    ECP R;

    // copy CURVE_Order to non const BIG
    BIG_rcopy(mod, CURVE_Order);

    int blen = hashval.len;
    if (blen > EGS_SECP256K1)
    {
        blen = EGS_SECP256K1;
    }
    // Convert hashval to BIG
    BIG_fromBytesLen(hval, hashval.val, blen);

    do
    {
        Key random = Key(RNG);
        octet k = random.getPrivateKey();
        octet R_oct = random.getPublicKey();

        // Convert k(private key) to BIG
        BIG_fromBytes(kval, k.val);

        // R_oct to ECP
        ECP_fromOctet(&R, &R_oct);

        // Extract r from R using ECP_get
        ECP_get(x, x, &R);

        // Side channel Masking
        BIG_randomnum(w, mod, RNG); /* IMPORTANT - side channel masking to protect invmodp() */

        // convert r to BIG
        BIG_copy(rval, x);
        BIG_mod(rval, mod);
        if (BIG_iszilch(rval))
            continue;

        // Now getting into equation s = k^-1 * (h + r* privKey)(mod n)

        // Multiply privKey by w for side-channel masking
        BIG_modmul(maskedPrivKey, kval, w, mod);

        // Convert k to k^-1 (inverse modulo)
        BIG_invmodp(invk, maskedPrivKey, mod);
        if (BIG_iszilch(invk))
        {
            cerr << "Error: k^-1 = 0" << endl;
            return false;
        }

        // r * privKey
        BIG_modmul(temp, rval, kval, mod); // temp = r * privKey

        // h + r * privKey
        BIG_modadd(temp, hval, temp, mod); // temp = h + r * privKey

        BIG_modmul(temp, temp, w, mod); // temp = h + r * privKey * w --> side channel masking

        // k^-1 * (h + r * privKey)
        BIG_modmul(temp, invk, temp, mod); // temp3 = k^-1 * (h + r * privKey)

    } while (BIG_iszilch(temp));

    if (BIG_iszilch(temp))
    {
        cerr << "Error: k^-1 * (h + r * privKey) = 0" << endl;
        return ECDH_ERROR;
    }
    // Convert BIG to FP
    signature_temp.first.len = EGS_SECP256K1;
    signature_temp.first.max = EGS_SECP256K1;
    signature_temp.first.val = new char[EGS_SECP256K1];

    signature_temp.second.len = EGS_SECP256K1;
    signature_temp.second.max = EGS_SECP256K1;
    signature_temp.second.val = new char[EGS_SECP256K1];

    BIG_toBytes(signature_temp.first.val, rval);
    BIG_toBytes(signature_temp.second.val, temp);

    this->setSignature(signature_temp);
    return true;
}

bool Message::verifySignature(Message *msg, octet *publicKey)
{
    cout << "Verifying signature..." << endl;

    pair<octet, octet> signature = msg->getSignature();

    SECP256K1::ECP G;
    Key::setGeneratorPoint(&G);

    ECP pubKey;
    int valid = ECP_fromOctet(&pubKey, publicKey);

    if (valid != 0)
    {
        cerr << "Error: Public Key Validation Failed" << endl;
        return false;
    }

    octet hashval = msg->getHashvalue(); // h

    int blen = hashval.len;
    if (hashval.len > EGS_SECP256K1)
    {
        blen = EGS_SECP256K1;
    }

    // Convert hashval to BIG
    BIG hashval_big;
    BIG_fromBytesLen(hashval_big, hashval.val, blen);

    // COnvert CURVE_Order to non const BIG
    BIG mod;
    BIG_rcopy(mod, CURVE_Order);

    // convert r to BIG
    BIG r;
    BIG_fromBytes(r, signature.first.val);

    // convert s to BIG
    BIG s;
    BIG_fromBytes(s, signature.second.val);

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

    // extract x coordinate of temp3 using ECP_get
    BIG r1, y_coord;
    ECP_get(r1, y_coord, &temp3);

    BIG_mod(r1, mod);

    // compare r and r1 in BIG
    if (BIG_comp(r, r1) != 0)
    {
        cout << "Signature not verified" << endl;
        return false;
    }
    else
    {
        cout << "Signature verified" << endl;
        return true;
    }
}
