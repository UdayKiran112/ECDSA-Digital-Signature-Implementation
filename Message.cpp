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
    delete[] message.val;
    delete[] Hashvalue.val;
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
    setHashvalue(Hashvalue);
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

bool Message::generateSignature(csprng *RNG, octet *privateKey, Message *msg)
{
    Key random = Key(RNG);
    pair<FP, FP> signature_temp;

    octet hashval = msg->getHashvalue();

    cout << "Hashvalue: ";
    OCT_output(&hashval);
    cout << endl;

    octet k = random.getPrivateKey();
    ECP R = random.getPublicKey();

    // Convert k to BIG
    BIG kval;
    BIG_fromBytes(kval, k.val);

    // Convert BIG value of k to FP
    FP k_fp;
    FP_nres(&k_fp, kval);

    // Extract x coordinate of R
    FP r = R.x;

    // Calculate Modular Inverse  of k
    FP k_inverse;
    FP_inv(&k_inverse, &k_fp, NULL);

    // Calculate signature s = (k^-1)∗(h+r∗privKey)(mod n)
    FP privKey, rval, h, temp1, temp2, rhs;
    octet_to_FP(&h, &hashval);         // h
    octet_to_FP(&privKey, privateKey); // privKey
    FP_mul(&temp1, &rval, &privKey);   // temp1 = r * privKey
    FP_add(&temp2, &h, &temp1);        // temp2 = h + r * privKey
    FP_mul(&rhs, &k_inverse, &temp2);  // rhs = (k^-1) * (h + r * privKey)(mod n)

    // Copy Signature values to signature_temp
    FP_copy(&signature_temp.first, &r);
    FP_copy(&signature_temp.second, &rhs);

    this->setSignature(signature_temp);
    return true;
}

bool Message::verifySignature(Message *msg, SECP256K1::ECP *publicKey)
{
    pair<FP, FP> signature = this->getSignature();
    SECP256K1::ECP G;
    Key::setGeneratorPoint(&G);

    ECP pubKey;
    ECP_copy(&pubKey, publicKey);

    octet hashval = msg->getHashvalue(); // h
    FP Hash;
    octet_to_FP(&Hash, &hashval); // convert h to FP

    FP s = signature.second; // s
    FP s_inverse;
    FP_inv(&s_inverse, &s, NULL); // s1

    // calculate R`= (h*s1) * G +(r * s1) * pubKey
    SECP256K1::ECP R;
    FP temp_1, temp_2;
    FP_mul(&temp_1, &Hash, &s_inverse);            // temp_1 = h * s1
    FP_mul(&temp_2, &signature.first, &s_inverse); // temp_2 = r * s1

    octet t1, t2;
    FP_to_octet(&t1, &temp_1); // convert temp_1 to octet
    FP_to_octet(&t2, &temp_2); // convert temp_2 to octet

    BIG r;
    BIG_rcopy(r, CURVE_Order);

    BIG t1n, t2n;
    BIG_fromBytes(t1n, t1.val);
    BIG_fromBytes(t2n, t2.val);

    ECP_clmul2(&G, &pubKey, t1n, t2n, r);

    FP r1 = G.x;
    if (FP_equals(&signature.first, &r1))
    {
        cout << "Signature Verified " << endl;
        return true;
    }
    else
    {
        cout << "Signature Not Verified " << endl;
        return false;
    }
    return false;
}

// Function to convert octet to FP type
void octet_to_FP(FP *fp, octet *octet)
{
    BIG b;
    BIG_fromBytes(b, octet->val);
    FP_nres(fp, b);
}

void FP_to_octet(octet *octet, FP *fp)
{
    BIG b;
    FP_redc(b, fp);
    BIG_toBytes(octet->val, b);
}