#include <bits/stdc++.h>
#include "Key.h"
#include "Message.h"

using namespace std;
using namespace B256_56;
using namespace SECP256K1;

int main()
{
    // Initialize random seed using a combination of time and random_device for better entropy
    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;

    // Improve seed generation by combining time and random_device
    std::random_device rd;
    ran = static_cast<unsigned long>(time(nullptr)) ^ rd();

    // Populate RAW with random data
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;

    // Fill the rest of RAW with high-entropy data
    for (int i = 4; i < 100; i++)
    {
        RAW.val[i] = rd() & 0xFF; // Use random_device to fill the remaining bytes
    }

    // Initialize CSPRNG
    core::CREATE_CSPRNG(&RNG, &RAW);

    Key key(&RNG);

    // Initialize Message
    string message ="Hello World!";
    cout << message << endl;
    Message msg(message);
    octet Hashvalue = msg.getHashvalue();
    octet Messageval = msg.getMessage();

    cout << "Message: ";
    OCT_output(&Messageval);
    cout << endl;

    cout << "Hashvalue: ";
    OCT_output(&Hashvalue);
    cout << endl;

    // Clean up the CSPRNG
    core::KILL_CSPRNG(&RNG);

    return 0;
}
