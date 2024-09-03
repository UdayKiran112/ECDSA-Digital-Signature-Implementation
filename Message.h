#pragma once

#include <bits/stdc++.h>
#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <chrono>
#include "Lib/core.h"
#include "Lib/eddsa_SECP256K1.h"
#include "Lib/config_big_B256_56.h"
using namespace std;

// using namespace std;
using namespace std;

class Message{
    private:
        core::octet message;
        // core::octet hashMsg; //64 bitss less than multiple of 512 bits
        core::octet Hashvalue;
    public:
        Message();
        ~Message();
        Message(string message, chrono::system_clock::time_point Timestamp, core::octet B);
        core::octet getMessage();
        core::octet getTimestamp();
        core::octet getFinalMsg();
        void setMessage(core::octet message);
        void setTimestamp(core::octet Timestamp);
        // void setHashMsg(core::octet hashMsg);
        void setFinalMsg(core::octet finalMsg);

        static void Concatenate_octet(octet *data1, octet *data2, octet *result);
        static void Hash_Function(octet *input, octet *output, int pad);
        static void add_octets(octet *data1, octet *data2, octet *result);
        static void multiply_octet(octet *data1, octet *data2, octet *result);
};

#endif // MESSAGE_H