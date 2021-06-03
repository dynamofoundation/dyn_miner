#pragma once
#include <vector>
#include <string>
#include "common.h"
#include "sha256.h"
#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <CL/cl_platform.h>
#include <CL/cl.h>




#define HASHOP_ADD 0
#define HASHOP_XOR 1
#define HASHOP_SHA_SINGLE 2
#define HASHOP_SHA_LOOP 3
#define HASHOP_MEMGEN 4
#define HASHOP_MEMADD 5
#define HASHOP_MEMXOR 6
#define HASHOP_MEM_SELECT 7
#define HASHOP_END 8


class CDynProgram {

public:
    int32_t startingTime;
    std::vector<std::string> program;

    const std::vector<char> hexDigit = {'0', '1', '2', '3', '4','5','6','7','8','9','A','B','C','D','E','F'};

    std::string execute(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot);


    int executeGPU(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot, unsigned char* nativeTarget, uint32_t *resultNonce);
        
    uint32_t* executeGPUAssembleByteCode(uint32_t* largestMemgen, std::string prevBlockHash, std::string merkleRoot, uint32_t* byteCodeLen);

    std::string getProgramString();
    void parseHex(std::string input, unsigned char* output);
    unsigned char decodeHex(char in);
    std::string makeHex(unsigned char* in, int len);
};
