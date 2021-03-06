#pragma once
#include <map>

#include "dynprogram.h"



class CDynHash {

public:

    CDynHash();

    std::vector<CDynProgram*> programs;
    bool programLoaded;

    void load(std::string program);
    std::string calcBlockHeaderHash(uint32_t blockTime, unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot);
    void addProgram(uint32_t startTime, std::string strProgram);

};
