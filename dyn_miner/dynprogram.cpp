#include "dynprogram.h"


std::string CDynProgram::execute(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot) {

    //initial input is SHA256 of header data

    CSHA256 ctx;

    uint32_t iResult[8];

    ctx.Write(blockHeader, 80);
    ctx.Finalize((unsigned char*) iResult);


    int line_ptr = 0;       //program execution line pointer
    int loop_counter = 0;   //counter for loop execution
    unsigned int memory_size = 0;    //size of current memory pool
    uint32_t* memPool = NULL;     //memory pool

    while (line_ptr < program.size()) {
        std::istringstream iss(program[line_ptr]);
        std::vector<std::string> tokens{std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{}};     //split line into tokens

        //simple ADD and XOR functions with one constant argument
        if (tokens[0] == "ADD") {
            uint32_t arg1[8];
            parseHex(tokens[1], (unsigned char*) arg1);
            for (int i = 0; i < 8; i++)
                iResult[i] += arg1[i];
        }

        else if (tokens[0] == "XOR") {
            uint32_t arg1[8];
            parseHex(tokens[1], (unsigned char*)arg1);
            for (int i = 0; i < 8; i++)
                iResult[i] ^= arg1[i];
        }

        //hash algo which can be optionally repeated several times
        else if (tokens[0] == "SHA2") {
            if (tokens.size() == 2) { //includes a loop count
                loop_counter = atoi(tokens[1].c_str());
                for (int i = 0; i < loop_counter; i++) {
                    if (tokens[0] == "SHA2") {
                        unsigned char output[32];
                        ctx.Write((unsigned char*)iResult, 32);
                        ctx.Finalize(output);
                        memcpy(iResult, output, 32);
                    }
                }
            }

            else {                         //just a single run
                if (tokens[0] == "SHA2") {
                    unsigned char output[32];
                    ctx.Write((unsigned char*)iResult, 32);
                    ctx.Finalize(output);
                    memcpy(iResult, output, 32);
                }
            }
        }

        //generate a block of memory based on a hashing algo
        else if (tokens[0] == "MEMGEN") {
            if (memPool != NULL)
                free(memPool);
            memory_size = atoi(tokens[2].c_str());
            memPool = (uint32_t*)malloc(memory_size * 32);
            for (int i = 0; i < memory_size; i++) {
                if (tokens[1] == "SHA2") {
                    unsigned char output[32];
                    ctx.Write((unsigned char*)iResult, 32);
                    ctx.Finalize(output);
                    memcpy(iResult, output, 32);
                    memcpy(memPool + i * 8, iResult, 32);
                }
            }
        }

        //add a constant to every value in the memory block
        else if (tokens[0] == "MEMADD") {
            if (memPool != NULL) {
                uint32_t arg1[8];
                parseHex(tokens[1], (unsigned char*)arg1);

                for (int i = 0; i < memory_size; i++) {
                    for (int j = 0; j < 8; j++)
                        memPool[i * 8 + j] += arg1[j];
                }
            }
        }

        //xor a constant with every value in the memory block
        else if (tokens[0] == "MEMXOR") {
            if (memPool != NULL) {
                uint32_t arg1[8];
                parseHex(tokens[1], (unsigned char*)arg1);

                for (int i = 0; i < memory_size; i++) {
                    for (int j = 0; j < 8; j++)
                        memPool[i * 8 + j] ^= arg1[j];
                }
            }
        }

        //read a value based on an index into the generated block of memory
        else if (tokens[0] == "READMEM") {
            if (memPool != NULL) {
                unsigned int index = 0;

                if (tokens[1] == "MERKLE") {
                    uint32_t arg1[8];
                    parseHex(merkleRoot, (unsigned char*)arg1);
                    index = arg1[0] % memory_size;
                    memcpy(iResult, memPool + index * 8, 32);
                }

                else if (tokens[1] == "HASHPREV") {
                    uint32_t arg1[8];
                    parseHex(prevBlockHash, (unsigned char*)arg1);
                    index = arg1[0] % memory_size;
                    memcpy(iResult, memPool + index * 8, 32);
                }
            }
        }

        line_ptr++;


    }


    if (memPool != NULL)
        free(memPool);

    return makeHex((unsigned char*)iResult, 32);
}


std::string CDynProgram::getProgramString() {
    std::string result;

    for (int i = 0; i < program.size(); i++)
        result += program[i] + "\n";

    return result;
}


void CDynProgram::parseHex(std::string input, unsigned char* output) {

    for (int i = 0; i < input.length(); i += 2) {
        unsigned char value = decodeHex(input[i]) * 16 + decodeHex(input[i + 1]);
        output[i/2] = value;
    }
}

unsigned char CDynProgram::decodeHex(char in) {
    in = toupper(in);
    if ((in >= '0') && (in <= '9'))
        return in - '0';
    else if ((in >= 'A') && (in <= 'F'))
        return in - 'A' + 10;
    else
        return 0;       //todo raise error
}

std::string CDynProgram::makeHex(unsigned char* in, int len)
{
    std::string result;
    for (int i = 0; i < len; i++) {
        result += hexDigit[in[i] / 16];
        result += hexDigit[in[i] % 16];
    }
    return result;
}




std::string CDynProgram::executeGPU(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot) {




    //assmeble bytecode for program
    //allocate global memory buffer based on largest size of memgen
    //allocate result hash buffer for each compute unit
    //allocate flag to indicate hash found for each compute unit (this is for later)
    //call kernel code with program, block header, memory buffer, result buffer and flag as params


    uint32_t largestMemgen = 0;
    unsigned char* byteCode = executeGPUAssembleByteCode(&largestMemgen);





    //initial input is SHA256 of header data

    CSHA256 ctx;

    uint32_t iResult[8];

    ctx.Write(blockHeader, 80);
    ctx.Finalize((unsigned char*)iResult);






 

    return makeHex((unsigned char*)iResult, 32);
}




uint32_t* CDynProgram::executeGPUAssembleByteCode(uint32_t* largestMemgen, std::string prevBlockHash, std::string merkleRoot) {

    std::vector<uint32_t> code;



    int line_ptr = 0;       //program execution line pointer
    int loop_counter = 0;   //counter for loop execution
    unsigned int memory_size = 0;    //size of current memory pool
    uint32_t* memPool = NULL;     //memory pool

    while (line_ptr < program.size()) {
        std::istringstream iss(program[line_ptr]);
        std::vector<std::string> tokens{ std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{} };     //split line into tokens

        //simple ADD and XOR functions with one constant argument
        if (tokens[0] == "ADD") {
            uint32_t arg1[8];
            parseHex(tokens[1], (unsigned char*)arg1);
            code.push_back(HASHOP_ADD);
            for (int i = 0; i < 8; i++)
                code.push_back(arg1[i]);
        }

        else if (tokens[0] == "XOR") {
            uint32_t arg1[8];
            code.push_back(HASHOP_XOR);
            parseHex(tokens[1], (unsigned char*)arg1);
            for (int i = 0; i < 8; i++)
                code.push_back(arg1[i]);
        }

        //hash algo which can be optionally repeated several times
        else if (tokens[0] == "SHA2") {
            if (tokens.size() == 2) { //includes a loop count
                loop_counter = atoi(tokens[1].c_str());
                code.push_back(HASHOP_SHA_LOOP);
                code.push_back(loop_counter);
            }

            else {                         //just a single run
                if (tokens[0] == "SHA2") {
                    code.push_back(HASHOP_SHA_SINGLE);
                }
            }
        }

        //generate a block of memory based on a hashing algo
        else if (tokens[0] == "MEMGEN") {
            memory_size = atoi(tokens[2].c_str());
            code.push_back(HASHOP_MEMGEN);
            code.push_back(memory_size);
            if (memory_size > *largestMemgen)
                *largestMemgen = memory_size;
        }

        //add a constant to every value in the memory block
        else if (tokens[0] == "MEMADD") {
            code.push_back(HASHOP_MEMADD);
            uint32_t arg1[8];
            parseHex(tokens[1], (unsigned char*)arg1);
            for (int j = 0; j < 8; j++)
                code.push_back(arg1[j]);
        }

        //xor a constant with every value in the memory block
        else if (tokens[0] == "MEMXOR") {
            code.push_back(HASHOP_MEMXOR);
            uint32_t arg1[8];
            parseHex(tokens[1], (unsigned char*)arg1);
            for (int j = 0; j < 8; j++)
                code.push_back(arg1[j]);
        }

        //read a value based on an index into the generated block of memory
        else if (tokens[0] == "READMEM") {
            code.push_back(HASHOP_MEM_SELECT);
            if (tokens[1] == "MERKLE") {
                uint32_t arg1[8];
                parseHex(merkleRoot, (unsigned char*)arg1);
                code.push_back(arg1[0]);
            }

            else if (tokens[1] == "HASHPREV") {
                uint32_t arg1[8];
                parseHex(prevBlockHash, (unsigned char*)arg1);
                code.push_back(arg1[0]);
            }
        }

        line_ptr++;
    }


    uint32_t* result = (uint32_t)malloc(sizeof(uint32_t) * code.size());
    for (int i = 0; i < code.size(); i++)
        result[i] = code.at(i);

    return result;

}