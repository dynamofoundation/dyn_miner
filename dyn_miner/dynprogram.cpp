#include "dynprogram.h"


std::string CDynProgram::execute(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot) {

    //initial input is SHA256 of header data

    CSHA256 ctx;

    uint32_t iResult[8];

    /*
    uint32_t sum = 0;
    for (int i = 0; i < 80; i++)
        sum += blockHeader[i];
    printf("sum = %d\n", sum);
    */

    ctx.Write(blockHeader, 80);
    ctx.Finalize((unsigned char*) iResult);

    /*
    printf("first sha result  ");
    for (int i = 0; i < 8; i++)
        printf("%08x", iResult[i]);
    printf("\n\n");
    */

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
                        ctx.Reset();
                        ctx.Write((unsigned char*)iResult, 32);
                        ctx.Finalize(output);
                        memcpy(iResult, output, 32);
                    }
                }
            }

            else {                         //just a single run
                if (tokens[0] == "SHA2") {
                    unsigned char output[32];
                    ctx.Reset();
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
                    ctx.Reset();
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

        
        /*
        printf("%02d  ", line_ptr);
        for (int i = 0; i < 8; i++)
            printf("%08x", iResult[i]);
        printf("\n");
        */
        

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




std::string CDynProgram::executeGPU(unsigned char* blockHeader, std::string prevBlockHash, std::string merkleRoot, unsigned char* nativeTarget) {




    //assmeble bytecode for program
    //allocate global memory buffer based on largest size of memgen
    //allocate result hash buffer for each compute unit
    //allocate flag to indicate hash found for each compute unit (this is for later)
    //call kernel code with program, block header, memory buffer, result buffer and flag as params


    uint32_t largestMemgen = 0;
    uint32_t byteCodeLen = 0;
    uint32_t* byteCode = executeGPUAssembleByteCode(&largestMemgen, prevBlockHash, merkleRoot, &byteCodeLen);


    cl_int returnVal;
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_context context;

    //Initialize context
    returnVal = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    returnVal = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, &ret_num_devices);
    context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &returnVal);


    size_t sizeRet;
    cl_ulong globalMem;
    cl_ulong localMem;
    cl_uint computeUnits;
    size_t workGroups;
    cl_bool littleEndian;

    //Get some device capabilities
    returnVal = clGetDeviceInfo(device_id, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(globalMem), &globalMem, &sizeRet);
    returnVal = clGetDeviceInfo(device_id, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(localMem), &localMem, &sizeRet);
    returnVal = clGetDeviceInfo(device_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(computeUnits), &computeUnits, &sizeRet);
    returnVal = clGetDeviceInfo(device_id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(workGroups), &workGroups, &sizeRet);
    returnVal = clGetDeviceInfo(device_id, CL_DEVICE_ENDIAN_LITTLE, sizeof(littleEndian), &littleEndian, &sizeRet);
    

    computeUnits = 1000;

    //Read the kernel source
    FILE* kernelSourceFile;

    kernelSourceFile = fopen("C:\\Users\\user\\source\\repos\\dyn_miner\\dyn_miner\\dyn_miner.cl", "r");
    if (!kernelSourceFile) {
        fprintf(stderr, "Failed to load kernel.\n");
        return "";
    }
    fseek(kernelSourceFile, 0, SEEK_END);
    size_t sourceFileLen = ftell(kernelSourceFile)+1;
    char *kernelSource = (char*)malloc(sourceFileLen);
    memset(kernelSource, 0, sourceFileLen);
    fseek(kernelSourceFile, 0, SEEK_SET);
    fread(kernelSource, 1, sourceFileLen, kernelSourceFile);
    fclose(kernelSourceFile);


    cl_program program;
    cl_kernel kernel;
    cl_command_queue command_queue;

    //Create kernel program
    program = clCreateProgramWithSource(context, 1, (const char**)&kernelSource, (const size_t*)&sourceFileLen, &returnVal);
    returnVal = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);

    if (returnVal == CL_BUILD_PROGRAM_FAILURE) {
        // Determine the size of the log
        size_t log_size;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);

        // Allocate memory for the log
        char* log = (char*)malloc(log_size);

        // Get the log
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);

        // Print the log
        printf("\n\n%s\n", log);
    }

    kernel = clCreateKernel(program, "dyn_hash", &returnVal);
    command_queue = clCreateCommandQueueWithProperties(context, device_id, NULL, &returnVal);


    //Calculate buffer sizes - mempool, hash result buffer, done flag
    uint32_t memgenBytes = largestMemgen * 32;
    uint32_t globalMempoolSize = memgenBytes * computeUnits;
    //TODO - make sure this is less than globalMem




    //Allocate program source buffer and load
    cl_mem clGPUProgramBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, byteCodeLen, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 0, sizeof(clGPUProgramBuffer), (void*)&clGPUProgramBuffer);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUProgramBuffer, CL_TRUE, 0, byteCodeLen, byteCode, 0, NULL, NULL);


    //Allocate global memory buffer and zero
    cl_mem clGPUMemGenBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, globalMempoolSize, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 1, sizeof(clGPUMemGenBuffer), (void*)&clGPUMemGenBuffer);
    unsigned char* buffMemGen = (unsigned char*)malloc(globalMempoolSize);
    memset(buffMemGen, 0, globalMempoolSize);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUMemGenBuffer, CL_TRUE, 0, globalMempoolSize, buffMemGen, 0, NULL, NULL);


    //Size of memgen area - this is the number of 8 uint blocks
    returnVal = clSetKernelArg(kernel, 2, sizeof(largestMemgen), (void*)&largestMemgen);


    //Allocate hash result buffer and zero
    uint32_t hashResultSize = computeUnits * 32;
    cl_mem clGPUHashResultBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, hashResultSize, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 3, sizeof(clGPUHashResultBuffer), (void*)&clGPUHashResultBuffer);
    uint32_t* buffHashResult = (uint32_t*)malloc(hashResultSize);
    memset(buffHashResult, 0, hashResultSize);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUHashResultBuffer, CL_TRUE, 0, hashResultSize, buffHashResult, 0, NULL, NULL);


    //Allocate found flag buffer and zero
    uint32_t doneFlagSize = computeUnits;
    cl_mem clGPUDoneBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, doneFlagSize, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 4, sizeof(clGPUDoneBuffer), (void*)&clGPUDoneBuffer);
    unsigned char* buffDoneFlag = (unsigned char*)malloc(doneFlagSize);
    memset(buffDoneFlag, 0, doneFlagSize);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUDoneBuffer, CL_TRUE, 0, doneFlagSize, buffDoneFlag, 0, NULL, NULL);


    //Allocate header buffer and load
    uint32_t headerBuffSize = computeUnits * 80;
    cl_mem clGPUHeaderBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, headerBuffSize, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 5, sizeof(clGPUHeaderBuffer), (void*)&clGPUHeaderBuffer);
    unsigned char* buffHeader = (unsigned char*)malloc(headerBuffSize);
    memset(buffHeader, 0, headerBuffSize);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUHeaderBuffer, CL_TRUE, 0, headerBuffSize, buffHeader, 0, NULL, NULL);


    //Allocate SHA256 scratch buffer - this probably isnt needed if properly optimized
    uint32_t scratchBuffSize = computeUnits * 32;
    cl_mem clGPUScratchBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, scratchBuffSize, NULL, &returnVal);
    returnVal = clSetKernelArg(kernel, 6, sizeof(clGPUScratchBuffer), (void*)&clGPUScratchBuffer);
    unsigned char* buffScratch = (unsigned char*)malloc(scratchBuffSize);
    memset(buffScratch, 0, scratchBuffSize);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUScratchBuffer, CL_TRUE, 0, scratchBuffSize, buffScratch, 0, NULL, NULL);



    /////////////////////////////////////////////////


    for (int i = 0; i < computeUnits; i++)
        memset(buffMemGen + i * memgenBytes, i, 32);
    returnVal = clEnqueueWriteBuffer(command_queue, clGPUMemGenBuffer, CL_TRUE, 0, globalMempoolSize, buffMemGen, 0, NULL, NULL);


    
    time_t start;
    time(&start);
    
    for (int nonce = 0; nonce < 1000000; nonce += computeUnits) {

        for (int i = 0; i < computeUnits; i++)
            memcpy(buffHeader + (i * 80), blockHeader, 80);

        for (int i = 0; i < computeUnits; i++)
            memcpy(buffHeader + (i * 80) + 76, &i, 4);

        returnVal = clEnqueueWriteBuffer(command_queue, clGPUHeaderBuffer, CL_TRUE, 0, headerBuffSize, buffHeader, 0, NULL, NULL);

        //size_t globalWorkSize = 1;
        size_t globalWorkSize = computeUnits;
        size_t localWorkSize = 1;
        returnVal = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &globalWorkSize, &localWorkSize, 0, NULL, NULL);
        returnVal = clFinish(command_queue);

        returnVal = clEnqueueReadBuffer(command_queue, clGPUHashResultBuffer, CL_TRUE, 0, hashResultSize, buffHashResult, 0, NULL, NULL);

        //if (nonce % (computeUnits * 10) == 0) {
            time_t current;
            time(&current);
            long long diff = current - start;
            printf("%d %lld %6.2f\n", nonce, diff, (float)nonce/float(diff));
        //}

    }
    /*
    for (int i = 0; i < computeUnits; i++) {
        printf("%02d  ", i);
        for (int j = 0; j < 8; j++)
            printf("%08x", buffHashResult[i * 8 + j]);
        printf("\n");
    }
    */

    return makeHex((unsigned char*)0, 32);
}




uint32_t* CDynProgram::executeGPUAssembleByteCode(uint32_t* largestMemgen, std::string prevBlockHash, std::string merkleRoot, uint32_t* byteCodeLen) {

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

    code.push_back(HASHOP_END);

    uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * code.size());
    for (int i = 0; i < code.size(); i++)
        result[i] = code.at(i);

    *byteCodeLen = code.size() * 4;

    return result;

}