// MIT License
//
// Copyright (c) 2023 Ferhat Geçdoğan All Rights Reserved.
// Distributed under the terms of the MIT License.
//

#include "../include/checks.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>

void checks::sha1() noexcept {
    if(!this->enable_sha1) return;

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, this->file_data_c_str, this->file_data_size);
    SHA1_Final(hash, &sha1);
    std::stringstream val;
    
    for(unsigned i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "SHA1  : " << val.str() << '\n';
}

void checks::sha224() noexcept {
    if(!this->enable_sha224) return;

    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA256_CTX sha224;
    SHA224_Init(&sha224);
    SHA224_Update(&sha224, this->file_data_c_str, this->file_data_size);
    SHA224_Final(hash, &sha224);
    std::stringstream val;
    
    for(unsigned i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "SHA224: " << val.str() << '\n';
}

void checks::sha256() noexcept {
    if(!this->enable_sha256) return;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, this->file_data_c_str, this->file_data_size);
    SHA256_Final(hash, &sha256);
    std::stringstream val;
    
    for(unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "SHA256: " << val.str() << '\n';
}


void checks::sha384() noexcept {
    if(!this->enable_sha384) return;

    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, this->file_data_c_str, this->file_data_size);
    SHA384_Final(hash, &sha384);
    std::stringstream val;
    
    for(unsigned i = 0; i < SHA384_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "SHA384: " << val.str() << '\n';
}

void checks::sha512() noexcept {
    if(!this->enable_sha512) return;

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, this->file_data_c_str, this->file_data_size);
    SHA512_Final(hash, &sha512);
    std::stringstream val;
    
    for(unsigned i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "SHA512: " << val.str() << '\n';
}

void checks::md4() noexcept {
    if(!this->enable_md4) return;

    unsigned char hash[MD4_DIGEST_LENGTH];
    MD4_CTX md4;
    MD4_Init(&md4);
    MD4_Update(&md4, this->file_data_c_str, this->file_data_size);
    MD4_Final(hash, &md4);
    std::stringstream val;

    for(unsigned i = 0; i < MD4_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "MD4   : " << val.str() << '\n';
}

void checks::md5() noexcept {
    if(!this->enable_md5) return;

    unsigned char hash[MD4_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, this->file_data_c_str, this->file_data_size);
    MD5_Final(hash, &md5);
    std::stringstream val;

    for(unsigned i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "MD5   : " << val.str() << '\n';
}

void checks::fasht() noexcept {
    if(!this->enable_fasht) return;

    std::cout << "fasht : " << fasht::h(this->file_data) << '\n';
}

void checks::whirlpool() noexcept {
    if(!this->enable_whirlpool) return;

    unsigned char hash[WHIRLPOOL_DIGEST_LENGTH];
    WHIRLPOOL_CTX wp;
    WHIRLPOOL_Init(&wp);
    WHIRLPOOL_Update(&wp, this->file_data_c_str, this->file_data_size);
    WHIRLPOOL_Final(hash, &wp);
    std::stringstream val;

    for(unsigned i = 0; i < WHIRLPOOL_DIGEST_LENGTH; ++i) {
        val << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::cout << "WHLPL : " << val.str() << '\n';
}

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cout << argv[0] << " -{args} {file}\n" <<
            "\n" <<
            "-{args}: disable calculating sum for {args}\n"
            " q: sha1 | w: sha224 | e: sha256 | r: sha384 | t: sha512\n" <<
            " a: md4 | s: md5\n" <<
            " z: fasht | x: whirlpool\n";
        
        return 1;
    }

    bool argument_found = false;
    checks val;

    for(unsigned i = 1; i < argc; ++i) {
        if(std::strlen(argv[i]) > 0 && argv[i][0] == '-') {
            argument_found = true;
            
            for(unsigned l = 1; l < std::strlen(argv[i]); ++l) {
                switch(argv[i][l]) {
                    case 'q': {
                        val.enable_sha1 = false;
                        break;
                    }

                    case 'w': {
                        val.enable_sha224 = false;
                        break;
                    }

                    case 'e': {
                        val.enable_sha256 = false;
                        break;
                    }

                    case 'r': {
                        val.enable_sha384 = false;
                        break;
                    }

                    case 't': {
                        val.enable_sha512 = false;
                        break;
                    }

                    case 'a': {
                        val.enable_md4 = false;
                        break;
                    }

                    case 's': {
                        val.enable_md5 = false;
                        break;
                    }

                    case 'z': {
                        val.enable_fasht = false;
                        break;
                    }

                    case 'x': {
                        val.enable_whirlpool = false;
                        break;
                    }

                    default: {
                        std::cout << "undefined argument (" << argv[i][l] << ")\n";
                        break; 
                    }
                }
            }    
        } 
    }
    
    if(argument_found && argc < 3) {
        std::cout << "file argument does not found around the arguments\n";
        return 1;
    }

    unsigned n = 1;

    while(n + 1 < argc) {
        std::cout << ((argument_found) ? (argv[n + 1]) : (argv[n])) << '\n';

        if(!std::filesystem::exists((argument_found) ? (argv[n + 1]) : (argv[n]))) {
            ++n;
            continue;
        }

        std::ifstream file_stream((argument_found) ? (argv[n + 1]) : (argv[n]));
        std::string file_data;

        for(std::string line; std::getline(file_stream, line);
            file_data.append(line + "\n"));

        file_data.pop_back();
        file_stream.close();
    
        val.file_data = file_data;
        val.file_data_c_str = file_data.c_str();
        val.file_data_size = file_data.size();
    
        val.sha1();
        val.sha224();
        val.sha256();
        val.sha384();
        val.sha512();
    
        val.md4();
        val.md5();

        val.fasht();
        val.whirlpool();

        ++n;
    }
}