// MIT License
//
// Copyright (c) 2023 Ferhat Geçdoğan All Rights Reserved.
// Distributed under the terms of the MIT License.
//

#pragma once

#include <openssl/whrlpool.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <string>

#include "fasht.hpp"

#define FUNCTION_DEFINE(name) bool enable_##name = true; void name() noexcept;

class checks {
public:
    std::string file_data;
    const char* file_data_c_str;
    std::size_t file_data_size;
    
    FUNCTION_DEFINE(sha1)
    FUNCTION_DEFINE(sha224)
    FUNCTION_DEFINE(sha384)
    FUNCTION_DEFINE(sha256)
    FUNCTION_DEFINE(sha512)

    FUNCTION_DEFINE(md4)
    FUNCTION_DEFINE(md5)

    FUNCTION_DEFINE(fasht)
    FUNCTION_DEFINE(whirlpool)
};