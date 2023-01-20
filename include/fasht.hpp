// MIT License
//
// Copyright (c) 2021 Ferhat Geçdoğan All Rights Reserved.
// Distributed under the terms of the MIT License.
//
// fasht - main implementation of fasht (library)
//
// fas(h)t is (trash) hash algorithm for non-cryptographic uses.
// designed & implemented for gretea language.
//
// github.com/ferhatgec/fasht
// github.com/ferhatgec/fasht.py

#ifndef FASHT_FASHT_HPP
#define FASHT_FASHT_HPP

#include <vector>
#include <string>
#include <sstream>

namespace fasht {
    static std::vector<unsigned> rounds {
        0x2, 0x5, 0x7d5, 0x7e5
    };

    template<typename Val>
    static std::string hex(Val data) noexcept {
        std::stringstream stream; stream << std::hex << data;
        return stream.str();
    }

    static std::string h(std::string data) noexcept {
        std::vector<unsigned> table;
        std::string result;

        for(auto& round : rounds) {
            for(auto& ch : data) {
                table.push_back((ch << 2) ^ round);
            }
        }

        for(auto& arg : table) {
            result.push_back(hex(arg >> 2).back());
        }

        if(result.length() > 32) {
            result = result.substr(0, 32);
        } else {
            fasht::h(result);
        }

        return result;
    }

    static unsigned long long hb(std::string data) noexcept {
        return std::strtoull(fasht::h(data).c_str(), 0, 16);
    }
}

#endif // FASHT_FASHT_HPP
