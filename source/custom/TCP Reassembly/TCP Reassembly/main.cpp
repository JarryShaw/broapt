//
//  main.cpp
//  TCP Reassembly
//
//  Created by Jarry Shaw on 03/24/2019.
//  Copyright © 2019 Jarry Shaw. All rights reserved.
//

#include <stdio.h>
#include <sstream>
#include <string>
#include <vector>

// buffer (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.TCP_Reassembly._buffer)

typedef struct {
    uint64_t first;
    uint64_t last;
} hole_t;

typedef struct {
    uint64_t isn;
    uint64_t len;
    std::string raw;
} part_t;

typedef std::vector<hole_t> hdl_t;

// utility functions (c.f. hexstr_to_bytestring in Bro, bytes.from_hex in Python)

unsigned char hexval(unsigned char c);
void hex2ascii(const std::string& in, std::string& out);

unsigned char hexval(unsigned char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else
        abort();
}

void hex2ascii(const std::string & in, std::string & out) {
    out.clear();
    out.reserve(in.length() / 2);
    for (std::string::const_iterator p = in.begin(); p != in.end(); p++) {
        unsigned char c = hexval(*p);
        p++;
        if (p == in.end())          // incomplete last digit - should report error
            break;
        c = (c << 4) + hexval(*p);  // + takes precedence over <<
        out.push_back(c);
    }
}

// TCP Reassembly algorithm (c.f. RFC791, RFC815)

void reassembly(uint64_t seq, uint64_t len, bool fin_rst, std::string payload);
void submit(const char * root);
void write_data(const char * root, std::string data, bool is_part, uint64_t start=0, uint64_t stop=UINT_MAX);

hdl_t HDL;
part_t BUF{};
bool FLAG = true;

#include <iostream>

void reassembly(uint64_t seq, uint64_t len, bool fin_rst, std::string PLD) {
    std::cout << "seq: " << seq << std::endl;
    std::cout << "len: " << len << std::endl;
    std::cout << "fin_rst: " << fin_rst << std::endl;
    std::cout << "----------" << std::endl;

    uint64_t DSN = seq;
    if (FLAG) {
        BUF.isn=DSN;
        BUF.raw=PLD;
        BUF.len=len;

        hole_t hole {len, UINT_MAX};
        HDL.push_back(hole);
        FLAG = false;
        return;
    }

    uint64_t LEN, SUM, GAP;
    uint64_t ISN = BUF.isn;
    std::string TMP;
    std::string RAW = BUF.raw;
    if (DSN > ISN) {
        LEN = BUF.len;
        SUM = ISN + LEN;
        if (DSN >= SUM) {
            GAP = DSN - SUM;
            TMP.resize(GAP, '\x00');
            RAW += TMP + PLD;
        } else {
            TMP.resize(0, DSN-ISN);
            RAW += TMP + PLD;
        }
    } else {
        LEN = len;
        SUM = DSN + LEN;
        if (ISN >= SUM) {
            GAP = ISN - SUM;
            TMP.resize(GAP, '\x00');
            RAW = PLD + TMP + RAW;
        } else
            RAW = PLD.substr(0, SUM) + RAW;
    }
    BUF.raw = RAW;
    BUF.len = (uint64_t) RAW.length();

    uint64_t first = seq;
    uint64_t last = first + len;
    for(hdl_t::iterator hole = HDL.begin(); hole != HDL.end(); ++hole) {
        if (first > hole->last)
            continue;
        if (last < hole->first)
            continue;
        HDL.erase(hole);
        if (first > hole->first) {
            hole_t new_hole {hole->first, first-1};
            HDL.insert(hole, new_hole);
        }
        if ((last < hole->last) && !fin_rst) {
            hole_t new_hole {last+1, hole->last};
            HDL.insert(hole, new_hole);
        }
        break;
    }
}

void submit(const char * root) {
    uint64_t start = 0;
    uint64_t stop = 0;
    std::string data;

    if (HDL.size() > 1) {
        for(hdl_t::iterator hole = HDL.begin(); hole != HDL.end(); ++hole) {
            stop = hole->first;
            data = BUF.raw.substr(start, stop-start);
            if (data.length())
                write_data(root, data, true, start, stop);
            start = hole->last;
        }
        data = BUF.raw.substr(start);
        if (data.length())
            write_data(root, data, true, start, (uint64_t) data.length());
    } else {
        data = BUF.raw;
        if (data.length())
            write_data(root, data, false);
    }
}

void write_data(const char * root, std::string data, bool is_part, uint64_t start, uint64_t stop) {
    char filename[strlen(root)*2];
    if (is_part)
        sprintf(filename, "%s_%llu-%llu.part", root, start, stop);
    else
        sprintf(filename, "%s.dat", root);

    FILE * fp = fopen(filename, "wb");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    fwrite(data.c_str(), sizeof(char), data.length(), fp);
    fclose(fp);
}

// entry point

#define ROOT "/Users/jarryshaw/Documents/GitHub/broapt/source/"

int main(int argc, const char * argv[]) {
//    const char * src = argv[1];
//    const char * dst = argv[2];
    const char * src = ROOT "logs/CGNKus3odD6nQQxll8_180.153.105.152:80-192.168.248.40:35623_589.log";
    const char * dst = ROOT "contents/CGNKus3odD6nQQxll8_180.153.105.152:80-192.168.248.40:35623_589";

    FILE * fp = fopen(src, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    float ts;
    uint64_t seq, len;
    char flag;
    bool fin_rst = false;
    std::string pld_hex, payload;

    char * line = NULL;
    size_t length = 0;
    while ((getline(&line, &length, fp)) != -1) {
        if ( line[0] == '#' ) {
            if ( strncmp(line, "#close", 6) == 0 )
                break;
            continue;
        }
        std::istringstream iss(line);
        iss >> ts >> seq >> len >> flag >> pld_hex;

        switch (flag) {
            case 'T':
                fin_rst = true;
                break;
            case 'F':
                fin_rst = false;
            default:
                break;          // invalid bool value - should report error
        }

        if (pld_hex != "(empty)")
            hex2ascii(pld_hex, payload);
        reassembly(seq, len, fin_rst, payload);
    }
    fclose(fp);
    submit(dst);

    return 0;
}
