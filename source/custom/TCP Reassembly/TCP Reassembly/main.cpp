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
    uint first;
    uint last;
} hole_t;

typedef struct {
    uint isn;
    uint len;
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

void reassembly(float ts, uint seq, uint len, bool fin_rst, std::string payload);
void submit(const char * root);
void write_data(const char * root, std::string data, bool is_part, uint start=0, uint stop=UINT_MAX);

hdl_t HDL;
part_t BUF{};
bool FLAG = true;

void reassembly(float ts, uint seq, uint len, bool fin_rst, std::string payload) {
    uint DSN = seq;
    std::string PLD = payload;

    if (FLAG) {
        BUF.isn=DSN;
        BUF.raw=PLD;
        BUF.len=len;

        hole_t hole {len, UINT_MAX};
        HDL.push_back(hole);
        FLAG = false;
        return;
    }

    uint LEN, SUM, GAP;
    uint ISN = BUF.isn;
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
        if (ISN>=DSN) {
            GAP = ISN - SUM;
            RAW = PLD + TMP.substr(0, '\x00') + RAW;
        } else
            RAW = PLD.substr(0, SUM) + RAW;
    }
    TMP.clear();
    BUF.raw = RAW;
    BUF.len = (uint) RAW.length();

    uint first = seq;
    uint last = first + len;
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
            HDL.insert(hole+1, new_hole);
        }
        break;
    }
}

void submit(const char * root) {
    uint start = 0;
    uint stop = 0;
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
            write_data(root, data, true, start, (uint) data.length());
    } else {
        data = BUF.raw;
        if (data.length())
            write_data(root, data, false);
    }
}

void write_data(const char * root, std::string data, bool is_part, uint start, uint stop) {
    char filename[strlen(root)*2];
    if (is_part)
        sprintf(filename, "%s_%u-%u.part", root, start, stop);
    else
        sprintf(filename, "%s.dat", root);

    FILE * fp = fopen(filename, "wb");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    fwrite(data.c_str(), sizeof(char), data.length(), fp);
    fclose(fp);
}

// entry point

int main(int argc, const char * argv[]) {
    const char * src = argv[1];
    const char * dst = argv[2];

    FILE * fp = fopen(src, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    float ts;
    uint seq, len;
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

        hex2ascii(pld_hex, payload);
        reassembly(ts, seq, len, fin_rst, payload);
    }
    fclose(fp);
    submit(dst);

    if (line)
        free(line);
    return 0;
}
