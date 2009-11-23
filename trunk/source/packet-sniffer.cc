/**
 * Copyright 2009 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Shaopeng Jia (jia.shao.peng@gmail.com)
 */

#include <ctype.h>
#include <pcap.h>
#include <string.h>

#include <iostream>
#include <string>
#include <vector>

#include "packet-sniffer.h"

using namespace std;

const char* memstr(const char* ptr, int length, const char* str) {
  int str_length = strlen(str);
  while (length >= str_length) {
    const char* pos = (char*)memchr(ptr, str[0], length);
    if (pos == NULL) return NULL;
    if (memcmp(pos, str, str_length) == 0) return pos;
    length = length - (pos - ptr) - 1;
    ptr = pos + 1;
  }
  return NULL;
}

void ExtractResultsFromCapFile(const char* filename,
                               const string& packet_type,
                               vector<string>* results
                               ) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle;                  // Session handle
  struct bpf_program fp;           // Compiled filter expression
  const unsigned char* packet = NULL;
  struct pcap_pkthdr pkthdr;

  string filter_exp = "";
  if (packet_type.compare("dns") == 0) {
    filter_exp += "(udp dst port 53)";
  } else {
    /*
     * ip[2:2] - Total length of the datagram of the IP package in bytes
     * (ip[0]&0xf)<<2 - Length of the IP packet header in bytes
     * (tcp[12]&0xf0)>>2 - Length of TCP header in bytes
     */
    filter_exp +=
           "(tcp dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - "
           "((tcp[12]&0xf0)>>2)) != 0))";
  }
  handle = pcap_open_offline(filename, errbuf);
  if (handle == NULL) {
    cerr << "Couldn't open file" << filename << ": " << errbuf << "\n";
  }

  if (pcap_compile(handle, &fp, const_cast<char*>(filter_exp.c_str()), 0, 0)
      == -1) {
    cerr << "Couldn't parse filter " << filter_exp << ": "
         << pcap_geterr(handle) << "\n";
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    cerr << "Couldn't install filter " << filter_exp << ": "
         << pcap_geterr(handle) << "\n";
  }

  packet = pcap_next(handle, &pkthdr);
  const vector<string>::iterator results_begin = results->begin();
  while (packet) {
    const char* packet_end = (const char*)packet + pkthdr.len;
    bpf_u_int32 pkt_length_remaining = pkthdr.len;
    const char* temp = memstr((const char*) packet,
                              pkt_length_remaining, "9pz");
    if (temp) {
      const char* start_intended = temp + 3;
      pkt_length_remaining = packet_end - start_intended + 1;
      const char* end_intended = memstr(start_intended,
                                        pkt_length_remaining, "9pz");
      int length_intended = end_intended - start_intended;
      string test_id(start_intended, length_intended);
      int index;
      index = atoi(test_id.c_str());
      if ((*(results_begin + index)).compare("not sent") == 0) {
        pkt_length_remaining = packet_end - end_intended - 3 + 1;
        const char* start_actual =
            memstr(end_intended + 3, pkt_length_remaining, "9qz") + 3;
        pkt_length_remaining = packet_end - start_actual + 1;
        const char* end_actual = memstr(start_actual, pkt_length_remaining,
                                        "9qz");
        if (end_actual) {
          int length_actual = end_actual - start_actual;
          if (length_actual == 0) {
            *(results_begin + index) = "deleted";
          } else {
           // For non-Ascii host testcases, the test string is always
           // surrounded by two periods.
           if ((*(end_actual - 1) == '\x03' || *(end_actual - 1) == '.') &&
               length_actual > 1) {
              start_actual++;
              length_actual -= 2;
           }
           string test_str(start_actual, length_actual);
           if (length_actual > 1) {
             test_str = "";
             for (int pos = 0; pos < length_actual; pos++) {
               const char ch = *(start_actual + pos);
               if (isprint(ch)) {
                 test_str.push_back(ch);
               } else if (ch < '\x20') {
                 test_str.push_back('.');
               } else {
                 char temp[10];
                 snprintf(temp, 10, "\\x%02X", ch);
                 test_str.append(temp);
               }
             }
           }
           *(results_begin + index) = test_str;
          }
        } else {
          *(results_begin + index) = "terminator";
        }
      }
    }
    packet = pcap_next(handle, &pkthdr);
  }
}
