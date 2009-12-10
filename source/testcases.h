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
 */

/**
 * Definition TestCase for Client URL Internet Emission Sniffer (Curlies)
 *
 * @author Shaopeng Jia (jia.shao.peng@gmail.com)
 * @author Erik van der Poel (erikvanderpoel@gmail.com)
 */
#ifndef TESTCASES_H_
#define TESTCASES_H_

enum TestType {
  kHost,
  kPath,
  kParameter,
  kQuery,
  kFormGet,
  kRelative,
};

enum Encoding {
  kAscii,
  kBig5,
  kEncodingSize,
};

struct TestCase {
  int test_id;
  TestType test_component;
  Encoding test_encoding;
  const char* test_string_for_display;
  const char* test_string;
  bool should_escape; // only in effect when test_string contains
                      // a single character
};

extern TestCase entries[];
extern int entries_size();

#endif  // TESTCASES_H_
