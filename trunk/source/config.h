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
 * Configuration file for Client URL Internet Emission Sniffer (Curlies)
 *
 * @author Shaopeng Jia (jia.shao.peng@gmail.com)
 * @author Erik van der Poel (erikvanderpoel@gmail.com)
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <string>

const std::string kWildcardDomain("wildcard.invalid");
const std::string kNoContentDomain("http204.invalid");
// By default, results are generated according to the ascending order of
// the id of each test case during report generation. This field overrides
// the default behavior by providing the sequence of ranges of ids of test
// cases that should be generated. Within a range, results are generated
// according to the ascending order of the id.
const int kEntrySequenceInReport[][2] = {
    {128, 255},
    {0, 127},
    {384, 511},
    {256, 383},
    {640, 767},
    {512, 639},
    {896, 1023},
    {768, 895},
    {1024, 1052},
    {1181, 1308},
    {1053, 1180},
    {1309, 1311},
    {1312, 1353},
};

#endif /* CONFIG_H_ */
