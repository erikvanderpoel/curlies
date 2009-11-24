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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "boost/regex.hpp"
#include "config.h"
#include "packet-sniffer.h"
#include "testcases.h"

using namespace std;

static void WriteFileHeader(FILE* output_file,
                            const vector<string>& platform_browser_under_test,
                            const bool isAscii) {
  fprintf(output_file,
      "<!-- Copyright 2009 Google Inc.\n\n"
      "Licensed under the Apache License, Version 2.0 (the \"License\");\n"
      "you may not use this file except in compliance with the License.\n"
      "You may obtain a copy of the License at\n\n"
      "     http://www.apache.org/licenses/LICENSE-2.0\n\n"
      "Unless required by applicable law or agreed to in writing, software\n"
      "distributed under the License is distributed on an \"AS IS\" BASIS,\n"
      "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
      "See the License for the specific language governing permissions and\n"
      "limitations under the License.\n\n"
      "Author: Shaopeng Jia (jia.shao.peng@gmail.com)\n"
      "Author: Erik van der Poel (erikvanderpoel@gmail.com)\n\n"
      "Note: This file is automatically generated by\n"
      "../source/report-generator.cc. If you want to add additional\n"
      "tests, please add it in the ../source/testcases.cc, or contact the authors."
      "\n-->\n\n"
      "<html>\n<head>\n<meta http-equiv=\"Content-Type\""
      "content=\"text/html; charset=US-ASCII\">\n</head>\n<body>\n"
	  "<h4>Legend</h4>\n"
	  "<table>\n"
      "<tr><td>\\xXX<td>= a single byte with that hex encoding\n"
      "<tr><td>%%XX<td>= three bytes (%%, X and X)\n"
      "<tr><td>not send<td>= no DNS/HTTP packet was sent\n"
      "<tr><td>deleted<td>= byte was deleted before packet was sent\n"
      "<tr><td>terminator<td>= this character was treated as a delimiter\n"
      "<tr><td>dot<td>= this was treated like the dot in domain names\n"
      "</table><br>\n");
  fprintf(output_file, "<table border=\"1\">\n");
  fprintf(output_file, "<tr><td>Test</td>");
  if (isAscii) {
    fprintf(output_file, "<td>Char</td>");
  }
  for (vector<string>::const_iterator it = platform_browser_under_test.begin();
       it != platform_browser_under_test.end(); it++) {
    fprintf(output_file, "<td>%s</td>", (*it).c_str());
  }
  fprintf(output_file, "</tr>\n");
}

static void WriteFileFooter(FILE* output_file) {
  fprintf(output_file, "</table>\n");
  fprintf(output_file, "</body>\n");
  fprintf(output_file, "</html>\n");
  fclose(output_file);
}

static void AppendResultToReport(
    const TestCase& test_case,
    const bool isAscii,
    const vector<vector<string> >& results,
    FILE* output_file) {
  const char* display_string = test_case.test_string_for_display;
  // Display results of test if it has not been removed
  if (strlen(display_string) > 0) {
    ostringstream oss;
    oss << "<td>" << display_string << "</td>";
    string row_result = oss.str();
    const char* test_string = test_case.test_string;
    char buffer[100];
    if (isAscii) {
      int b = *test_string;
      if (isprint(b) && b != ' ') {
        snprintf(buffer, 100, "<td>%c</td>", b);
        row_result.append(buffer);
      } else {
        snprintf(buffer, 100, "<td>\\x%02X</td>", b);
        row_result.append(buffer);
      }
    }
    bool same_across_cells = true; // True if each cell in this row
                                   // contains the same data
    string last_string_result;
    for (vector<vector<string> >::const_iterator it = results.begin();
         it != results.end(); it++) {
      string result_string = (*it)[test_case.test_id];
      if (same_across_cells && !last_string_result.empty() &&
          result_string.compare(last_string_result) != 0) {
        same_across_cells = false;
      }
      if (result_string.size() == 1 &&
          (!isprint(result_string[0]) || result_string[0] == ' ')) {
        if (isAscii && *test_string == '.' && result_string[0] == '\x03') {
          snprintf(buffer, 100, "<td>%s</td>", "dot");
          row_result.append(buffer);
        } else {
          snprintf(buffer, 100, "<td>\\x%02X</td>", (int)(result_string[0]));
          row_result.append(buffer);
        }
      } else {
        snprintf(buffer, 100, "<td>%s</td>", result_string.c_str());
        row_result.append(buffer);
      }
      last_string_result = result_string;
    }
    string row_color = " bgcolor='#FFFF00'";
    if (same_across_cells) {
      row_color = "";
    }
    fprintf(output_file, "<tr%s>%s</tr>\n", row_color.c_str(),
            row_result.c_str());
  }
}

static FILE* OpenFile(string path, const char* filename) {
  string full_path = path + filename;
  return fopen(full_path.c_str(), "w");
}

int main(int argc, char* argv[]) {
  vector<char*> input_cap_files;
  string output_path(argv[1]);
  for (int i = 2; i < argc; i++) {
    input_cap_files.push_back(argv[i]);
  }
  vector<string> platform_browser_under_test;
  vector<vector<string> > test_results_dns, test_results_http;
  int total_num_of_test = entries_size();

  // Collect results for each browser/platform being tested
  for (vector<char*>::const_iterator it = input_cap_files.begin();
       it != input_cap_files.end(); it++) {
    const boost::regex e("/([^/]+/[^/]+)\\.p?cap");
    boost::match_results<string::const_iterator> what;
    assert(boost::regex_search(string(*it), what, e, boost::match_default));
    string match(what[1].first, what[1].second);
    replace(match.begin(), match.end(), '_', '.');
    platform_browser_under_test.push_back(match);
    vector<string> dns_results(total_num_of_test, "not sent");
    vector<string> http_results(total_num_of_test, "not sent");
    ExtractResultsFromCapFile(*it, "dns", &dns_results);
    ExtractResultsFromCapFile(*it, "http", &http_results);
    test_results_dns.push_back(dns_results);
    test_results_http.push_back(http_results);
  }

  // Generate reports
  FILE* host_ascii_dns_results = OpenFile(output_path, "host_ascii_dns_results.html");
  FILE* host_ascii_http_results = OpenFile(output_path, "host_ascii_http_results.html");
  FILE* path_ascii_results = OpenFile(output_path, "path_ascii_results.html");
  FILE* parameter_ascii_results = OpenFile(output_path, "parameter_ascii_results.html");
  FILE* query_ascii_results = OpenFile(output_path, "query_ascii_results.html");
  FILE* form_get_ascii_results = OpenFile(output_path, "form_get_ascii_results.html");
  FILE* host_big5_dns_results = OpenFile(output_path, "host_big5_dns_results.html");
  FILE* host_big5_http_results = OpenFile(output_path, "host_big5_http_results.html");
  FILE* path_big5_results = OpenFile(output_path, "path_big5_results.html");
  FILE* parameter_big5_results = OpenFile(output_path, "parameter_big5_results.html");
  FILE* query_big5_results = OpenFile(output_path, "query_big5_results.html");
  FILE* form_get_big5_results = OpenFile(output_path, "form_get_big5_results.html");

  WriteFileHeader(host_ascii_dns_results, platform_browser_under_test, true);
  WriteFileHeader(host_ascii_http_results, platform_browser_under_test, true);
  WriteFileHeader(path_ascii_results, platform_browser_under_test, true);
  WriteFileHeader(parameter_ascii_results, platform_browser_under_test, true);
  WriteFileHeader(query_ascii_results, platform_browser_under_test, true);
  WriteFileHeader(form_get_ascii_results, platform_browser_under_test, true);
  WriteFileHeader(host_big5_dns_results, platform_browser_under_test, false);
  WriteFileHeader(host_big5_http_results, platform_browser_under_test, false);
  WriteFileHeader(path_big5_results, platform_browser_under_test, false);
  WriteFileHeader(parameter_big5_results, platform_browser_under_test, false);
  WriteFileHeader(query_big5_results, platform_browser_under_test, false);
  WriteFileHeader(form_get_big5_results, platform_browser_under_test, false);

  // The first dimension of this array denotes Encoding, the second dimension
  // denotes TestType
  FILE* http_file_matrix[][5] = {{host_ascii_http_results, path_ascii_results,
                                  parameter_ascii_results, query_ascii_results,
                                  form_get_ascii_results},
                                {host_big5_http_results, path_big5_results,
                                 parameter_big5_results, query_big5_results,
                                 form_get_big5_results}};
  // Dimension of this array denotes Encoding
  FILE* dns_file_matrix[] = {host_ascii_dns_results, host_big5_dns_results};
  int number_of_ranges = sizeof(kEntrySequenceInReport)/sizeof(kEntrySequenceInReport[0]);
  for (int i = 0; i < number_of_ranges; i++) {
    for (int j = kEntrySequenceInReport[i][0]; j <= kEntrySequenceInReport[i][1]; j++) {
      TestCase test_case = entries[j];
      FILE* output_file;

      // Generate Http reports
      output_file =
          http_file_matrix[test_case.test_encoding][test_case.test_component];
      AppendResultToReport(test_case,
                           test_case.test_encoding == kAscii,
                           test_results_http, output_file);

      // Generate DNS report
      if (test_case.test_component == kHost) {
        output_file = dns_file_matrix[test_case.test_encoding];
        AppendResultToReport(test_case,
                             test_case.test_encoding == kAscii,
                             test_results_dns, output_file);
      }
    }
  }

  WriteFileFooter(host_ascii_dns_results);
  WriteFileFooter(host_ascii_http_results);
  WriteFileFooter(path_ascii_results);
  WriteFileFooter(parameter_ascii_results);
  WriteFileFooter(query_ascii_results);
  WriteFileFooter(form_get_ascii_results);
  WriteFileFooter(host_big5_dns_results);
  WriteFileFooter(host_big5_http_results);
  WriteFileFooter(path_big5_results);
  WriteFileFooter(parameter_big5_results);
  WriteFileFooter(query_big5_results);
  WriteFileFooter(form_get_big5_results);

  return 0;
}
