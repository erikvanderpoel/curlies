Erik van der Poel, 18 Dec 2009, Draft 1.5

### 1 Introduction ###

This document makes recommendations for browser developers who wish to transform URLs in the same way as other browsers. In addition to these interoperability considerations, some security recommendations are made.

This document is not intended to be a full specification. It only highlights the differences between the current versions of the browsers and makes a few interoperability and security recommendations.

### 2 Document Conventions ###

Recommendations are in normal paragraphs like this one.

> _**Rationale**_ The rationale for the previous paragraph is given in paragraphs like this one.

> _**Diffs**_ Differences between the browsers are highlighted in paragraphs like this one.

Characters are written in the Unicode U+HHHH notation, where H is a hex digit.

### 3 Definitions ###

  * Character encoding: e.g. UTF-8, not to be confused with percent-encoding
  * IRI: Internationalized Resource Identifier, [RFC 3987](http://www.rfc-editor.org/rfc/rfc3987.txt)
  * Percent-encoding: %HH where H is a hex digit, not to be confused with character encoding
  * URI: Uniform Resource Identifier, [RFC 3986](http://www.rfc-editor.org/rfc/rfc3986.txt)
  * URL: Uniform Resource Locator, as defined in [HTML5](http://dev.w3.org/html5/spec/Overview.html#terminology-0). URLs may contain mixtures of percent-encoded and not-percent-encoded non-ASCII text, so they are neither pure URIs nor pure IRIs

### 4 Scope ###

This document is limited to discussion of HTML, JavaScript, HTTP, HTTPS, FTP, IRI, URI, URL, IDNA and DNS. All other markup languages, scripting languages, and network protocols are out of scope.

### 5 Interoperability ###

In order to achieve interoperability, browsers must behave the same way in a number of areas, including protocol elements, script interfaces, user input, and display. User input and display are just as important because true interoperability includes human-to-human communication, not just machine-level interoperability.

APIs provided by the OS, such as DNS-related APIs called from a browser, are out of scope for this document.

#### 5.1 Protocol Elements ####

URLs appear in a number of protocol elements, including HTML attributes and HTTP requests. Also, the host name is often extracted from a URL in order to place it in other protocol elements like DNS packets and the HTTP Host request header.

When sending and receiving protocol elements, browsers must take care to achieve interoperability. The robustness principle is usually stated as follows.

> _Be conservative in what you do; be liberal in what you accept from others._

However, browsers have often been too liberal, and this has led to the proliferation of garbage on the Web. So the new recommendations are as follows.

> _Consumers should be as liberal as the major implementation(s), but not more liberal than that. Where security considerations are more important, consumers should be more conservative._

> _Producers should be conservative, to avoid constructs where consumers differ._

Note that a browser is both a consumer (of HTML documents, URLs typed by the user, etc) and a producer (of DNS packets, HTTP requests, etc).

#### 5.2 Script Interfaces ####

When browsers read and parse an HTML document, they build a DOM (Document Object Model) which can then be manipulated by scripts defined in or linked from the document. Browsers must therefore implement script interfaces to the same spec so that scripts can run the same way in any browser.

After building the initial DOM and displaying the document, browsers allow users to click on hyperlinks. At that point, browsers must resolve URLs and build network packets such as DNS queries and HTTP requests.

The following sections cover these areas in more detail.

### 6 Parsing a URL ###

When an HTML implementation reads in an HTML file, it first converts the entire file from the original character encoding to one of the Unicode character encodings, often UTF-16. It then parses the HTML, converting character references like &#12345; to Unicode along the way. The details of these steps are not in scope for this document.

This section is about parsing URLs found in HTML attributes like the href in ` <a href="..."> `. After extracting the attribute value, the steps are as follows.

TODO: Script interface tests will have to be written to confirm or expand upon the browser differences mentioned in this section. See section 8 "Resolving a URL" for test results that are more complete at this time.

#### 6.1 Remove Leading/Trailing Space ####

Remove white space from the beginning and end of the string.

#### 6.2 Remove TAB/LF/CR ####

Remove TAB, LF and CR (U+0009, U+000A, U+000D) from the entire string.

> _**Diffs**_ IE also removes NUL (U+0000) from the entire HTML file. See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinVista_SP1/path_ascii_results.html).

#### 6.3 Find the Delimiters ####

Parse the URL, looking for the ASCII syntax characters such as : and /. Developers who wish to be compatible with IE should convert \ to / in all parts before the ?query and #fragment. The structure of a URL is ` scheme://user:password@host:port/path;params?query#fragment `.

> _**Diffs**_ Some browsers terminate the host name at a semicolon, while others do not. See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinVista_SP1/host_ascii_dns_results.html). Semicolon is used to delimit parameters in the ftp scheme.

#### 6.4 Handle User/Password ####

If there is no user:password but there is an @, remove the @.

> _**Diffs**_ IE rejects http/https URLs with user:password, while Firefox accepts them.

#### 6.5 Handle Host Name ####

Percent-decode the host name. If the result is not well-formed UTF-8, reject the URL. If the resulting host name contains any ASCII control characters (U+0000-1F, U+007F) or any URL syntax character (:@/\;?#%), reject the URL.

> _**Rationale**_ Control characters and syntax characters are considered "tricky" and rejected on security grounds.

> _**Diffs**_ Safari performs these steps in the wrong order, leading to a Punycode encoding of a string that contains a dot (U+002E). See the [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/MacOSX10_5_8/host_big5_dns_results.html).

Convert the non-ASCII dots specified by IDNA2003 to the ASCII dot (U+002E), and divide the host name into labels. If any label begins with "xn--", run it through the Punycode decoder. If the decoding fails or the resulting Unicode string contains character sequences that are not allowed in the versions of IDNA and Unicode implemented by the browser, leave the label in its original xn-- form.

If there are any non-ASCII bytes, perform Nameprep and Punycode. If either of these steps fail, reject the URL. IDNA2003 did not explicitly specify what to do with dots (U+002E) that appear as a result of the Nameprep step. The recommendation is to split the name into labels again after the Nameprep step. Finally, convert these Punycode labels back to Unicode.

#### 6.6 Handle the Rest ####

For the rest of the URL, percent-decode the unreserved ASCII characters (a-zA-Z0-9, etc). TODO: details.

> _**Rationale**_ Percent-decoding all characters in the fragment and running a character encoding detector on it leads to non-deterministic behavior. Scripts in the document environment can decide what to do with percent-encoded fragments, since they are more likely to have knowledge of the underlying character encoding.

> _**Diffs**_ Firefox percent-decodes all characters in the fragment and runs a heuristic character encoding detector.

### 7 Script Interfaces ###

Scripts may run during the initial loading of a document and also afterwards, e.g. via timers and user input events. Browsers should implement the following interfaces in the same way in order to achieve interoperability.

Note: JavaScript characters and strings are in UTF-16.

#### 7.1 URL Attributes ####

For the HTML tag ` <a href="..."> `, the following interfaces are available.

` this.href ` should return the host name in Unicode, even if the original was in Punycode or percent-encoded UTF-8. Originally percent-encoded text in other parts of the URL should be returned as is, while originally not-percent-encoded text is returned in Unicode. Note: This corresponds to IRI. TODO: Decide whether this interface should return the absolute URL or the relative URL. In IE8 mode, IE8 returns the absolute URL.

> _**Diffs**_ IE and Firefox do not support percent-encoded UTF-8 in the host name. When the HTML specifies the host name in Punycode, IE, Firefox and Opera return the host name in Unicode, while Chrome returns it in Punycode.

` this.getAttribute('href') ` should return the URL in the original format, except for not-percent-encoded text, which should be returned in Unicode. This interface should return the absolute URL or the relative URL, depending on the original. In IE8 mode, IE8 returns the original. TODO: Test this.

> _**Diffs**_ Microsoft's interface allows an extra argument that controls relative vs absolute and Unicode vs Punycode host. See [their interface](http://msdn.microsoft.com/en-us/library/ms536429(VS.85).aspx). If the HTML source specifies the host name in Punycode, IE only returns it in Punycode when 2 is passed for the second argument.

` this.hostname ` should return Unicode.

> _**Diffs**_ When the HTML specifies the host name in Punycode, Chrome3 returns Punycode, while IE8, Firefox3.5 and Opera10 return Unicode.

` this.pathname ` should return Unicode.

> _**Diffs**_ When the HTML has a not-percent-encoded path, Firefox3.5 and Chrome3 return percent-encoded UTF-8, while IE8 and Opera10 return Unicode.

` this.search ` should return Unicode.

> _**Diffs**_ When the HTML has a not-percent-encoded query, IE8 returns Unicode, while Firefox3.5, Chrome3 and Opera10 return percent-encoded original character encoding.

#### 7.2 Summary ####

The script interfaces are a complete mess. Browser developers will have to discuss these, reach an agreement, and clean them up.

### 8 Resolving a URL ###

After parsing an HTML document and building the DOM, users may click on links and scripts may access interfaces that are defined to return resolved URLs and URL components. This section describes the resolution of URLs and URL components.

#### 8.1 Convert the Host Name ####

Convert any non-ASCII labels to Punycode. When an HTTP proxy is being used, the host name becomes part of the URL. Otherwise, the host name is placed in a DNS query and later in the HTTP Host header.

> _**Diffs**_ IE6 does not support IDNA. It converts non-ASCII host names using the default character encoding of the user's (localized) Windows OS. See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinXP_SP3/IE/host_big5_dns_results.html).

#### 8.2 Convert the Path and Params ####

Convert the path and params to UTF-8 and percent-encode the non-ASCII bytes.

> _**Diffs**_ Firefox2 converted back to the original character encoding (of the HTML document). See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinVista_SP1/Firefox/path_big5_results.html).

#### 8.3 Convert the Query ####

If the original character encoding of the HTML document was UTF-16- or UTF-32-based, convert the query to UTF-8. Otherwise, convert the query to the original character encoding and percent-encode all resulting non-ASCII bytes and any resulting delimiter-like ASCII bytes (#=&).

> _**Diffs**_ IE does not percent-encode. See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinVista_SP1/query_big5_results.html). TODO: iso-2022-jp results.

Unicode characters that cannot be converted to the original character encoding are converted to decimal NCRs (numeric character references) of the form &#12345; and then the &#; are percent-encoded.

> _**Rationale**_ For HTML forms with method GET, characters that cannot be converted to the original character encoding are converted to NCRs. Since servers cannot tell the difference between a URI that came from a hyperlink and a URI that came from an HTML form, it is better to handle the query part of a hyperlink in the same way as the query part of an HTML form submission. Converting unconvertable characters to question marks loses information, so NCRs should be used. Web site operators who are concerned about the fact that the ampersand itself is not escaped should use UTF-8 instead.

> _**Diffs**_ IE and Firefox do not convert unconvertable characters to NCRs for hyperlinks. For characters above U+FFFF, IE converts to two question marks, due to the internal UTF-16 encoding. See [test results](http://curlies.googlecode.com/svn/trunk/test_results/operating_systems/WinVista_SP1/query_big5_results.html).

### 9 User Input of a URL ###

The [IDNA2008 mapping draft](http://tools.ietf.org/html/draft-ietf-idnabis-mappings-05) suggests mapping the host name only in the UI (user interface), and not in interchanged host names such as those in HTML hrefs. One example where such mapping might be applied is the Turkish letter i, which has special mappings between upper and lower case.

Extreme caution is advised in this area, since it is difficult for an implementation to tell whether an input is from the current user or has been copied-and-pasted from another person who may be expecting different case mappings.

Until this area is better understood, the recommendation is to use a standard mapping similar to IDNA2003. Although this does not serve Turkish keyboard input very well, it is probably the most prudent thing to do at the moment.

### 10 Displaying a URL ###

#### 10.1 Spoofing ####

Some pairs of Unicode characters look exactly the same, e.g. Latin and Cyrillic letter a. The infamous paypal.com spoof showed how easy it was at the time to create a host name that looks exactly the same as the real paypal.com, yet resolve to a different IP address, potentially allowing the attacker to capture user passwords.

The recommendation is to display host names in Unicode only if they contain characters that the user is likely to be familiar with, or characters that cannot be confused with familiar ones. This should probably be based on the language(s) chosen by the user, normally also used with the HTTP Accept-Language header.

When the host name is not displayed in Unicode, it should be displayed in Punycode. Alternatively, the host name can be obscured somehow, but further research is probably needed.

> _**Diffs**_ Firefox displays IDNs in Unicode only when the TLD (top level domain) is in Firefox's white-list. A registry can apply for white-listing by submitting proof of the documentation and enforcement of rules against spoofing. Since VeriSign and Firefox have not reached any agreement, this has unfortunately left IDNs under .com in a state of limbo for several years.

#### 10.2 Bidi ####

Bidi is short for bidirectional text, as used with Arabic and Hebrew, which are written from right to left. The [IDNA2008 bidi draft](http://tools.ietf.org/html/draft-ietf-idnabis-bidi-06) is based on the premise that implementations will use the Unicode bidi algorithm to display host names.

However, it is probably necessary to conduct further research to determine the optimum display of URLs that contain bidi text. It is not clear that a simple application of the Unicode bidi algorithm (without override characters) would always yield a string that can easily be understood by the average bidi user.

### 11 References ###

[HTML5](http://dev.w3.org/html5/spec/Overview.html)

IDNA2003 [Main](http://www.rfc-editor.org/rfc/rfc3490.txt) [Nameprep](http://www.rfc-editor.org/rfc/rfc3491.txt) [Punycode](http://www.rfc-editor.org/rfc/rfc3492.txt)

IDNA2008 [Definitions](http://tools.ietf.org/html/draft-ietf-idnabis-defs-12) [Protocol](http://tools.ietf.org/html/draft-ietf-idnabis-protocol-17) [Table](http://tools.ietf.org/html/draft-ietf-idnabis-tables-08) [Bidi](http://tools.ietf.org/html/draft-ietf-idnabis-bidi-06) [Rationale](http://tools.ietf.org/html/draft-ietf-idnabis-rationale-14) [Mapping](http://tools.ietf.org/html/draft-ietf-idnabis-mappings-05)

IRI [RFC 3987](http://www.rfc-editor.org/rfc/rfc3987.txt)

IRIbis [Draft](http://tools.ietf.org/html/draft-duerst-iri-bis-07)

URI [RFC 3986](http://www.rfc-editor.org/rfc/rfc3986.txt)

[Web Addresses](http://www.w3.org/html/wg/href/draft)