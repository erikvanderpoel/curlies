SRCS = \
  source/config.h \
  source/packet-sniffer.cc \
  source/packet-sniffer.h \
  source/report-generator.cc \
  source/testcases.cc \
  source/testcases.h \
  source/test-page-generator.cc

OBJS = report-generator test-page-generator

all: $(OBJS)

report-generator: $(SRCS)
	g++ -Wall -g source/report-generator.cc source/packet-sniffer.cc source/testcases.cc -o report-generator -lpcap

test-page-generator: $(SRCS)
	g++ -Wall -g source/testcases.cc source/test-page-generator.cc -o test-page-generator

clean:
	rm -fr $(OBJS)
