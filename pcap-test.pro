TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += pcap-test.c \
    parse_packet.c

HEADERS += \
    pcap-test.h
