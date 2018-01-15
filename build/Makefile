###
# This file is part of imPENNetrables
#
# @author: Hung Nguyen
###

CC=g++
CFLAGS=-Ilibs -Isrc
CXXFLAGS=-std=c++11 -Wall
LDFLAGS=-lssl -lcrypto -lgmpxx -lgmp -lpthread

BANK_DIR=src/bank
ATM_DIR=src/atm
COMMON_DIR=src/common
OBJ_DIR=obj

BANK_SOURCES=$(wildcard $(BANK_DIR)/*.cpp)
ATM_SOURCES=$(wildcard $(ATM_DIR)/*.cpp)
COMMON_SOURCES=$(wildcard $(COMMON_DIR)/*.cpp)
BANK_OBJECTS=$(patsubst $(BANK_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(BANK_SOURCES))
ATM_OBJECTS=$(patsubst $(ATM_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(ATM_SOURCES))
COMMON_OBJECTS=$(patsubst $(COMMON_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(COMMON_SOURCES))

all: $(BANK_SOURCES) $(ATM_SOURCES) $(COMMON_SOURCES) bank atm

bank: $(BANK_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(BANK_OBJECTS) $(COMMON_OBJECTS) -o $@ $(LDFLAGS)

atm:  $(ATM_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(ATM_OBJECTS) $(COMMON_OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(BANK_DIR)/%.cpp | create_dirs
	g++ $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: $(ATM_DIR)/%.cpp | create_dirs
	g++ $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: $(COMMON_DIR)/%.cpp | create_dirs
	g++ $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) bank atm *.auth *.card

create_dirs:
	mkdir -p $(OBJ_DIR)