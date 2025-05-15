
# the standard shell for make

EXE_NAM = cry3
BASE_DIR = ..

SRC_DIR = $(BASE_DIR)/src

BIN_DIR = $(BASE_DIR)/bin
OBJ_DIR = $(BASE_DIR)/bin/obj
INCLUDE_DIR = $(BASE_DIR)/include

INCLUDE_FLAGS = -I$(INCLUDE_DIR)
#DBG_FLAGS = -DFULL_DEBUG -rdynamic  
DBG_FLAGS = -rdynamic  

# CMPL_FLAGS = $(INCLUDE_FLAGS) 
CMPL_FLAGS = $(DBG_FLAGS) $(INCLUDE_FLAGS) -Wall -std=c++20 
LNK_FLAGS = $(DBG_FLAGS) -lstdc++
#LNK_FLAGS = $(DBG_FLAGS) -lstdc++

CPP = g++
CC = gcc

default_rule: $(BIN_DIR)/$(EXE_NAM)
	@echo "Finished building "$(EXE_NAM)"."

ALL_OBJS = \
$(OBJ_DIR)/cry.o\
$(OBJ_DIR)/sha2.o\
$(OBJ_DIR)/tak_mak.o

ALL_HEADERS = \
$(INCLUDE_DIR)/mem.h\
$(INCLUDE_DIR)/platform.h\
$(INCLUDE_DIR)/bit_row.h\
$(INCLUDE_DIR)/tools.h\
$(INCLUDE_DIR)/secure_gets.h\
$(INCLUDE_DIR)/sha2.h\
$(INCLUDE_DIR)/tak_mak.h\
$(INCLUDE_DIR)/cry.h

#---------------------------------------------------------
# executables
#

$(BIN_DIR)/$(EXE_NAM): $(ALL_OBJS) 
	@echo "Building executable "$(EXE_NAM)" ..."
	$(CPP) $(ALL_OBJS) $(LNK_FLAGS) -o $(BIN_DIR)/$(EXE_NAM)

help:
	@echo "Teclee 'make'"

#---------------------------------------------------------
# clean rule
#

clean: 
	rm -f $(BIN_DIR)/$(EXE_NAM) $(ALL_OBJS)


full: clean $(BIN_DIR)/$(EXE_NAM)
	@echo "Finished full build of "$(EXE_NAM)"."


# Rules to build .o files from their sources:


#---------------------------------------------------------
# object files
#

$(OBJ_DIR)/cry.o: $(SRC_DIR)/cry.cpp $(ALL_HEADERS)
	$(CPP) -o $(OBJ_DIR)/cry.o $(CMPL_FLAGS)  -c $(SRC_DIR)/cry.cpp

$(OBJ_DIR)/sha2.o: $(SRC_DIR)/sha2.c $(ALL_HEADERS)
	$(CC) -o $(OBJ_DIR)/sha2.o $(CMPL_FLAGS)  -c $(SRC_DIR)/sha2.c

$(OBJ_DIR)/tak_mak.o: $(SRC_DIR)/tak_mak.cpp $(ALL_HEADERS)
	$(CPP) -o $(OBJ_DIR)/tak_mak.o $(CMPL_FLAGS)  -c $(SRC_DIR)/tak_mak.cpp




