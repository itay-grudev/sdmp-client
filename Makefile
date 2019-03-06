# Basic Setup
EXECNAME = sdmp-client
BINDIR   = bin/
OBJDIR   = $(BINDIR)obj/

# List the source input directories
SRCDIRS = src

# Default build
BUILD = debug

# Compiler command
CC = g++

# Compiler and Linker flags
CCFLAGS = -Wall -pedantic -std=c++11
LDFLAGS = -lgnutls

SRCEXTS = .c .cc .cpp .c++ .cxx .cp
SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
OBJECTS = $(addprefix $(OBJDIR), $(patsubst %,%.o,$(SOURCES)))
EXECUTABLE = $(BINDIR)$(EXECNAME)

# Check for debug or not
ifeq ($(BUILD),debug)
	CCFLAGS += -g3
else
	CCFLAGS += -O2
endif

# Check if we need to make a seperate bin folder
ifneq ($(BINDIR), )
	BINDIRCOMMAND = mkdir -p $(BINDIR)
else
	BINDIRCOMMAND =
endif

# Check if we need to make a seperate obj folder and its subfolder structure
ifneq ($(OBJDIR), )
	OBJDIRCOMMAND = mkdir -p $(OBJDIR)
	OBJDIRCOMMAND += $(foreach d,$(SRCDIRS), $(OBJDIR)$(d))
else
	OBJDIRCOMMAND =
endif

# Building recipies
all: bindir objdir $(EXECUTABLE)

run: $(EXECUTABLE)
	$(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CCFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

bindir:
	$(BINDIRCOMMAND)

objdir:
	$(OBJDIRCOMMAND)

$(OBJECTS) : $(SOURCES)
	$(CC) $(CCFLAGS) -c -o $@ $(patsubst $(OBJDIR)%.o,%,$@)

clean:
	rm -rf $(BINDIR)
	rm -rf $(OBJDIR)

.PHONY: all run clean
