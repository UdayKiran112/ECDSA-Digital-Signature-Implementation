# Compiler and Flags
CXX = g++
CXXFLAGS = -g -O2 -Wall

# Directories
SRC_DIR = .
OBJ_DIR = obj
LIB_DIR = Lib

# Project Files
SRCS = main.cpp Key.cpp
OBJS = $(SRCS:%.cpp=$(OBJ_DIR)/%.o)
LIBS = $(LIB_DIR)/core.a

# Executable
TARGET = main

# Rules
all: $(OBJ_DIR) $(TARGET)

# Link the object files to create the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compile the source files into object files and place them in the OBJ_DIR
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create the object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean up
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean
