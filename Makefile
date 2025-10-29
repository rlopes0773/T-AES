# Makefile for T-AES project

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -Iinclude
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src
APP_DIR = apps
TEST_DIR = tests
BUILD_DIR = build

# Source files
CORE_SOURCES = $(SRC_DIR)/taes.c $(SRC_DIR)/counter_mode.c $(SRC_DIR)/utils.c
CORE_SOURCES_NI = $(SRC_DIR)/taes_ni.c $(SRC_DIR)/counter_mode.c $(SRC_DIR)/utils.c

# Object files
CORE_OBJECTS = $(BUILD_DIR)/taes.o $(BUILD_DIR)/counter_mode.o $(BUILD_DIR)/utils.o
CORE_OBJECTS_NI = $(BUILD_DIR)/taes_ni.o $(BUILD_DIR)/counter_mode.o $(BUILD_DIR)/utils.o

# Applications
APPS = encrypt decrypt speed stat
APP_SOURCES = $(foreach app,$(APPS),$(APP_DIR)/$(app).c)

# Test
TEST_SOURCES = $(TEST_DIR)/test_taes.c

# Targets
.PHONY: all clean test test-basic apps taes taes-ni tests

all: $(BUILD_DIR) taes taes-ni apps tests

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Standard implementation
taes: $(BUILD_DIR) $(CORE_OBJECTS)
	@echo "Built standard T-AES implementation"

# AES-NI implementation
taes-ni: CFLAGS += -maes
taes-ni: $(BUILD_DIR) $(CORE_OBJECTS_NI)
	@echo "Built AES-NI T-AES implementation"

# Build object files (standard)
$(BUILD_DIR)/taes.o: $(SRC_DIR)/taes.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/counter_mode.o: $(SRC_DIR)/counter_mode.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/utils.o: $(SRC_DIR)/utils.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build object files (AES-NI)
$(BUILD_DIR)/taes_ni.o: $(SRC_DIR)/taes_ni.c
	$(CC) $(CFLAGS) -maes -c $< -o $@

# Applications
apps: $(APPS)

encrypt: $(BUILD_DIR) $(CORE_OBJECTS)
	$(CC) $(CFLAGS) $(APP_DIR)/encrypt.c $(CORE_OBJECTS) -o encrypt $(LDFLAGS)

decrypt: $(BUILD_DIR) $(CORE_OBJECTS)
	$(CC) $(CFLAGS) $(APP_DIR)/decrypt.c $(CORE_OBJECTS) -o decrypt $(LDFLAGS)

speed: $(BUILD_DIR) $(CORE_OBJECTS) $(CORE_OBJECTS_NI)
	$(CC) $(CFLAGS) -maes $(APP_DIR)/speed.c $(CORE_OBJECTS) -o speed $(LDFLAGS)

stat: $(BUILD_DIR) $(CORE_OBJECTS)
	$(CC) $(CFLAGS) $(APP_DIR)/stat.c $(CORE_OBJECTS) -o stat $(LDFLAGS)

# Tests
tests: $(BUILD_DIR) $(CORE_OBJECTS)
	$(CC) $(CFLAGS) $(TEST_SOURCES) $(CORE_OBJECTS) -o $(TEST_DIR)/test_taes $(LDFLAGS)
	$(CC) $(CFLAGS) $(TEST_DIR)/test_basic_aes.c $(CORE_OBJECTS) -o $(TEST_DIR)/test_basic_aes $(LDFLAGS)

# Run tests
test: tests
	./$(TEST_DIR)/test_taes

# Run basic AES tests (without tweak)
test-basic: $(BUILD_DIR) $(CORE_OBJECTS)
	$(CC) $(CFLAGS) $(TEST_DIR)/test_basic_aes.c $(CORE_OBJECTS) -o $(TEST_DIR)/test_basic_aes $(LDFLAGS)
	./$(TEST_DIR)/test_basic_aes

# Clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f encrypt decrypt speed stat
	rm -f $(TEST_DIR)/test_taes $(TEST_DIR)/test_basic_aes

# Help
help:
	@echo "T-AES Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (default)"
	@echo "  taes       - Build standard T-AES implementation"
	@echo "  taes-ni    - Build AES-NI T-AES implementation"
	@echo "  apps       - Build all applications"
	@echo "  tests      - Build test suite"
	@echo "  test       - Build and run full T-AES tests"
	@echo "  test-basic - Build and run basic AES tests (no tweak)"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Applications:"
	@echo "  encrypt    - Encryption tool"
	@echo "  decrypt    - Decryption tool"
	@echo "  speed      - Performance benchmark"
	@echo "  stat       - Statistical analysis"
