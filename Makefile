# Makefile — macOS APT UI Interference Detector
# Requires: Xcode Command Line Tools (free)
#   xcode-select --install

CC      = clang
TARGET  = macos_apt_detector
SRC     = macos_apt_detector.c

CFLAGS  = -Wall -Wextra -O2 -mmacosx-version-min=12.0
LDFLAGS = -framework CoreFoundation   \
          -framework ApplicationServices \
          -framework IOKit              \
          -framework Security           \
          -lproc

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Build OK → ./$(TARGET)"

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
