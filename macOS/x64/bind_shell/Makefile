TARGET=bind_shell

# compilation targets
SRC_FILES:=$(shell find . -name *.asm)
OBJ_FILES=$(SRC_FILES:%.asm=%.o)
BIN_FILE=$(TARGET:%=%.bin)

# compilation options
AS=nasm
ASFLAGS=-f macho64
LD=ld
LDFLAGS=-macosx_version_min 10.7.0 -lSystem

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILES)

debug: $(TARGET)
	objdump -d -M intel -j .text $(TARGET)
	python ../../../test.py $(BIN_FILE)

$(TARGET): $(OBJ_FILES)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILES)
	# generating shell code stub ...
	objdump -d -j .text $(TARGET) | grep '[0-9a-f]:' | cut -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g' > $(BIN_FILE)
	cat $(BIN_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
