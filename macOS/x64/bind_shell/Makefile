TARGET=bind_shell

# compilation targets
SRC_FILES:=$(shell find . -name *.asm)
OBJ_FILES=$(SRC_FILES:%.asm=%.o)
TXT_FILE=$(TARGET:%=%.txt)

# compilation options
AS=nasm
ASFLAGS=-f macho64
LD=ld
LDFLAGS=-macosx_version_min 10.7.0 -lSystem

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILES) $(TXT_FILE)

python: $(TARGET)
	# generating Python stub ...
	objdump -d -j .text $(TARGET) | grep '[0-9a-f]:' | cut -f2 | grep -v 'file' | tr -d " \n" > $(TXT_FILE)
	cat $(TXT_FILE) | python ../../../shellcode_test.py

debug: $(TARGET)
	objdump -d -M intel -j .text $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILES)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
