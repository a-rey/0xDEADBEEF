TARGET=hello_world

# compilation targets
OBJ_FILE=$(TARGET:%=%.o)
ASM_FILE=$(TARGET:%=%.asm)
BIN_FILE=$(TARGET:%=%.bin)
TST_FILE=$(TARGET:%=%.py)

# compilation options
AS=nasm
ASFLAGS=-f macho64
LD=ld
LDFLAGS=-macosx_version_min 10.7.0 -lSystem
OBJDUMP=objdump

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILE) $(BIN_FILE)

test: $(TARGET)
	python3 $(TST_FILE)

print: $(OBJ_FILE)
	$(OBJDUMP) -d -m i386 -j .text -M intel $(OBJ_FILE)
	$(AS) -f bin $(ASM_FILE) -o $(BIN_FILE)
	xxd -i $(BIN_FILE)
	
$(TARGET): $(OBJ_FILE)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
