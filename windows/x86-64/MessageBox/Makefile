TARGET=MessageBox

# compilation targets
EXE_FILE=$(TARGET:%=%.exe)
OBJ_FILE=$(TARGET:%=%.o)
TST_FILE=$(TARGET:%=%.c)
BIN_FILE=$(TARGET:%=%.bin)
ASM_FILE=$(TARGET:%=%.asm)

# compilation options
AS=nasm
ASFLAGS=-f win64
CC=x86_64-w64-mingw32-gcc
CCFLAGS=-m64
OBJDUMP=x86_64-w64-mingw32-objdump

all: $(OBJ_FILE)

clean:
	rm -f $(EXE_FILE) $(OBJ_FILE) $(BIN_FILE)

test:
	$(CC) $(CCFLAGS) $(TST_FILE) -o $(EXE_FILE)

print: $(OBJ_FILE)
	$(OBJDUMP) -d -m i386:x86-64 -j .text -M intel $(OBJ_FILE)
	$(AS) -f bin $(ASM_FILE) -o $(BIN_FILE)
	xxd -i $(BIN_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
