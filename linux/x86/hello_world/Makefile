TARGET=hello_world

# compilation targets
OBJ_FILE=$(TARGET:%=%.o)
TST_FILE=$(TARGET:%=%.c)

# compilation options
AS=nasm
ASFLAGS=-f elf
LD=ld
LDFLAGS=-m elf_i386
CC=gcc
CCFLAGS=-m32 -fno-stack-protector -z execstack

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILE)

test:
	$(CC) $(CCFLAGS) $(TST_FILE) -o $(TARGET)
	./$(TARGET)

print: $(TARGET)
	objdump -D -m i386 -j .text -M intel $(TARGET)
	objdump -d -j .text $(TARGET) | grep '[0-9a-f]:' | cut -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g' && printf "\n"

$(TARGET): $(OBJ_FILE)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
