TARGET=execve

# compilation targets
OBJ_FILE=$(TARGET:%=%.o)
TST_FILE=$(TARGET:%=%.c)

# compilation options
AS=nasm
ASFLAGS=-f elf64
LD=ld
LDFLAGS=-m elf_x86_64
CC=gcc
CCFLAGS=-m64 -fno-stack-protector -z execstack

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILE)

test:
	$(CC) $(CCFLAGS) $(TST_FILE) -o $(TARGET)
	./$(TARGET)

print: $(TARGET)
	objdump -D -m i386:x86-64 -j .text -M intel $(TARGET)
	objdump -d -j .text $(TARGET) | grep '[0-9a-f]:' | cut -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g' && printf "\n"

$(TARGET): $(OBJ_FILE)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
