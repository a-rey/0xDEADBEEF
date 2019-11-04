TARGET=execve

# compilation targets
OBJ_FILE=$(TARGET:%=%.o)
TST_FILE=$(TARGET:%=%.py)

# compilation options
AS=nasm
ASFLAGS=-f macho64
LD=ld
LDFLAGS=-macosx_version_min 10.7.0 -lSystem

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ_FILE)

test: $(TARGET)
	python3 $(TST_FILE)

print: $(TARGET)
	objdump -D -j .text -M intel $(TARGET)
	objdump -d -j .text $(TARGET) | grep '[0-9a-f]:' | cut -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g' && printf "\n"

$(TARGET): $(OBJ_FILE)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJ_FILE)

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@
