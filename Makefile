CC ?= gcc
CFLAGS := $(CFLAGS) \
	-Wall \
	-Wextra \
	-Werror \
	-Wstrict-aliasing \
	-Wchar-subscripts \
	-Wformat-security \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wpointer-arith \
	-Wshadow \
	-Wsign-compare \
	-Wstrict-prototypes \
	-Wtype-limits \
	-Wunused-function \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-Wno-unknown-pragmas

OBJECTS := wirefraud
.PHONY: all clean

all: $(OBJECTS)
clean:
	rm -f $(OBJECTS)
%: %.c
	$(CC) $(CFLAGS) -o $@ $^
