CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = DBStoreLib.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include -I/usr/include -I./include
#Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib
LDFLAGS += /home/pedro/devel/optee/optee_examples/HCEMobile/libs/libcrypto.a

BINARY = DBStore

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDADD) -o $@ $< $(LDFLAGS) $(CFLAGS) -ldl

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)
