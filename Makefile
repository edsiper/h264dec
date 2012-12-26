ARM_TOOLCHAIN = /home/edsiper/ToolChain/Mozart_Toolchain/
ARM_ROOT      = $(ARM_TOOLCHAIN)/arm-eabi-uclibc


CFLAGS = -g -Wall -Wno-format-security
OBJ    = network.o streamer.o base64.o rtp.o rtsp.o

all: h264dec

h264dec: $(OBJ)
	gcc $(CFLAGS) -o $@ $(OBJ)

arm:
	arm-linux-gcc --sysroot=$(ARM_ROOT) $(CFLAGS) -o $@ $(OBJ)

clean:
	rm -rf *~ *.o rtsp

.c.o:
	gcc -c $(CFLAGS) $<
