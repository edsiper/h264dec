ARM_TOOLCHAIN = /home/edsiper/ToolChain/Mozart_Toolchain/
ARM_ROOT      = $(ARM_TOOLCHAIN)/arm-eabi-uclibc
CFLAGS  = -g -Wall -Wno-format-security
OBJ     = streamer.o network.o base64.o rtp.o rtcp.o rtsp.o
SOURCES = streamer.c network.c base64.c rtp.c rtcp.c rtsp.c
LIBS    = -lpthread

all: h264dec

h264dec: $(OBJ)
	gcc $(CFLAGS) -o $@ $(OBJ) $(LIBS)

arm: $(OBJ)
	arm-linux-gcc --sysroot=$(ARM_ROOT) $(SOURCES) -o $@ $(LIBS)

clean:
	rm -rf *~ *.o rtsp

