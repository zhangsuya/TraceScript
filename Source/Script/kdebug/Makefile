
all: x86 arm64
	lipo -create -arch arm64 kdv.arm64 -arch x86_64 kdv -arch armv7 kdv.armv7 -output kdv.universal


x86:
	gcc kdebugView.c -o kdv

# iOS 9 with Pangu requires a self signature
arm64:
	gcc-iphone kdebugView.c -o kdv.arm64
	jtool --sign kdv.arm64
	mv out.bin kdv.arm64

armv7:
	gcc-armv7 kdebugView.c -o kdv.armv7 -DARMv7
	ldid -S kdv.armv7
	#jtool --sign kdv.armv7
	#mv out.bin kdv.armv7

dist:
	tar cvf ~/kdebug.tar	Makefile kdebug_private.h kdebugView.c kdv.universal /usr/share/misc/trace.codes
