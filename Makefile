.PHONY: all debug clean

all: curlmypoison

debug: curlmypoison_dbg

curlmypoison: curlmypoison.c
	gcc -Wall \
		curlmypoison.c \
		-lpcap \
		-o curlmypoison

curlmypoison_dbg: curlmypoison.c
	gcc -Wall -ggdb -O0 -D__DEBUG__ \
		curlmypoison.c \
		-lpcap \
		-o curlmypoison_dbg

clean:
	rm -f curlmypoison curlmypoison_dbg

