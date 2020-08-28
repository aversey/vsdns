DEBUG  ?= yes

CFLAGS  = -xc -ansi -Wall
ifeq '$(DEBUG)' 'yes'
CFLAGS += -g -O0
else
CFLAGS += -O3
endif

dns_example: dns_example.c dns.c
	gcc $(CFLAGS) $^ -I. -o $@

.PHONY: clean
clean:
	rm -f dns_example
