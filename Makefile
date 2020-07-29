dns_example: dns_example.c dns.c dns.h
	gcc dns_example.c dns.c -I. -o $@

.PHONY: clean
clean:
	rm -f dns_example
