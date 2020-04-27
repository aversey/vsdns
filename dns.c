#include "dns.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>


struct header {
    unsigned short id;

    char a;
    /*
    int is_response:          1;
    int opcode:               4;
    int is_authanswer:        1;
    int is_recursion_desired: 1;
    */

    char b;
    /*
    int is_recursion_available: 1;
    int:                        3;
    int response_code:          4;
    */

    unsigned short questions;
    unsigned short answers;
    unsigned short authorities;
    unsigned short additionals;
};

struct question_header {
    unsigned short type;
    unsigned short class;
};

struct resource_header {
    unsigned short type;
    unsigned short class;
    unsigned int   ttl;
    unsigned short datalen;
};


static void fill_header(char **writer)
{
    struct header *head = (struct header *) *writer;
    memset(head, 0, sizeof(*head));
    head->id        = (unsigned short) htons(getpid());
    head->a         = 0b00000001;
    head->questions = htons(1);
    *writer += sizeof(*head);
}

static void fill_name(char **writer, const char *host)
{
    char *last = *writer;
    do {
        if (*host == '.' || !*host) {
            *last = *writer - last;
            last  = ++*writer;
        } else {
            *++*writer = *host;
        }
    } while (*host++);
    *last = 0;
    ++*writer;
}

static void fill_question(char **writer, int query_type)
{
    struct question_header *q = (struct question_header *) *writer;
    q->type  = htons(query_type);
    q->class = htons(1);
    *writer += sizeof(*q);
}

static int ask(const char *s, const char *h, int qt, struct sockaddr_in *a)
{
    int sent;
    int plen = sizeof(struct header) + strlen(h) + 2 +
               sizeof(struct question_header);
    char *packet       = malloc(plen);
    char *writer       = packet;
    int   sock         = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    a->sin_family      = AF_INET;
    a->sin_port        = htons(53);
    a->sin_addr.s_addr = inet_addr(s);

    fill_header(&writer);
    fill_name(&writer, h);
    fill_question(&writer, qt);

    sent = sendto(sock, packet, plen, 0, (struct sockaddr *) a, sizeof(*a));
    free(packet);
    if (sent != plen) {
        return 0;
    }
    return sock;
}


static void skip_questions(char **reader, int num)
{
    for (; num; --num) {
        *reader += strlen(*reader) + 1;
        *reader += sizeof(struct question_header);
    }
}

static char *read_name(char **extrareader, char *packet)
{
    char *name   = malloc(256);  /* cannot be more =) */
    char *reader = *extrareader;
    char *writer = name;
    int   jumped = 0;
    if (!*reader) {
        *name = 0;
        return name;
    }
    while (*reader) {
        unsigned char len = *reader++;
        if (len >= 192) {
            int jump = ((unsigned char) *reader) + (len - 192) * 256;
            if (!jumped) {
                *extrareader += 2;
                jumped        = 1;
            }
            reader = packet + jump;
            continue;
        }
        memcpy(writer, reader, len);
        writer += len;
        reader += len;
        if (!jumped) {
            *extrareader += len + 1;
        }
        *writer++ = '.';
    }
    if (!jumped) {
        ++*extrareader;
    }
    *--writer = 0;
    return name;
}

static struct dns_answers *get_answers(char **reader, char *packet, int num)
{
    struct dns_answers     *res;
    struct resource_header *head;
    if (!num) {
        return 0;
    }
    res       = malloc(sizeof(*res));
    res->host = read_name(reader, packet);
    head      = (struct resource_header *) *reader;
    res->type = ntohs(head->type);
    res->size = ntohs(head->datalen);
    *reader  += 10;
    if (res->type == dns_type_cname) {
        res->size--;
        res->data = read_name(reader, packet);
    } else if (res->type == dns_type_mx) {
        char *name;
        unsigned short pref = ntohs(*((unsigned short *) *reader));
        *reader  += 2;
        name      = read_name(reader, packet);
        res->data = malloc(3 + strlen(name));
        *((unsigned short *) res->data) = pref;
        memcpy(res->data + 2, name, strlen(name) + 1);
        free(name);
    } else {
        if (res->type == dns_type_txt) {
            res->size--;
            ++*reader;
        }
        res->data = malloc(res->size);
        memcpy(res->data, *reader, res->size);
        *reader += res->size;
    }
    res->next = get_answers(reader, packet, num - 1);
    return res;
}

static struct dns_answers *get(int sock, struct sockaddr_in *a)
{
    char           packet[512];
    char          *reader = packet;
    struct header *head;
    socklen_t      slen = sizeof(*a);
    if (!sock) {
        return 0;
    }
    if (recvfrom(sock, packet, 512, 0, (struct sockaddr *) a, &slen) < 0) {
        return 0;
    }
    head            = (struct header *) reader;
    head->questions = ntohs(head->questions);
    head->answers   = ntohs(head->answers);
    reader         += sizeof(*head);
    skip_questions(&reader, head->questions);
    return get_answers(&reader, packet, head->answers);
}


int dns_mx_preference(void *data)
{
    return *((unsigned short *) data);
}

char *dns_mx_server(void *data)
{
    return ((char *) data) + 2;
}


struct dns_answers *dns_get(const char *server, const char *host, int query)
{
    struct sockaddr_in addr;
    return get(ask(server, host, query, &addr), &addr);
}

void dns_free(struct dns_answers *answers)
{
    if (answers) {
        dns_free(answers->next);
        free(answers->host);
        free(answers->data);
        free(answers);
    }
}
