#ifndef NEWBIEDNS_INCLUDED
#define NEWBIEDNS_INCLUDED


enum {  /* Some of DNS types: */
    dns_type_a     = 1,
    dns_type_cname = 5,
    dns_type_mx    = 15,
    dns_type_txt   = 16,
    dns_type_srv   = 33
};

struct dns_answers {
    struct dns_answers *next;
    char               *host;
    int                 type;
    unsigned int        size;
    void               *data;
};

/* For CNAME & TXT data is just 'char *',
 * For A data is 'unsigned char *' of size 4. */

char *dns_mx_server(void *data);
int   dns_mx_preference(void *data);

char *dns_srv_server(void *data);
int   dns_srv_port(void *data);
int   dns_srv_priority(void *data);
int   dns_srv_weight(void *data);

/* In case of error result is 0. */
struct dns_answers *dns_get(const char *server, const char *host, int query);

void dns_free(struct dns_answers *answers);


#endif
