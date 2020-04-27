#include <dns.h>
#include <stdio.h>


int main()
{
    struct dns_answers *ans = dns_get("10.1.1.1",
                                      "veresov.pro",
                                      dns_type_mx);
    struct dns_answers *cur;
    for (cur = ans; cur; cur = cur->next) {
        if (cur->type == dns_type_a) {
            unsigned char *ip = cur->data;
            printf("IP of %s is %d.%d.%d.%d.\n",
                   cur->host, ip[0], ip[1], ip[2], ip[3]);
        } else if (cur->type == dns_type_cname) {
            printf("Cannonical name of %s is %s.\n", cur->host, cur->data);
        } else if (cur->type == dns_type_txt) {
            printf("Text from %s: %s\n", cur->host, cur->data);
        } else if (cur->type == dns_type_mx) {
            printf("Mail exchange server for %s with preference %d is %s.\n",
                   cur->host,
                   dns_mx_preference(cur->data), dns_mx_server(cur->data));
        }
    }
    dns_free(ans);
    return 0;
}
