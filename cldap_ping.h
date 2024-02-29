#ifndef _CLDAP_PING_H_
#define _CLDAP_PING_H_

// returns -1 of fatal errors, and -2 on network errors
// if we get one of those retry do the cldap ping again on a another dc
// site_name must be of MAXCDNAME size!
int cldap_ping(char *domain, struct sockaddr **addr, char *site_name);

#endif /* _CLDAP_PING_H_ */
