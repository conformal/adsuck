#include <sys/socket.h>
#include <netdb.h>

/* Missing bits from Linux. */
#ifdef __linux__
#include <grp.h> /* needed for setgroups() */

size_t  strlcpy(char *, const char *, size_t);
#endif


#if defined(__linux__) || defined(DARWIN)
/*
 * XXX used in log_sockaddr which is currently unused. SA_LEN() was removed
 * from glibc and AFAICT there is no replacement.
 */
#define SA_LEN(x) (0)
#endif

/* log.c */
void		 log_init(int);
void		 vlog(int, const char *, va_list);
void		 log_warn(const char *, ...);
void		 log_warnx(const char *, ...);
void		 log_info(const char *, ...);
void		 log_debug(const char *, ...);
void		 fatal(const char *);
void		 fatalx(const char *);

/* resolv.c */
pid_t		monitor_fork(char *);

