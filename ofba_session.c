#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <apr_pools.h>
#include <apr_getopt.h>
#include <apr_file_io.h>
#include <apr_mmap.h>
#include <apr_strings.h>

#include "auth_ofba.h"

static const apr_getopt_option_t ofba_session_options[] = {
 { "list",        'l', FALSE, "list sessions" },
 { "kill-user",   'u', TRUE,  "Kill user session" },
 { "kill-cookie", 'c', TRUE,  "Kill session by cookie" },
 { NULL,          0,   0,     NULL },
};

int
main(int argc, const char *const *argv)
{
  apr_getopt_t *opt;
  apr_pool_t *p;
  int optch;
  const char *optarg;
  int list = FALSE;
  char *kill_user = NULL;
  char *kill_cookie = NULL;
  apr_file_t *fh; 
  apr_int32_t fflags;
  apr_mmap_t *mmap;
  apr_off_t session_size;
  auth_ofba_session_t *sessions;               
  auth_ofba_session_t session0;
  apr_size_t session0_len = sizeof(session0);
  char errbuf[1024];
  apr_status_t res;;
  int i;

  if ((res = apr_pool_initialize()) != APR_SUCCESS)
    errx(1, "apr_pool_initialize failed: %s", 
         apr_strerror(res, errbuf, sizeof(errbuf)));

  if ((res = apr_pool_create(&p, NULL)) != APR_SUCCESS) 
    errx(1, "apr_pool_create failed: %s", 
         apr_strerror(res, errbuf, sizeof(errbuf)));

  if ((res = apr_getopt_init(&opt, p, argc, argv)) != APR_SUCCESS) 
    errx(1, "apr_getopt_init failed: %s", 
         apr_strerror(res, errbuf, sizeof(errbuf)));

  while ((res = apr_getopt_long(opt, ofba_session_options,
                                &optch, &optarg)) == APR_SUCCESS) {
    switch (optch) {
    case 'l':
      list = TRUE;
      break;
    case 'u':
      kill_user = apr_pstrdup(p, optarg);
      break;
    case 'c':
      kill_cookie = apr_pstrdup(p, optarg);
      break;
    default:
      errx(1, "Unexpected option. Usage: ofba_session (-l|-u user|-c cookie)");
    }
  }
 
  fflags = APR_FOPEN_READ|APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_BINARY;
  res = apr_file_open(&fh, AUTH_OFBA_SESSIONFILE, fflags, 0600, p);
  if (res != APR_SUCCESS)
     errx(1, "apr_file_open(\"%s\") failed: %s", AUTH_OFBA_SESSIONFILE,
          apr_strerror(res, errbuf, sizeof(errbuf)));

  res = apr_file_read(fh, &session0, &session0_len);
  if (res != APR_SUCCESS || auth_ofba_check_session_hash(&session0) != TRUE)
     errx(1, "Corrupted or newbirth session header");

  if (session0.s.header.version != AUTH_OFBA_SESSION_VERSION)
     errx(1, "Unexpected session file version %d, give up", 
          session0.s.header.version);

  session_size = session0.s.header.session_len * 
                 session0.s.header.session_count;
  
  res = apr_mmap_create(&mmap, fh, 0, session_size,
                        APR_MMAP_READ|APR_MMAP_WRITE, p);
  if (res != APR_SUCCESS)
     errx(1, "apr_mmap_create(\"%s\") failed: %s", AUTH_OFBA_SESSIONFILE,
          apr_strerror(res, errbuf, sizeof(errbuf)));

  sessions = mmap->mm;
  
  for (i = 1; i < session0.s.header.session_count; i++) {
     auth_ofba_session1_t *session1;

    if (auth_ofba_check_session_hash(&sessions[i]) != TRUE)
      continue;

    session1 = &sessions[i].s.v1;

    if (session1->expires == 0)
      continue;

    if (list) {
      apr_time_exp_t lt;
      apr_size_t written;
      char ltstr[1024];

      if ((res = apr_time_exp_lt(&lt, session1->expires)) != APR_SUCCESS)
         errx(1, "bad time on record %d, apr_time_exp_lt failed: %s", i, 
             apr_strerror(res, errbuf, sizeof(errbuf)));

      if ((res = apr_strftime(ltstr, &written, sizeof(ltstr),
                              "%Y-%m-%d %H:%M:%S", &lt)) != APR_SUCCESS)
         errx(1, "bad time on record %d, apr_strftime failed: %s", i, 
             apr_strerror(res, errbuf, sizeof(errbuf)));

      printf("%s\t%s\t%s\n", session1->cookie,
             session1->user, ltstr);
    }
                
    if (kill_user && strcmp(kill_user, session1->user) == 0) {
      auth_ofba_clear_session(&sessions[i]);
      printf("\tRemoved %s\n", kill_user);
      continue;
    }

    if (kill_cookie && strcmp(kill_cookie, session1->cookie) == 0) {
      auth_ofba_clear_session(&sessions[i]);
      printf("\tRemoved %s\n", kill_cookie);
      continue;
    }
  }

  if ((res = apr_file_close(fh)) != APR_SUCCESS)
     errx(1, "apr_file_close(\"%s\") failed: %s", AUTH_OFBA_SESSIONFILE,
          apr_strerror(res, errbuf, sizeof(errbuf)));

  return 0;
}
