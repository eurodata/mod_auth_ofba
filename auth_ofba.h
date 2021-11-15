#ifndef _MOD_AUTH_OFBA_H_
#define _MOD_AUTH_OFBA_H_

#include <apr_time.h>
#include <apr_sha1.h>

#define AUTH_OFBA_SESSION_MAX 1024
#define AUTH_OFBA_SESSION_VERSION 1
#define AUTH_OFBA_USER_MAX 16

typedef struct {
  char cookie[40];
  char user[AUTH_OFBA_USER_MAX];
  char ap_auth_type[16];
  apr_time_t expires;
} auth_ofba_session1_t;

typedef struct {
  union {
    struct {
      int version;
      apr_size_t session_len;
      apr_size_t session_count;
    } header;
    auth_ofba_session1_t v1;
  } s;
  unsigned char hash[APR_SHA1_DIGESTSIZE];
} auth_ofba_session_t;

static inline void
auth_ofba_set_session_hash(auth_ofba_session_t *session)
{
  auth_ofba_session_t s;
  apr_sha1_ctx_t context; 

  memcpy(&s, session, sizeof(s));
  memset(s.hash, '\0', sizeof(s.hash));
  
  apr_sha1_init(&context);
  apr_sha1_update(&context, (char *)&s, sizeof(s));
  apr_sha1_final((unsigned char *)&session->hash, &context);

  return;
}

static inline int
auth_ofba_check_session_hash(auth_ofba_session_t *session)
{
  auth_ofba_session_t s;
  apr_sha1_ctx_t context; 

  memcpy(&s, session, sizeof(s));
  memset(s.hash, '\0', sizeof(s.hash));
  
  apr_sha1_init(&context);
  apr_sha1_update(&context, (char *)&s, sizeof(s));
  apr_sha1_final((unsigned char *)&s.hash, &context);

  return (memcmp(session, &s, sizeof(s)) == 0) ? TRUE : FALSE;
}

static inline void
auth_ofba_clear_session(auth_ofba_session_t *session)
{
  (void)memset(session, '\0', sizeof(*session));
  auth_ofba_set_session_hash(session);
}


#endif /* _MOD_AUTH_OFBA_H_ */
