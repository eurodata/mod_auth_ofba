/*
 * Copyright (c) 2017 Emmanuel Dreyfus
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by Emmanuel Dreyfus
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_strmatch.h>
#include <apr_global_mutex.h>
#include <apr_random.h>
#include <apr_strings.h>
#include <apr_escape.h>

#include <httpd.h>
#include <http_protocol.h>
#include <unixd.h>
#include <http_log.h>
#include <http_core.h>
#include <http_config.h>
#include <http_request.h>

#define AUTH_OFBA_REALM_DEFAULT "mod_auth_ofba"
#define AUTH_OFBA_DIALOG_SIZE_DEFAULT "320x130"
#define AUTH_OFBA_COOKIE_NAME_DEFAULT "OFBAsession"
#define AUTH_OFBA_SESSION_DURATION_DEFAULT 86400

#include "auth_ofba.h"

const char *auth_ofba_user_agents_str[] = {
  "^Microsoft Data Access Internet Publishing Provider",
#if 0
  "^Microsoft-WebDAV-MiniRedir",
#endif
  "^MSOffice [0-9]",
  "^MSOffice (Word|Excel|PowerPoint|OneNote|SyncCenter) [0-9]",
  "^Microsoft Office (Word|Excel|PowerPoint|OneNote|SyncCenter) [0-9]",
  "^Microsoft Office Protocol Discovery",
  "^non-browser",
  "^Mozilla/4.0 \\(compatible; MS FrontPage ([1-9]|1[0-4])",
};
#define AUTH_OFBA_USER_AGENTS_COUNT \
  sizeof(auth_ofba_user_agents_str) / sizeof(*auth_ofba_user_agents_str)

typedef struct {
  int enable;
  char *auth_request_url;
  char *auth_success_url;
  char *dialog_size;
  char *cookie_name;
  int session_duration;
  int session_autorenew;
  ap_regex_t *cookie_pat;
} auth_ofba_conf_t;

typedef struct {
  const ap_regex_t *ofba_user_agents_pat[AUTH_OFBA_USER_AGENTS_COUNT];
  auth_ofba_session_t *sessions;
  apr_size_t session_len;
  apr_size_t session_count;
  apr_global_mutex_t *mtx;
  apr_random_t *random;
} auth_ofba_state_t;

module AP_MODULE_DECLARE_DATA auth_ofba_module;

static ap_regex_t *
auth_ofba_cookie_pat(apr_pool_t *p, const char *cookie_name)
{
  ap_regex_t *cookie_pat;
  char *pattern = apr_psprintf(p, "(^|;[ \t]+)%s=([^;]+)", cookie_name);

  cookie_pat = ap_pregcomp(p, pattern, AP_REG_EXTENDED);
  if (cookie_pat == NULL)
    ap_log_perror(APLOG_MARK, APLOG_ERR, EINVAL, p,
                  "ap_pregcomp(\"%s\" failed", pattern);

  return cookie_pat;
}

static const char *
auth_ofba_set_cookie_slot(cmd_parms *cmd, void *conf_ptr, const char *val)
{
  const char *errmsg = NULL;
  auth_ofba_conf_t *conf = (auth_ofba_conf_t *)conf_ptr;
  
  conf->cookie_name = apr_pstrdup(cmd->pool, val);

  if ((conf->cookie_pat = auth_ofba_cookie_pat(cmd->pool, val)) == NULL)
    errmsg = "Fatal error: Bad AuthOFBAcookieName";
    
  return errmsg;
}

static const command_rec auth_ofba_cmds[] = {
  AP_INIT_FLAG("AuthOFBAenable", ap_set_flag_slot,
               (void *)APR_OFFSETOF(auth_ofba_conf_t, enable),
               OR_ALL, "Enable OFBA"),
  AP_INIT_TAKE1("AuthOFBAauthRequestURL", ap_set_string_slot,
                (void *)APR_OFFSETOF(auth_ofba_conf_t, auth_request_url),
                OR_ALL, "Set authentication form URL"),
  AP_INIT_TAKE1("AuthOFBAauthSuccessURL", ap_set_string_slot,
                (void *)APR_OFFSETOF(auth_ofba_conf_t, auth_success_url),
                OR_ALL, "Set authentication success URL"),
  AP_INIT_TAKE1("AuthOFBAdialogSize", ap_set_string_slot,
                (void *)APR_OFFSETOF(auth_ofba_conf_t, dialog_size),
                OR_ALL, "Set authentication dialog size"),
  AP_INIT_TAKE1("AuthOFBAcookieName", auth_ofba_set_cookie_slot,
                NULL,
                OR_ALL, "Set OFBA session cookie name"),
  AP_INIT_TAKE1("AuthOFBAsessionDuration", ap_set_int_slot,
                (void *)APR_OFFSETOF(auth_ofba_conf_t, session_duration),
                OR_ALL, "Set OFBA session session duration"),
  AP_INIT_FLAG("AuthOFBAsessionAutoRenew", ap_set_flag_slot,
               (void *)APR_OFFSETOF(auth_ofba_conf_t, session_autorenew),
                OR_ALL, "Automatically extend session on each request"),
  {NULL}
};


static int
auth_ofba_init(apr_pool_t *conf_pool, apr_pool_t *log_pool,
               apr_pool_t *tmp_pool, server_rec *s)
{
  const char *userdata_key = __func__;
  void *userdata_val;
  apr_file_t *fh;
  apr_int32_t fflags;
  apr_fileperms_t fperms;
  auth_ofba_state_t *state;
  apr_mmap_t *mmap;
  auth_ofba_session_t session0;
  apr_size_t session0_len = sizeof(session0);;
  auth_ofba_session1_t *session1;
  apr_off_t session_size;
  int corrupted_sessions = 0;
  unsigned char seed[8];
  apr_time_t now = apr_time_now();
  apr_status_t res = APR_SUCCESS;
  int i;

  /*
   * Apache loads modules twice, initialize only on second run.
   */
  res = apr_pool_userdata_get(&userdata_val, userdata_key, s->process->pool);
  if (res != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_pool_userdata_get failed");
    goto out;
  }

  if (userdata_val == NULL) {
    apr_pool_userdata_set((const void *)-1, userdata_key,
                          apr_pool_cleanup_null, s->process->pool);
    res = OK;
    goto out;
  }

  state = ap_get_module_config(s->module_config, &auth_ofba_module);

  res = apr_global_mutex_create(&state->mtx, AUTH_OFBA_LOCKFILE,
                                APR_LOCK_DEFAULT, conf_pool);
  if (res != APR_SUCCESS) {
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "apr_global_mutex_create failed");
     goto out;
  }

  res = ap_unixd_set_global_mutex_perms(state->mtx);
  if (res != APR_SUCCESS) {
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "ap_unixd_set_global_mutex_perms failed");
     goto out;
  }

  fflags = APR_FOPEN_READ|APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_BINARY;
  fperms = APR_FPROT_UREAD|APR_FPROT_UWRITE;
  res = apr_file_open(&fh, AUTH_OFBA_SESSIONFILE, fflags, fperms, conf_pool);
  if (res != APR_SUCCESS) {
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "apr_file_open(\"%s\") failed", AUTH_OFBA_SESSIONFILE);
     goto out;
  }

  res = apr_file_read(fh, &session0, &session0_len);
  if (res != APR_SUCCESS || auth_ofba_check_session_hash(&session0) != TRUE) {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                  "Corrupted or newbirth session header, remove all sessions");
     session0.s.header.version = AUTH_OFBA_SESSION_VERSION;
     session0.s.header.session_len = sizeof(session0);
     session0.s.header.session_count = AUTH_OFBA_SESSION_MAX;
     auth_ofba_set_session_hash(&session0);
  }

  if (session0.s.header.version != AUTH_OFBA_SESSION_VERSION) {
     res = EINVAL;
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "Unexpected session file version %d, give up",
                  session0.s.header.version);
     goto out;
  }

  state->session_len = session0.s.header.session_len;
  state->session_count = session0.s.header.session_count;

  session_size = state->session_len * state->session_count;
  res = apr_file_trunc(fh, session_size);
  if (res != APR_SUCCESS) {
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "apr_file_trunc(\"%s\") failed", AUTH_OFBA_SESSIONFILE);
     goto out;
  }

  res = apr_mmap_create(&mmap, fh, 0, session_size,
                        APR_MMAP_READ|APR_MMAP_WRITE, conf_pool);
  if (res != APR_SUCCESS) {
     ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                  "apr_mmap_create failed");
     goto out;
  }

  state->sessions = mmap->mm;

  /* copyback session header */
  memcpy(&state->sessions[0], &session0, state->session_len);

  if ((res = apr_global_mutex_lock(state->mtx)) != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_global_mutex_lock failed");
    goto out;
  }
  
  for (i = 1; i < state->session_count; i++) {
    if (auth_ofba_check_session_hash(&state->sessions[i]) != TRUE) {
      auth_ofba_clear_session(&state->sessions[i]);
      corrupted_sessions++;
    }

    session1 = &state->sessions[i].s.v1;
    if (session1->expires && session1->expires < now)
      auth_ofba_clear_session(&state->sessions[i]);
  }

  if (corrupted_sessions)
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 "deleted %d corrupted sessions", corrupted_sessions);

  if ((res = apr_global_mutex_unlock(state->mtx)) != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_global_mutex_lock failed");
    goto out;
  }
  
  for (i = 0; i < AUTH_OFBA_USER_AGENTS_COUNT; i++) {
    state->ofba_user_agents_pat[i] =
      ap_pregcomp(conf_pool, auth_ofba_user_agents_str[i], AP_REG_EXTENDED);
    if (state->ofba_user_agents_pat[i] == NULL) {
      res = EINVAL;
      ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                   "ap_pregcomp(\"%s\" failed",
                   auth_ofba_user_agents_str[i]);
      goto out;
    }
  }

  state->random = apr_random_standard_new(conf_pool);
  do {
    if ((res = apr_generate_random_bytes(seed, sizeof(seed))) != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                   "apr_generate_random_bytes failed");
      goto out;
    }

    apr_random_add_entropy(state->random, seed, sizeof(seed));
    res = apr_random_insecure_ready(state->random);
  } while (res == APR_ENOTENOUGHENTROPY);

  if (res != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_random_insecure_ready failed");
    goto out;
  }

out:
  return res;
}

void *
auth_ofba_server_config(apr_pool_t *p, server_rec *s)
{
  const char *userdata_key = __func__;
  auth_ofba_state_t *state;
  apr_status_t res;

  res = apr_pool_userdata_get((void **)&state, userdata_key, p);
  if (res != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_pool_userdata_get failed");
    return NULL;
  }

  if (state != NULL)
    return state;

  state = apr_palloc(p, sizeof(*state));

  res = apr_pool_userdata_set(state, userdata_key, apr_pool_cleanup_null, p);
  if (res != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, res, s,
                 "apr_pool_userdata_set failed");
    return NULL;
  }

  return state;
}


static void *
auth_ofba_create_dir_config(apr_pool_t *p, char *x)
{
  auth_ofba_conf_t *conf = apr_pcalloc(p, sizeof(*conf));

  conf->enable = 0;
  conf->auth_request_url = NULL;
  conf->auth_success_url = NULL;
  conf->dialog_size = AUTH_OFBA_DIALOG_SIZE_DEFAULT;
  conf->cookie_name = AUTH_OFBA_COOKIE_NAME_DEFAULT;
  conf->session_duration = AUTH_OFBA_SESSION_DURATION_DEFAULT;
  conf->session_autorenew = 0;
  conf->cookie_pat = auth_ofba_cookie_pat(p, conf->cookie_name);

  return conf;
}

char *
auth_ofba_get_cookie(request_rec *r)
{
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  const char *cookie;
  ap_regmatch_t pmatch[3];
  apr_size_t nmatch = sizeof(pmatch) / sizeof(*pmatch);
  char *value = NULL;

  if (conf->cookie_pat == NULL)
    goto out;

  cookie = apr_table_get(r->headers_in, "Cookie");
  if (cookie == NULL) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "No Cookie header");
#endif
    goto out;
  }

  if (ap_regexec(conf->cookie_pat, cookie, nmatch, pmatch, 0) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie match failed 1");
    goto out;
  }

  if (pmatch[2].rm_so == -1) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie match failed 2");
    goto out;
  }

  if ((value = ap_pregsub(r->pool, "$2", cookie, nmatch, pmatch)) == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie match faiiled 3");
    goto out;
  }

out:
  return value;
}

apr_status_t
auth_ofba_set_cookie(request_rec *r, auth_ofba_session1_t *session1)
{
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  char expires[APR_RFC822_DATE_LEN];
  char *cookie;
  apr_status_t res = APR_SUCCESS;
  const char *cookie_opts;

  if (strcmp(ap_http_scheme(r), "https") == 0)
    cookie_opts = "secure;httpOnly";
  else
    cookie_opts = "httpOnly";

  res = apr_rfc822_date(expires, session1->expires);
  if (res != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, "apr_rfc822_date failed");
    goto out;
  }

  cookie = apr_psprintf(r->pool, "%s=%s;version=1;domain=%s;"
                        "path=/;max-age=%lld;expires=%s;%s",
                        conf->cookie_name, session1->cookie, r->hostname,
                        apr_time_sec(session1->expires -apr_time_now()),
                        expires, cookie_opts);

#ifdef DEBUG
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Set-Cookie: %s", cookie);
#endif
  apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);

out:
  return res;
}

static auth_ofba_session1_t *
auth_ofba_set_session(request_rec *r)
{
  auth_ofba_state_t *state = ap_get_module_config(r->server->module_config,
                                                  &auth_ofba_module);
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  auth_ofba_session1_t *rs1p = NULL;
  auth_ofba_session1_t *session1 = NULL;
  char randombin[sizeof(session1->cookie) / 2];
  int i;
  apr_time_t now = apr_time_now();
  apr_time_t older = 0;
  int corrupted_sessions = 0;
  int older_i = 0;
  apr_status_t res = APR_SUCCESS;

  if ((res = apr_global_mutex_lock(state->mtx)) != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
                  "apr_global_mutex_lock failed");
    goto out;
  }
  
  for (i = 1; i < state->session_count ; i++) {
    if (auth_ofba_check_session_hash(&state->sessions[i]) != TRUE) {
      auth_ofba_clear_session(&state->sessions[i]);
      corrupted_sessions++;
    } 

    session1 = &state->sessions[i].s.v1;

    if (session1->expires && session1->expires < now)
      auth_ofba_clear_session(&state->sessions[i]);

    if (session1->cookie[0] == '\0')
      break;

    if (session1->expires > older) {
      older = session1->expires;
      older_i = i;
    }
  }

  if (corrupted_sessions)
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "deleted %d corrupted sessions", corrupted_sessions);

  if (i == state->session_count) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_ENOSPC, r,
                  "Maximum session count reached");
    i = older_i;
  }

  res = apr_random_insecure_bytes(state->random, randombin, sizeof(randombin));
  if (res != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
                  "apr_random_insecure_bytes failed");
    goto out;
  }

  session1 = &state->sessions[i].s.v1;

  ap_bin2hex(randombin, sizeof(session1->cookie), session1->cookie);
  session1->cookie[sizeof(session1->cookie) - 1] = '\0';

  (void)strncpy(session1->user, r->user, sizeof(session1->user));
  (void)strncpy(session1->ap_auth_type, r->ap_auth_type,
                sizeof(session1->ap_auth_type));

  session1->expires = now + apr_time_from_sec(conf->session_duration);

  auth_ofba_set_session_hash(&state->sessions[i]);

#ifdef DEBUG
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "New session %s for %s", session1->cookie, session1->user);
#endif

  /* For safe access after mutex unlock */
  rs1p = apr_pmemdup(r->pool, session1, sizeof(*session1));

out:
  if ((res = apr_global_mutex_unlock(state->mtx)) != APR_SUCCESS)
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
                  "apr_global_mutex_unlock failed");
  
  return rs1p;
}

static auth_ofba_session1_t *
auth_ofba_get_session(request_rec *r)
{
  auth_ofba_state_t *state = ap_get_module_config(r->server->module_config,
                                                  &auth_ofba_module);
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  char *cookie;
  auth_ofba_session1_t *session1 = NULL;
  auth_ofba_session1_t *rs1p = NULL;
  int i;
  int corrupted_sessions = 0;
  apr_time_t now = apr_time_now();
  apr_status_t res = APR_SUCCESS;

  if ((cookie = auth_ofba_get_cookie(r)) == NULL) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_ENOENT, r,
                  "Missing %s cookie", conf->cookie_name);
#endif
    goto out_nolock;
  }

  if ((res = apr_global_mutex_lock(state->mtx)) != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
                  "apr_global_mutex_lock failed");
    goto out;
  }
  
  for (i = 1; i < state->session_count; i++) {
    if (auth_ofba_check_session_hash(&state->sessions[i]) != TRUE) {
      auth_ofba_clear_session(&state->sessions[i]);
      corrupted_sessions++;
    }

    session1 = &state->sessions[i].s.v1;

    if (session1->expires && session1->expires < now)
      auth_ofba_clear_session(&state->sessions[i]);

    if (strncmp(session1->cookie, cookie,
                sizeof(session1->cookie)) == 0)
      break;
  }

  if (corrupted_sessions)
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "deleted %d corrupted sessions", corrupted_sessions);

  if (i == state->session_count) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_ENOENT, r,
                  "Session %s not found", cookie);
#endif
    cookie = apr_psprintf(r->pool, "%s=;version=1;domain=%s;path=/;"
                        "max-age=0;expires=Thu,  1 Jan 1970 00:00:00 GMT;"
                        "secure;httpOnly",
                        conf->cookie_name, r->hostname);

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Set-Cookie: %s", cookie);
#endif
    apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);
      
    goto out;
  }

  if (conf->session_autorenew) {
    session1->expires = now + apr_time_from_sec(conf->session_duration);
    auth_ofba_set_session_hash(&state->sessions[i]);
  }

  /* For safe access after mutex unlock */
  rs1p = apr_pmemdup(r->pool, session1, sizeof(*session1));

out:
  if ((res = apr_global_mutex_unlock(state->mtx)) != APR_SUCCESS)
    ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
                  "apr_global_mutex_unlock failed");
  
out_nolock:
  return rs1p;
}

static int
auth_ofba_capable(request_rec *r)
{
  auth_ofba_state_t *state = ap_get_module_config(r->server->module_config,
                                                  &auth_ofba_module);
  const char *user_agent;
  const char *ofba_accepted;
  int ofba_capable = FALSE;
  int i;

  /* 
   * MS-OFBA quires that we only send OFBA authentication header 
   * on OPTIONS method, but sending it for all methods seems to 
   * help for sessions renewal.
   */
#if 0
  if (r->method_number != M_OPTIONS)
    goto out;
#endif

  /* 
   * Let the administrator blacklist some User-Agent 
   * through the no-ofba environment variable.
   */
  if (apr_table_get(r->subprocess_env, "no-ofba"))
    goto out;

  user_agent = apr_table_get(r->headers_in, "User-Agent");
  if (user_agent != NULL) {
    for (i = 0; i < AUTH_OFBA_USER_AGENTS_COUNT; i++) {
      if (ap_regexec(state->ofba_user_agents_pat[i],
                     user_agent, 0, NULL, 0) == 0) {
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "OFBA capable User-Agent \"%s\"", user_agent);
#endif
        ofba_capable = TRUE;
      }
    }

#ifdef DEBUG
    if (!ofba_capable)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "User-Agent \"%s\" is not OFBA capable", user_agent);
#endif

  }

  ofba_accepted = apr_table_get(r->headers_in, "X-Forms_Based_Auth_Accepted");
  if (ofba_accepted != NULL && strcasecmp(ofba_accepted, "t") == 0) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "X-Forms_Based_Auth_Accepted=t received");
#endif
    ofba_capable = TRUE;
  }

  if (ofba_accepted != NULL && strcasecmp(ofba_accepted, "f") == 0) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "X-Forms_Based_Auth_Accepted=f received");
#endif
    ofba_capable = FALSE;
  }

out:
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "is OFBA capable: %s", ofba_capable ? "yes" : "no");
#endif
  return ofba_capable;
}

static apr_port_t
auth_ofba_port_from_scheme(const char *scheme)
{
  apr_port_t port;

  if (strcmp(scheme, "https") == 0)
    port = APR_URI_HTTPS_DEFAULT_PORT;
  else
    port = APR_URI_HTTP_DEFAULT_PORT;

  return port;
}

static const char *
auth_ofba_url_from_path(request_rec *r, const char *path)
{
  const char *scheme;
  apr_port_t port;
  char *port_str;

  if (path[0] != '/')
    return path;

  scheme = ap_http_scheme(r);
  port = auth_ofba_port_from_scheme(scheme);
  if (r->server->addrs->host_port != port)
    port_str = apr_psprintf(r->pool, ":%d", r->server->addrs->host_port);
  else
    port_str = "";

  return apr_pstrcat(r->pool, scheme, "://", r->hostname,
                     port_str, path, NULL);
}

static const char *
auth_ofba_success_url(request_rec *r)
{
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  return auth_ofba_url_from_path(r, conf->auth_success_url);
}

static char *
auth_ofba_required_path(request_rec *r, const char *realm)
{
  char *ofba_required_url;
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);

  ofba_required_url = apr_pstrcat(r->pool, conf->auth_request_url,
      (strchr(conf->auth_request_url, '&') == NULL) ? "?": "&",
      "version=1.0",
      "&action=signin",
      "&realm=", apr_pescape_urlencoded(r->pool, realm),
      "&returnurl=", apr_pescape_urlencoded(r->pool, 
                                            auth_ofba_success_url(r)),
      NULL);

  return ofba_required_url;
}

static const char *
auth_ofba_required_url(request_rec *r, const char *realm)
{
  return auth_ofba_url_from_path(r, auth_ofba_required_path(r, realm));
}

static int
auth_ofba_url_match(request_rec *r, char *urlstr)
{ 
  int match = FALSE;
  const char *req_url;

  if (urlstr[0] == '/')
    req_url = r->unparsed_uri;
  else
    req_url = auth_ofba_url_from_path(r, r->unparsed_uri);

  if (strcmp(req_url, urlstr) == 0)
      match = TRUE;

  return match;
}

static int
auth_ofba_authenticate_user(request_rec *r)
{
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  auth_ofba_session1_t *session1;
  const char *realm;

  if (!conf->enable)
    return DECLINED;

  if (conf->auth_request_url == NULL || conf->auth_success_url == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, r,
                  "AuthOFBAenable requires AuthOFBAauthRequestURL "
                  "and AuthOFBAauthSuccessURL");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  if ((session1 = auth_ofba_get_session(r)) != NULL) {
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "got OFBA session cookie %s for %s", 
                  session1->cookie, session1->user); 
#endif

    r->user = session1->user;
    r->ap_auth_type = session1->ap_auth_type;
    auth_ofba_set_cookie(r, session1);
    return OK;
  }

  if (!auth_ofba_capable(r))
    return DECLINED;

  if ((realm = ap_auth_name(r)) == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, r,
                  "AuthOFBAenable requires AuthName");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  apr_table_set(r->err_headers_out, "X-Forms_Based_Auth_Required",
                auth_ofba_required_url(r, realm));
  apr_table_set(r->err_headers_out, "X-Forms_Based_Auth_Return_Url",
                auth_ofba_success_url(r));
  apr_table_set(r->err_headers_out, "X-Forms_Based_Auth_Dialog_Size",
                conf->dialog_size);

  return HTTP_FORBIDDEN;
}

static int
auth_ofba_authenticated(request_rec *r)
{
  auth_ofba_conf_t *conf = ap_get_module_config(r->per_dir_config,
                                                &auth_ofba_module);
  const char *current_auth = ap_auth_type(r);
  auth_ofba_session1_t *session1;
  int status = OK;

  if (!conf->enable)
    return DECLINED;

  if ((session1 = auth_ofba_get_session(r)) != NULL)
    goto out;

#ifdef DEBUG
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "user = \"%s\" curent_auth = \"%s\"",
                r->user, current_auth);
#endif

  if (r->user != NULL && current_auth != NULL) {
    const char *realm;

    /*
     * We send an OFBA cookie for authenticated user
     * reaching success URL
     */
    if (auth_ofba_url_match(r, conf->auth_success_url)) {
      if ((session1 = auth_ofba_set_session(r)) != NULL)
        auth_ofba_set_cookie(r, session1);
      goto out;
    }

    if ((realm = ap_auth_name(r)) == NULL) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, r,
                    "AuthOFBAenable requires AuthName");
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Already authenticated users can short-circuit
     * the authentication form
     */
    if (auth_ofba_url_match(r, auth_ofba_required_path(r, realm))) {
      apr_table_addn(r->err_headers_out, "Location", auth_ofba_success_url(r));
      status = HTTP_MOVED_TEMPORARILY;
      goto out;
    }
  }

out:
  return status;
}

static void
register_hooks(apr_pool_t *p)
{
  ap_hook_post_config(auth_ofba_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_access_checker(auth_ofba_authenticate_user, NULL, NULL, 
                         APR_HOOK_FIRST);
  ap_hook_fixups(auth_ofba_authenticated, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(auth_ofba) =
{
  STANDARD20_MODULE_STUFF,
  auth_ofba_create_dir_config,
  NULL,
  auth_ofba_server_config,
  NULL,
  auth_ofba_cmds,        /* command apr_table_t */
  register_hooks         /* register hooks */
};
