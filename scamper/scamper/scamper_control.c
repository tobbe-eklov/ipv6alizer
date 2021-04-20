/*
 * scamper_control.c
 *
 * $Id: scamper_control.c,v 1.161.2.1 2015/12/06 08:06:42 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2014      Matthew Luckie
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_control.c,v 1.161.2.1 2015/12/06 08:06:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_control.h"
#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_sources.h"
#include "scamper_source_file.h"
#include "scamper_source_control.h"
#include "scamper_source_tsps.h"
#include "scamper_privsep.h"
#include "mjl_list.h"
#include "utils.h"

/* hack to deal with lss clear */
#include "scamper_list.h"
#include "trace/scamper_trace_do.h"

/*
 * client_obj_t
 *
 */
typedef struct client_obj
{
  void   *data;
  size_t  len;
} client_obj_t;

/*
 * client_txt_t
 *
 * string and length, not including null character
 */
typedef struct client_txt
{
  char   *str;
  size_t  len;
} client_txt_t;

/*
 * client_t
 *
 * this structure records state required to manage a client connected to
 * scamper via a control socket.
 */
typedef struct client
{
  /* address of client connected */
  struct sockaddr    *sa;

  /* node for this client in the list of connected clients */
  dlist_node_t       *node;

  /*
   * fdn: file descriptor managed by scamper for the client fd.
   * lp:  interface to read a line at a time from the client.
   * wb:  interface to handle non-blocking writes to the scamper_fd.
   * txt: text strings to pass over socket when able to.
   */
  scamper_fd_t       *fdn;
  scamper_linepoll_t *lp;
  scamper_writebuf_t *wb;
  slist_t            *txt;

  /* pointer returned by the source observe code */
  void               *observe;

  /* the mode the client is in */
  int                 mode;

  /*
   * the next set of variables are used when the client's connection is used
   * to supply tasks, and is also used to send the results back.
   *
   *  source:     the source allocated to the control socket.
   *  sof:        scamper file wrapper for accessing the warts code.
   *  sof_objs:   warts objects waiting to be written.
   *  sof_obj:    current object partially written over socket.
   *  sof_off:    offset into current object being written.
   */
  scamper_source_t   *source;
  scamper_outfile_t  *sof;
  slist_t            *sof_objs;
  client_obj_t       *sof_obj;
  size_t              sof_off;
} client_t;

#define CLIENT_MODE_INTERACTIVE 0
#define CLIENT_MODE_ATTACHED    1
#define CLIENT_MODE_FLUSH       2

typedef struct command
{
  char *word;
  int (*handler)(client_t *client, char *param);
} command_t;

typedef struct param
{
  char  *word;
  char **var;
} param_t;

/*
 * client_list: a doubly linked list of connected clients
 * fd: a scamper_fd struct that contains callback details
 */
static dlist_t      *client_list  = NULL;
static scamper_fd_t *fdn          = NULL;

#if defined(AF_UNIX) && !defined(_WIN32)
static char         *ctrl_unix_name = NULL;
static int           ctrl_unix_num  = 0;
#endif

static int command_handler(command_t *handler, int cnt, client_t *client,
			   char *word, char *param, int *retval)
{
  int i;

  for(i=0; i<cnt; i++)
    {
      if(strcasecmp(handler[i].word, word) == 0)
	{
	  *retval = handler[i].handler(client, param);
	  return 0;
	}
    }

  return -1;
}

/*
 * params_get
 *
 * go through the line and get parameters out, returning the start of
 * each parameter in the words array.
 */
static int params_get(char *line, char **words, int *count)
{
  int i, w;

  i = 0; /* first character in the parameters */
  w = 0; /* first word to be read */

  /* if there is no line, there can't be any parameters */
  if(line == NULL)
    {
      *count = 0;
      return 0;
    }

  while(line[i] != '\0' && w < *count)
    {
      if(line[i] == '"')
	{
	  /* the start of the parameter is past the opening quote */
	  words[w++] = &line[++i];

	  /* until we get to the end of the param / string, keep hunting */
	  while(line[i] != '"' && line[i] != '\0') i++;

	  /* did not get the closing double-quote */
	  if(line[i] == '\0') return -1;
	}
      else
	{
	  /* the start of the word is here, skip past this opening char */
	  words[w++] = &line[i++];

	  /* until we get to the end of the word / string, keep hunting */
	  while(line[i] != ' ' && line[i] != '\0') i++;

	  if(line[i] == '\0') break;

	}

      /* null terminate the word, skip towards the next word */
      line[i++] = '\0';

      /* skip to the next word */
      while(line[i] == ' ' && line[i] != '\0') i++;
    }

  if(line[i] == '\0')
    {
      *count = w;
      return 0;
    }

  return -1;
}

static char *switch_tostr(char *buf, size_t len, int val)
{
  if(val == 0)
    {
      strncpy(buf, "off", len);
    }
  else
    {
      strncpy(buf, "on", len);
    }

  return buf;
}

static void client_obj_free(client_obj_t *obj)
{
  if(obj == NULL)
    return;
  if(obj->data != NULL)
    free(obj->data);
  free(obj);
  return;
}

static void client_txt_free(client_txt_t *txt)
{
  if(txt == NULL)
    return;
  if(txt->str != NULL)
    free(txt->str);
  free(txt);
  return;
}

static char *client_sockaddr_tostr(client_t *client, char *buf, size_t len)
{
  /*
   * if the socket is a unix domain socket, make something up that
   * is sensible.
   */
#if defined(AF_UNIX) && !defined(_WIN32)
  if(client->sa->sa_family == AF_UNIX)
    {
      if(ctrl_unix_name == NULL)
	return NULL;
      snprintf(buf, len, "%s:%d", ctrl_unix_name, ctrl_unix_num++);
      return buf;
    }
#endif

  /*
   * get the name of the connected socket, which is used to name the
   * source and the outfile
   */
  if(sockaddr_tostr(client->sa, buf, len) == NULL)
    {
      printerror(0, NULL, __func__, "could not decipher client sockaddr");
      return NULL;
    }

  return buf;
}

/*
 * client_free
 *
 * free up client state for the socket handle.
 */
static void client_free(client_t *client)
{
  client_obj_t *obj;
  client_txt_t *txt;
  int fd;

  if(client == NULL) return;

  /* if there's an open socket here, close it now */
  if(client->fdn != NULL)
    {
      fd = scamper_fd_fd_get(client->fdn);
      scamper_fd_free(client->fdn);
      client->fdn = NULL;

      shutdown(fd, SHUT_RDWR);
      close(fd);
    }

  /* remove the linepoll structure */
  if(client->lp != NULL) scamper_linepoll_free(client->lp, 0);
  client->lp = NULL;

  /* remove the writebuf structure */
  if(client->wb != NULL) scamper_writebuf_free(client->wb);
  client->wb = NULL;

  /* remove the client from the list of clients */
  if(client->node != NULL) dlist_node_pop(client_list, client->node);
  client->node = NULL;

  /* if we made a copy of the client's sockaddr, free it now */
  if(client->sa != NULL) free(client->sa);
  client->sa = NULL;

  /* if we are monitoring source events, unobserve */
  if(client->observe != NULL) scamper_sources_unobserve(client->observe);
  client->observe = NULL;

  /* make sure the source is empty before freeing */
  if(client->source != NULL)
    {
      scamper_source_abandon(client->source);
      scamper_source_free(client->source);
      client->source = NULL;
    }

  /* cleanup the output file */
  if(client->sof != NULL) scamper_outfile_free(client->sof);
  client->sof = NULL;

  if(client->sof_objs != NULL)
    {
      while((obj = slist_head_pop(client->sof_objs)) != NULL)
	client_obj_free(obj);
      slist_free(client->sof_objs);
      client->sof_objs = NULL;
    }

  if(client->txt != NULL)
    {
      while((txt = slist_head_pop(client->txt)) != NULL)
	client_txt_free(txt);
      slist_free(client->txt);
      client->txt = NULL;
    }

  free(client);
  return;
}

static int client_send(client_t *client, char *fs, ...)
{
  char msg[512], *str = NULL;
  client_txt_t *t = NULL;
  size_t len, size = sizeof(msg) - 1;
  va_list ap;
  int ret;

  va_start(ap, fs);
  ret = len = vsnprintf(msg, sizeof(msg), fs, ap);
  if(len < size)
    {
      va_end(ap);
      str = msg;
    }
  else
    {
      if((str = malloc_zero((size_t)(len+1))) == NULL)
	{
	  va_end(ap);
	  goto err;
	}
      vsnprintf(str, len+1, fs, ap);
      va_end(ap);
    }
  str[len++] = '\n';

  if(str == msg && (str = memdup(msg, len)) == NULL)
    goto err;
  if((t = malloc_zero(sizeof(client_txt_t))) == NULL)
    goto err;
  if(slist_tail_push(client->txt, t) == NULL)
    goto err;
  t->str = str;
  t->len = len;
  scamper_fd_write_unpause(client->fdn);

  return ret;

 err:
  if(str != NULL && str != msg)
    free(str);
  return -1;
}

/*
 * param_handler
 *
 */
static int param_handler(param_t *handler, int cnt, client_t *client,
			 char *param, char *next)
{
  int i;

  for(i=0; i<cnt; i++)
    {
      /* skip until we find the handler for this parameter */
      if(strcasecmp(handler[i].word, param) != 0)
	{
	  continue;
	}

      /* already seen this parameter specified */
      if(*handler[i].var != NULL)
	{
	  scamper_debug(__func__, "parameter '%s' already specified", param);
	  return -1;
	}

      /* the parameter passed does not have a value to go with it */
      if(next == NULL)
	{
	  scamper_debug(__func__, "parameter '%s' requires argument", param);
	  return -1;
	}

      /* got the parameter */
      *handler[i].var = next;
      return 0;
    }

  return -1;
}

static int set_long(client_t *client, char *buf, char *name,
		    int (*setfunc)(int), int min, int max)
{
  long l;
  char *err;

  if(buf == NULL)
    {
      client_send(client, "ERR set %s requires argument", name);
      scamper_debug(__func__, "set %s required argument", name);
      return -1;
    }

  /*
   * null terminate this word.  discard the return value, we don't care
   * about any further words.
   */
  string_nextword(buf);

  /* make sure the argument is an integer argument */
  if(string_isnumber(buf) == 0)
    {
      client_send(client, "ERR set %s argument is not an integer", name);
      scamper_debug(__func__, "set %s argument is not an integer", name);
      return -1;
    }

  /* convert the argument to a long.  catch any error */
  if(string_tolong(buf, &l) != 0)
    {
      err = strerror(errno);
      client_send(client, "ERR could not convert %s to long: %s", buf, err);
      scamper_debug(__func__, "could not convert %s to long: %s", buf, err);
      return -1;
    }

  if(setfunc(l) == -1)
    {
      client_send(client, "ERR %s: %d out of range (%d, %d)", name,l,min,max);
      scamper_debug(__func__, "%s: %d out of range (%d, %d)", name,l,min,max);
      return -1;
    }

  client_send(client, "OK %s %d", name, l);
  return 0;
}

static int get_switch(client_t *client, char *name, char *buf, long *l)
{
  if(strcasecmp(buf, "on") == 0)
    {
      *l = 1;
    }
  else if(strcasecmp(buf, "off") == 0)
    {
      *l = 0;
    }
  else
    {
      client_send(client, "ERR %s <on|off>", name);
      return -1;
    }

  return 0;
}

static char *source_tostr(char *str, const size_t len,
			  const scamper_source_t *source)
{
  char descr[256], outfile[256], type[512], sw1[4];
  int i;

  /* format type-specific data */
  switch((i = scamper_source_gettype(source)))
    {
    case SCAMPER_SOURCE_TYPE_FILE:
      snprintf(type, sizeof(type),
	       "type 'file' file '%s' cycles %d autoreload %s",
	       scamper_source_file_getfilename(source),
	       scamper_source_file_getcycles(source),
	       switch_tostr(sw1, sizeof(sw1),
			    scamper_source_file_getautoreload(source)));
      break;

    case SCAMPER_SOURCE_TYPE_CMDLINE:
      snprintf(type, sizeof(type), "type 'cmdline'");
      break;

    case SCAMPER_SOURCE_TYPE_CONTROL:
      snprintf(type, sizeof(type), "type 'control'");
      break;

    case SCAMPER_SOURCE_TYPE_TSPS:
      snprintf(type, sizeof(type), "type 'tsps' file '%s'",
	       scamper_source_tsps_getfilename(source));
      break;

    default:
      printerror(0, NULL, __func__, "unknown source type %d", i);
      return NULL;
    }

  /* if there is a description for the source, then format it in */
  if(scamper_source_getdescr(source) != NULL)
    {
      snprintf(descr, sizeof(descr),
	       " descr '%s'", scamper_source_getdescr(source));
    }
  else descr[0] = '\0';

  /* outfile */
  if(scamper_source_getoutfile(source) != NULL)
    {
      snprintf(outfile, sizeof(outfile), " outfile '%s'",
	       scamper_source_getoutfile(source));
    }
  else outfile[0] = '\0';

  snprintf(str, len,
	   "name '%s'%s list_id %u cycle_id %u priority %u%s %s",
	   scamper_source_getname(source),
	   descr,
	   scamper_source_getlistid(source),
	   scamper_source_getcycleid(source),
	   scamper_source_getpriority(source),
	   outfile,
	   type);

  return str;
}

/*
 * client_data_send
 *
 * take a data object and put it on the list of data objects to send.
 */
static int client_data_send(void *param, const void *vdata, size_t len)
{
  client_t *client = param;
  client_obj_t *obj = NULL;
  const uint8_t *data = vdata;

  assert(len >= 8);

  if(client->wb == NULL || client->sof_objs == NULL)
    return 0;

  if(data[0] != 0x12 || data[1] != 0x05)
    {
      printerror(0, NULL, __func__,
		 "lost synchronisation: %02x%02x %02x%02x %02x%02x%02x%02x",
		 data[0], data[1], data[2], data[3], data[4], data[5],
		 data[6], data[7]);
      goto err;
    }

  /* cycle end */
  if(data[2] == 0 && data[3] == 0x04)
    client->mode = CLIENT_MODE_FLUSH;

  if((obj = malloc_zero(sizeof(client_obj_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc obj");
      goto err;
    }

  if((obj->data = memdup(vdata, len)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not memdup");
      goto err;
    }
  obj->len = len;

  if(slist_tail_push(client->sof_objs, obj) == NULL)
    {
      printerror(errno, strerror, __func__, "could not push obj onto list");
      goto err;
    }
  obj = NULL;

  scamper_fd_write_unpause(client->fdn);
  return 0;

 err:
  client_obj_free(obj);
  return -1;
}

static void client_signalmore(void *param)
{
  client_t *client = (client_t *)param;
  client_send(client, "MORE");
  return;
}

static char *client_tostr(void *param, char *buf, size_t len)
{
  client_t *client = param;
  size_t off = 0;

  buf[0] = '\0';
  if(client->fdn != NULL)
    string_concat(buf, len, &off, "fd %d", scamper_fd_fd_get(client->fdn));

  return buf;
}

/*
 * command_attach
 *
 * the client wants to receive data from measurements over their control
 * socket connection.
 *
 */
#ifndef _WIN32
static int command_attach(client_t *client, char *buf)
{
  scamper_source_params_t ssp;
  scamper_file_t *sf;
  char sab[128];
  long priority = 1;
  char *priority_str = NULL, *params[2], *next;
  int i, cnt = sizeof(params) / sizeof(char *);
  param_t handlers[] = {
    {"priority", &priority_str},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);

  if(params_get(buf, params, &cnt) != 0)
    {
      client_send(client, "ERR could not params_get");
      return 0;
    }
  for(i=0; i<cnt; i+=2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;
      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client,"ERR command attach param '%s' failed",params[i]);
	  return 0;
	}
    }

  if(priority_str != NULL && (string_tolong(priority_str, &priority) != 0 ||
			      priority < 1 || priority > 100000))
    {
      client_send(client, "ERR invalid priority");
      return 0;
    }

  client_sockaddr_tostr(client, sab, sizeof(sab));

  if((client->sof_objs = slist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc objs list");
      goto err;
    }

  if((client->sof = scamper_outfile_opennull(sab)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc outfile");
      goto err;
    }
  sf = scamper_outfile_getfile(client->sof);
  scamper_file_setwritefunc(sf, client, client_data_send);

  /* create the source */
  memset(&ssp, 0, sizeof(ssp));
  ssp.list_id    = 0;
  ssp.cycle_id   = 1;
  ssp.priority   = priority;
  ssp.name       = sab;
  ssp.sof        = client->sof;
  if((client->source = scamper_source_control_alloc(&ssp, client_signalmore,
						    client_tostr,
						    client)) == NULL)
    {
      printerror(errno, strerror, __func__,
		 "could not allocate source '%s'", sab);
      goto err;
    }

  /* put the source into rotation */
  if(scamper_sources_add(client->source) != 0)
    {
      printerror(errno, strerror, __func__,
		 "could not add source '%s' to rotation", sab);
      goto err;
    }

  client->mode = CLIENT_MODE_ATTACHED;
  client_send(client, "OK");
  return 0;

 err:
  client_send(client, "ERR internal error");
  client_free(client);
  return 0;
}
#endif

static int command_lss_clear(client_t *client, char *buf)
{
  if(buf == NULL)
    {
      client_send(client, "ERR usage: lss-clear [lss-name]");
      return 0;
    }
  string_nextword(buf);

  if(scamper_do_trace_dtree_lss_clear(buf) != 0)
    {
      return client_send(client, "ERR lss-clear %s failed", buf);
    }

  return client_send(client, "OK lss-clear %s", buf);
}

static int command_exit(client_t *client, char *buf)
{
  client_free(client);
  return 0;
}

static int command_get_command(client_t *client, char *buf)
{
  const char *command = scamper_command_get();
  if(command == NULL)
    {
      return client_send(client, "OK null command");
    }
  return client_send(client, "OK command %s", command);
}

static int command_get_monitorname(client_t *client, char *buf)
{
  const char *monitorname = scamper_monitorname_get();
  if(monitorname == NULL)
    {
      return client_send(client, "OK null monitorname");
    }
  return client_send(client, "OK monitorname %s", monitorname);
}

static int command_get_pid(client_t *client, char *buf)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif
  return client_send(client, "OK pid %d", pid);
}

static int command_get_pps(client_t *client, char *buf)
{
  int pps = scamper_pps_get();
  return client_send(client, "OK pps %d", pps);
}

static int command_get_version(client_t *client, char *buf)
{
  return client_send(client, "OK version " SCAMPER_VERSION);
}

static int command_get_window(client_t *client, char *buf)
{
  return client_send(client, "OK window %d/%d",
		     scamper_queue_windowcount(), scamper_window_get());
}

static int command_get(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"command",     command_get_command},
    {"monitorname", command_get_monitorname},
    {"pid",         command_get_pid},
    {"pps",         command_get_pps},
    {"version",     command_get_version},
    {"window",      command_get_window},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: get "
	  "[command | monitorname | pid | pps | version | window]");
      return 0;
    }

  if(command_handler(handlers, handler_cnt, client, buf, NULL, &ret) == -1)
    {
      client_send(client, "ERR unhandled get command '%s'", buf);
      return 0;
    }

  return 0;
}

static int command_help(client_t *client, char *buf)
{
  client_send(client, "ERR XXX: todo");
  return 0;
}

static void observe_source_event_add(const scamper_source_event_t *sse,
				     char *buf, const size_t len)
{
  buf[0] = 'a'; buf[1] = 'd'; buf[2] = 'd'; buf[3] = ' ';
  source_tostr(buf+4, len-4, sse->source);
  return;
}

static void observe_source_event_update(const scamper_source_event_t *sse,
					char *buf, const size_t len)
{
  char autoreload[16];
  char cycles[16];
  char priority[24];

  /* autoreload */
  if(sse->sse_update_flags & 0x01)
    snprintf(autoreload, sizeof(autoreload),
	     " autoreload %d", sse->sse_update_autoreload);
  else autoreload[0] = '\0';

  /* cycles */
  if(sse->sse_update_flags & 0x02)
    snprintf(cycles, sizeof(cycles),
	     " cycles %d", sse->sse_update_cycles);
  else cycles[0] = '\0';

  /* priority */
  if(sse->sse_update_flags & 0x04)
    snprintf(priority, sizeof(priority),
	     " priority %d", sse->sse_update_priority);
  else priority[0] = '\0';

  snprintf(buf, len, "update '%s'%s%s%s",
	   scamper_source_getname(sse->source),
	   autoreload, cycles, priority);
  return;
}

static void observe_source_event_cycle(const scamper_source_event_t *sse,
				       char *buf, const size_t len)
{
  snprintf(buf, len, "cycle '%s' id %d",
	   scamper_source_getname(sse->source),
	   sse->sse_cycle_cycle_id);
  return;
}

static void observe_source_event_delete(const scamper_source_event_t *sse,
					char *buf, const size_t len)
{
  snprintf(buf, len, "delete '%s'",
	   scamper_source_getname(sse->source));
  return;
}

static void observe_source_event_finish(const scamper_source_event_t *sse,
					char *buf, const size_t len)
{
  snprintf(buf, len, "finish '%s'",
	   scamper_source_getname(sse->source));
  return;
}

/*
 * command_observe_source_cb
 *
 * this function is a callback that is used whenever some event occurs
 * with a source.
 */
static void command_observe_source_cb(const scamper_source_event_t *sse,
				      void *param)
{
  static void (* const func[])(const scamper_source_event_t *,
			       char *, const size_t) =
  {
    observe_source_event_add,
    observe_source_event_update,
    observe_source_event_cycle,
    observe_source_event_delete,
    observe_source_event_finish,
  };
  client_t *client = (client_t *)param;
  char buf[512];
  size_t len;

  if(sse->event < 0x01 || sse->event > 0x05)
    {
      return;
    }

  snprintf(buf, sizeof(buf), "EVENT %u source ", (uint32_t)sse->sec);
  len = strlen(buf);

  func[sse->event-1](sse, buf + len, sizeof(buf)-len);
  client_send(client, "%s", buf);

  return;
}

static int command_observe(client_t *client, char *buf)
{
  if(buf == NULL)
    {
      client_send(client, "ERR usage: observe [sources]");
      return 0;
    }
  string_nextword(buf);

  if(strcasecmp(buf, "sources") != 0)
    {
      client_send(client, "ERR usage: observe [sources]");
      return 0;
    }

  client->observe = scamper_sources_observe(command_observe_source_cb, client);
  if(client->observe == NULL)
    {
      printerror(errno, strerror, __func__, "could not observe sources");
      client_send(client, "ERR could not observe");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

/*
 * command_outfile_close
 *
 * outfile close <alias>
 */
static int command_outfile_close(client_t *client, char *buf)
{
  scamper_outfile_t *sof;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: outfile close <alias>");
      return 0;
    }
  string_nextword(buf);

  if((sof = scamper_outfiles_get(buf)) == NULL)
    {
      client_send(client, "ERR unknown outfile '%s'", buf);
      return 0;
    }

  if(scamper_outfile_close(sof) == -1)
    {
      client_send(client, "ERR could not drop outfile: refcnt %d",
		  scamper_outfile_getrefcnt(sof));
      return 0;
    }

  client_send(client, "OK");
  return 0;
}

static int outfile_foreach(void *param, scamper_outfile_t *sof)
{
  client_t *client = (client_t *)param;
  scamper_file_t *sf = scamper_outfile_getfile(sof);
  char *filename = scamper_file_getfilename(sf);

  if(filename == NULL) filename = "(null)";

  client_send(client, "INFO '%s' file '%s' refcnt %d",
	      scamper_outfile_getname(sof),
	      filename,
	      scamper_outfile_getrefcnt(sof));
  return 0;
}

/*
 * command_outfile_list
 *
 * outfile list
 */
static int command_outfile_list(client_t *client, char *buf)
{
  scamper_outfiles_foreach(client, outfile_foreach);
  client_send(client, "OK");
  return 0;
}

/*
 * command_outfile_open
 *
 * outfile open name <alias> mode <truncate|append> file <path>
 */
static int command_outfile_open(client_t *client, char *buf)
{
  char *params[24];
  int   i, cnt = sizeof(params) / sizeof(char *);
  char *file = NULL, *mode = NULL, *name = NULL;
  char *next;
  param_t handlers[] = {
    {"file", &file},
    {"mode", &mode},
    {"name", &name},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR params_get failed");
      return -1;
    }

  for(i=0; i<cnt; i += 2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;

      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client, "ERR param '%s' failed", params[i]);
	  return -1;
	}
    }

  if(name == NULL || file == NULL || mode == NULL)
    {
      client_send(client,
		  "ERR usage: outfile open name <alias> file <path> "
		  "mode <truncate|append>");
      return -1;
    }

  if(strcasecmp(mode, "truncate") != 0 && strcasecmp(mode, "append") != 0)
    {
      client_send(client, "ERR mode must be truncate or append");
      return -1;
    }

  if(scamper_outfile_open(name, file, mode) == NULL)
    {
      client_send(client, "ERR could not add outfile");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

/*
 * outfile socket
 *
 * outfile socket name <alias> type <type>
 */
static int command_outfile_socket(client_t *client, char *buf)
{
  char *params[4], *next;
  int   i, fd;
  int   cnt = sizeof(params) / sizeof(char *);
  char *name = NULL, *type = NULL;
  param_t handlers[] = {
    {"name", &name},
    {"type", &type},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR source add params_get failed");
      return -1;
    }

  for(i=0; i<cnt; i += 2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;

      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client, "ERR source add param '%s' failed", params[i]);
	  return -1;
	}
    }

  if(name == NULL || type == NULL)
    {
      client_send(client, "ERR usage outfile socket name <alias> type <type>");
      return 0;
    }

  if(scamper_outfiles_get(name) != NULL)
    {
      client_send(client, "ERR outfile '%s' already exists", name);
      return 0;
    }

  fd = scamper_fd_fd_get(client->fdn);
  if(scamper_outfile_openfd(name, fd, type) == NULL)
    {
      client_send(client, "ERR could not turn socket into outfile");
      return 0;
    }

  client_send(client, "OK");
  return 0;
}

/*
 * outfile swap
 *
 * swap <alias 1> <alias 2>
 */
static int command_outfile_swap(client_t *client, char *buf)
{
  scamper_outfile_t *a, *b;
  char *files[2];
  int   cnt = 2;

  if(params_get(buf, files, &cnt) == -1)
    {
      client_send(client, "ERR params_get failed");
      return -1;
    }

  if(cnt != 2)
    {
      client_send(client, "ERR usage outfile swap <alias 1> <alias 2>");
      return -1;
    }

  if((a = scamper_outfiles_get(files[0])) == NULL)
    {
      client_send(client, "ERR unknown outfile '%s'", a);
      return -1;
    }

  if((b = scamper_outfiles_get(files[1])) == NULL)
    {
      client_send(client, "ERR unknown outfile '%s'", b);
      return -1;
    }

  scamper_outfiles_swap(a, b);
  client_send(client, "OK");

  return 0;
}

static int command_outfile(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"close",  command_outfile_close},
    {"list",   command_outfile_list},
    {"open",   command_outfile_open},
    {"socket", command_outfile_socket},
    {"swap",   command_outfile_swap},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: outfile [close | list | open | swap]");
      return 0;
    }
  next = string_nextword(buf);

  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled outfile command '%s'", buf);
    }

  return 0;
}

static int command_set_command(client_t *client, char *buf)
{
  if(scamper_command_set(buf) == -1)
    {
      client_send(client, "ERR could not set command");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

static int command_set_monitorname(client_t *client, char *buf)
{
  if(scamper_monitorname_set(buf) == -1)
    {
      client_send(client, "ERR could not set monitorname");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

static int command_set_pps(client_t *client, char *buf)
{
  return set_long(client, buf, "pps", scamper_pps_set,
		  SCAMPER_PPS_MIN, SCAMPER_PPS_MAX);
}

static int command_set_window(client_t *client, char *buf)
{
  return set_long(client, buf, "window", scamper_window_set,
		  SCAMPER_WINDOW_MIN, SCAMPER_WINDOW_MAX);
}

static int command_set(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"command",     command_set_command},
    {"monitorname", command_set_monitorname},
    {"pps",         command_set_pps},
    {"window",      command_set_window},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: "
		  "set [command | monitorname | pps | window]");
      return 0;
    }
  next = string_nextword(buf);

  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled set command '%s'", buf);
    }
  return 0;
}

/*
 * command_source_add
 *
 * this function deals with a control socket adding a new address list file
 * to scamper.  no other type of source is supported with this function.
 *
 * source add [name <name>] [descr <descr>] [list_id <id>] [cycle_id <id>]
 *            [priority <priority>] [outfile <name>]
 *            [command <command>] [file <name>] [cycles <count>]
 *            [autoreload <on|off>]
 */
static int command_source_add(client_t *client, char *buf)
{
  scamper_source_params_t ssp;
  scamper_source_t *source;
  char *params[24];
  int   i, cnt = sizeof(params) / sizeof(char *);
  char *file = NULL, *name = NULL, *priority = NULL;
  char *descr = NULL, *list_id = NULL, *cycles = NULL, *autoreload = NULL;
  char *outfile = NULL, *command = NULL, *cycle_id = NULL;
  long  l;
  int   i_cycles, i_autoreload;
  char *next;
  param_t handlers[] = {
    {"autoreload", &autoreload},
    {"command",    &command},
    {"cycle_id",   &cycle_id},
    {"cycles",     &cycles},
    {"descr",      &descr},
    {"file",       &file},
    {"list_id",    &list_id},
    {"name",       &name},
    {"outfile",    &outfile},
    {"priority",   &priority},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR source add params_get failed");
      return -1;
    }

  for(i=0; i<cnt; i += 2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;

      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client, "ERR source add param '%s' failed", params[i]);
	  return -1;
	}
    }

  if(name == NULL)
    {
      client_send(client, "ERR required parameter 'name' missing");
      return -1;
    }

  if(scamper_sources_get(name) != NULL)
    {
      client_send(client, "ERR source '%s' already exists", name);
      return -1;
    }

  if(file == NULL)
    {
      client_send(client, "ERR required parameter 'file' missing");
      return -1;
    }

  if(outfile == NULL)
    {
      client_send(client, "ERR required parameter 'outfile' missing");
      return -1;
    }

  /*
   * initialise with suitable default values in case the client does not
   * specify values for them.
   */
  memset(&ssp, 0, sizeof(ssp));
  ssp.list_id    = 0;
  ssp.cycle_id   = 1;
  ssp.priority   = 1;
  ssp.name       = name;
  ssp.descr      = descr;

  /* look up the outfile's name */
  if((ssp.sof = scamper_outfiles_get(outfile)) == NULL)
    {
      client_send(client, "ERR unknown outfile '%s'", outfile);
      return -1;
    }

  /* sanity check the list_id parameter */
  if(list_id != NULL)
    {
      if(string_tolong(list_id, &l) == -1 || l < 0 || l > 0x7fffffffL)
	{
	  client_send(client, "ERR list_id <number gte 0>");
	  return -1;
	}
      ssp.list_id = l;
    }

  /* sanity check the cycle_id parameter */
  if(cycle_id != NULL)
    {
      if(string_tolong(cycle_id, &l) == -1 || l < 0 || l > 0x7fffffffL)
	{
	  client_send(client, "ERR cycle_id <number gte 0>");
	  return -1;
	}
      ssp.cycle_id = l;
    }

  /* sanity check the priority parameter */
  if(priority != NULL)
    {
      if(string_tolong(priority, &l) == -1 || l < 0 || l > 0x7fffffff)
	{
	  client_send(client, "ERR priority <number gte 0>");
	  return -1;
	}
      ssp.priority = l;
    }

  /* sanity check the autoreload parameter */
  if(autoreload != NULL)
    {
      if(get_switch(client, "autoreload", autoreload, &l) != 0)
	{
	  return -1;
	}
      i_autoreload = l;
    }
  else i_autoreload = 0;

  /* sanity check the cycle parameter */
  if(cycles != NULL)
    {
      if(string_tolong(cycles, &l) == -1 || l < 0)
	{
	  client_send(client, "ERR cycle <number gte 0>");
	  return -1;
	}
      i_cycles = l;
    }
  else i_cycles = 1;

  if(command == NULL)
    command = (char *)scamper_command_get();

  if((source = scamper_source_file_alloc(&ssp, file, command,
					 i_cycles, i_autoreload)) == NULL)
    {
      client_send(client, "ERR could not alloc source");
      return -1;
    }

  if(scamper_sources_add(source) != 0)
    {
      scamper_source_free(source);
      client_send(client, "ERR could not add source");
      return -1;
    }

  scamper_source_free(source);
  client_send(client, "OK source added");
  return 0;
}

/*
 * command_source_cycle
 *
 * source cycle <name>
 */
static int command_source_cycle(client_t *client, char *buf)
{
  scamper_source_t *source;
  char *params[1];
  char *name;
  int   cnt = sizeof(params) / sizeof(char *);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR source cycle params_get failed");
      return -1;
    }

  if(cnt != 1)
    {
      client_send(client, "ERR missing required parameter for source cycle");
      return -1;
    }

  name = params[0];
  if((source = scamper_sources_get(name)) == NULL)
    {
      client_send(client, "ERR no source '%s'", name);
      return -1;
    }

  if(scamper_source_cycle(source) == -1)
    {
      client_send(client, "ERR could not cycle source '%s'", name);
      return -1;
    }

  client_send(client, "OK");

  return 0;
}

/*
 * command_source_delete
 *
 * source delete <name>
 */
static int command_source_delete(client_t *client, char *buf)
{
  scamper_source_t *source;
  char *name;
  char *params[1];
  int   cnt = sizeof(params) / sizeof(char *);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR source delete params_get failed");
      return -1;
    }

  if(cnt != 1)
    {
      client_send(client, "ERR missing required parameter for source delete");
      return -1;
    }

  name = params[0];

  if((source = scamper_sources_get(name)) == NULL)
    {
      client_send(client, "ERR unknown source '%s'", params[0]);
      return -1;
    }

  if(scamper_sources_del(source) == -1)
    {
      client_send(client, "ERR could not delete source '%s'", name);
      return -1;
    }

  client_send(client, "OK source '%s' deleted", name);

  return 0;
}

static int source_foreach(void *param, scamper_source_t *source)
{
  client_t *client = (client_t *)param;
  char str[1024];

  if(source_tostr(str, sizeof(str), source) != NULL)
    {
      client_send(client, "INFO %s", str);
    }

  return 0;
}

/*
 * command_source_list
 *
 * source list [<name>]
 *
 */
static int command_source_list(client_t *client, char *buf)
{
  scamper_source_t *source;
  char *params[1], str[1024];
  char *name;
  int   cnt = sizeof(params) / sizeof(char *);

  /* if there is no parameter, then dump all lists */
  if(buf == NULL)
    {
      scamper_sources_foreach(client, source_foreach);
      client_send(client, "OK");
      return 0;
    }

  /* if there is a parameter, then use that to find a source */
  if(params_get(buf, params, &cnt) == -1 || cnt != 1)
    {
      client_send(client, "ERR source check params_get failed");
      return -1;
    }
  name = params[0];
  if((source = scamper_sources_get(name)) == NULL)
    {
      client_send(client, "ERR no source '%s'", name);
      return 0;
    }
  client_send(client, "INFO %s", source_tostr(str, sizeof(str), source));
  client_send(client, "OK");

  return 0;
}

/*
 * command_source_update
 *
 * source update <name> [priority <priority>]
 *                      [autoreload <on|off>] [cycles <count>]
 *
 */
static int command_source_update(client_t *client, char *buf)
{
  scamper_source_t *source;
  char             *autoreload = NULL, *cycles = NULL, *priority = NULL;
  int               i_autoreload, i_cycles;
  long              l;
  int               i, cnt, handler_cnt;
  char             *params[10], *next;
  param_t           handlers[] = {
    {"autoreload", &autoreload},
    {"cycles",     &cycles},
    {"priority",   &priority},
  };

  if(buf == NULL)
    {
      client_send(client, "ERR missing name parameter");
      return 0;
    }

  cnt = sizeof(params) / sizeof(char *);
  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR source update params_get failed");
      return -1;
    }

  /* the name parameter should be in parameter zero */
  if(cnt < 1)
    {
      client_send(client, "ERR missing name parameter");
      return 0;
    }

  /* find the source */
  if((source = scamper_sources_get(params[0])) == NULL)
    {
      client_send(client, "ERR no such source '%s'", params[0]);
      return 0;
    }

  /* parse out each parameter */
  for(i=1; i<cnt; i += 2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;

      handler_cnt = sizeof(handlers) / sizeof(param_t);
      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client, "ERR source update param '%s' failed",params[i]);
	  return -1;
	}
    }

  /* sanity check the parameters that apply to sources of type 'file' */
  if(scamper_source_gettype(source) != SCAMPER_SOURCE_TYPE_FILE)
    {
      if(autoreload != NULL || cycles != NULL)
	{
	  client_send(client,
		      "ERR can't specify autoreload/cycles on %s source",
		      scamper_source_type_tostr(source));
	  return 0;
	}
    }
  else
    {
      if(autoreload != NULL)
	{
	  if(get_switch(client, "autoreload", autoreload, &l) == -1)
	    {
	      client_send(client, "ERR autoreload <on|off>");
	      return 0;
	    }
	  i_autoreload = l;
	}

      if(cycles != NULL)
	{
	  if(string_tolong(cycles, &l) == -1 || l < 0)
	    {
	      client_send(client, "ERR cycles <number gte 0>");
	      return 0;
	    }
	  i_cycles = l;
	}
    }

  if(priority != NULL)
    {
      if(string_tolong(priority, &l) == -1 || l < 0)
	{
	  client_send(client, "ERR priority <number gte 0>");
	  return 0;
	}
      scamper_source_setpriority(source, (uint32_t)l);
    }

  if(autoreload != NULL || cycles != NULL)
    {
      scamper_source_file_update(source,
				 (autoreload != NULL ? &i_autoreload : NULL),
				 (cycles     != NULL ? &i_cycles     : NULL));
    }

  client_send(client, "OK");
  return 0;
}

static int command_source(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"add",    command_source_add},
    {"cycle",  command_source_cycle},
    {"delete", command_source_delete},
    {"list",   command_source_list},
    {"update", command_source_update},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client,
		  "ERR usage: source [add | cycle | delete | list | update]");
      return 0;
    }

  next = string_nextword(buf);
  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

static int command_shutdown_cancel(client_t *client, char *buf)
{
  scamper_exitwhendone(0);
  client_send(client, "OK");
  return 0;
}

static int command_shutdown_done(client_t *client, char *buf)
{
  scamper_exitwhendone(1);
  client_send(client, "OK");
  return 0;
}

static int command_shutdown_flush(client_t *client, char *buf)
{
  /* empty the address list of all sources */
  scamper_sources_empty();

  /* tell scamper to exit when it has finished probing the existing window */
  scamper_exitwhendone(1);

  client_send(client, "OK");
  return 0;
}

static int command_shutdown_now(client_t *client, char *buf)
{
  /* empty the active trace window */
  scamper_queue_empty();

  /* empty the address list of all sources */
  scamper_sources_empty();

  /* tell scamper to exit when it has finished probing the existing window */
  scamper_exitwhendone(1);

  client_send(client, "OK");

  return 0;
}

static int command_shutdown(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"cancel", command_shutdown_cancel},
    {"done",   command_shutdown_done},
    {"flush",  command_shutdown_flush},
    {"now",    command_shutdown_now},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: [cancel | done | flush | now]");
      return 0;
    }

  next = string_nextword(buf);
  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

static int client_isdone(client_t *client)
{
  size_t len;
  int c;

  assert(client->wb != NULL);

  if((len = scamper_writebuf_len(client->wb)) != 0)
    {
      scamper_debug(__func__, "client writebuf len %d", len);
      return 0;
    }

  if(client->source != NULL && scamper_source_isfinished(client->source) == 0)
    {
      scamper_debug(__func__, "source not finished");
      return 0;
    }

  if(client->sof_obj != NULL)
    {
      scamper_debug(__func__, "object partially written");
      return 0;
    }

  if(client->sof_objs != NULL && (c = slist_count(client->sof_objs)) != 0)
    {
      scamper_debug(__func__, "objects outstanding %d", c);
      return 0;
    }

  return 1;
}

/*
 * client_attached_cb
 *
 * this callback is used when a control socket has been 'attached' such that
 * it sends commands over the control socket and in return it obtains
 * results.
 */
static int client_attached_cb(client_t *client, uint8_t *buf, size_t len)
{
  char *str;
  long l;
  uint32_t id;

  assert(client->source != NULL);

  /* the control socket will not be supplying any more tasks */
  if(len == 4 && strcasecmp((char *)buf, "done") == 0)
    {
      client_send(client, "OK");
      scamper_source_control_finish(client->source);
      return 0;
    }

  if(len >= 5 && strncasecmp((char *)buf, "halt ", 5) == 0)
    {
      str = string_nextword((char *)buf);
      if(string_isnumber(str) == 0)
	return client_send(client, "ERR usage: halt [id]");
      if(string_tolong(str, &l) != 0 || l <= 0 || l > 0xffffffffUL)
	return client_send(client, "ERR halt number invalid");
      id = l;
      if(scamper_source_halttask(client->source, id) != 0)
	return client_send(client, "ERR no task id-%d", id);
      return client_send(client, "OK halted %ld", id);
    }

  /* try the command to see if it is valid and acceptable */
  if(scamper_source_command2(client->source, (char *)buf, &id) != 0)
    return client_send(client, "ERR command not accepted");

  return client_send(client, "OK id-%d", id);
}

static int client_interactive_cb(client_t *client, uint8_t *buf, size_t len)
{
  static command_t handlers[] = {
#ifndef _WIN32
    {"attach",     command_attach},
#endif
    {"exit",       command_exit},
    {"get",        command_get},
    {"help",       command_help},
    {"lss-clear",  command_lss_clear},
    {"observe",    command_observe},
    {"outfile",    command_outfile},
    {"set",        command_set},
    {"shutdown",   command_shutdown},
    {"source",     command_source},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  /* XXX: should check for null? */
  next = string_nextword((char *)buf);

  if(command_handler(handlers,handler_cnt,client,(char *)buf,next,&ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

/*
 * client_read_line
 *
 * callback passed to the client's linepoll instance, which is used to read
 * incoming commands.  the current mode the client is in determines how the
 * command is actually handled.
 */
static int client_read_line(void *param, uint8_t *buf, size_t len)
{
  static int (*const func[])(client_t *, uint8_t *, size_t) = {
    client_interactive_cb,   /* CLIENT_MODE_INTERACTIVE == 0x00 */
    client_attached_cb,      /* CLIENT_MODE_ATTACHED    == 0x01 */
    NULL,                    /* CLIENT_MODE_FLUSH       == 0x02 */
  };
  client_t *client = (client_t *)param;

  /* make sure all the characters in the string are printable */
  if(string_isprint((char *)buf, len) == 0)
    {
      client_send(client, "ERR invalid character in line");
      client->mode = CLIENT_MODE_FLUSH;
      return 0;
    }

  if(func[client->mode] != NULL)
    return func[client->mode](client, buf, len);
  return 0;
}

static void client_read(const int fd, client_t *client)
{
  uint8_t buf[256];
  ssize_t rc;

  assert(scamper_fd_fd_get(client->fdn) == fd);

  /* try and read more from the client */
  if((rc = read(fd, buf, sizeof(buf))) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return;

      printerror(errno, strerror, __func__, "read failed");
      client_free(client);
      return;
    }

  /* if there is incoming data, deal with it */
  if(rc > 0)
    {
      scamper_linepoll_handle(client->lp, buf, (size_t)rc);
      return;
    }

  /* nothing left to do read with this fd */
  scamper_fd_read_pause(client->fdn);

  if(client->source != NULL)
    {
      scamper_source_control_finish(client->source);
      scamper_source_abandon(client->source);
    }

  if(client_isdone(client) != 0)
    {
      client_free(client);
      return;
    }
  client->mode = CLIENT_MODE_FLUSH;

  return;
}

static void client_write(const int fd, client_t *client)
{
  client_txt_t *t = NULL;
  client_obj_t *o = NULL;
  uint8_t data[8192];
  char str[64];
  size_t len;
  int rc;

  assert(scamper_fd_fd_get(client->fdn) == fd);

  if(scamper_writebuf_len(client->wb) == 0)
    {
      if(client->sof_off == 0)
	{
	  while((t = slist_head_pop(client->txt)) != NULL)
	    {
	      rc = scamper_writebuf_send(client->wb, t->str, t->len);
	      client_txt_free(t); t = NULL;
	      if(rc < 0)
		goto err;
	    }

	  /* check if we should start sending through a completed task */
	  if(client->sof_objs != NULL &&
	     (o = slist_head_pop(client->sof_objs)) != NULL)
	    {
	      client->sof_obj = o;
	      len = snprintf(str, sizeof(str), "DATA %d\n",
			     (int)uuencode_len(o->len, NULL, NULL));
	      if(scamper_writebuf_send(client->wb, str, len) < 0)
		{
		  printerror(errno, strerror, __func__,
			     "could not send DATA header");
		  goto err;
		}
	    }
	}
      else
	{
	  o = client->sof_obj;
	}

      if(o != NULL)
	{
	  len = uuencode_bytes(o->data, o->len, &client->sof_off,
			       data, sizeof(data));
	  if(client->sof_off == o->len)
	    {
	      client_obj_free(o);
	      client->sof_obj = NULL;
	      client->sof_off = 0;
	    }

	  if(scamper_writebuf_send(client->wb, data, len) != 0)
	    {
	      printerror(errno, strerror, __func__,
			 "could not send %d bytes", len);
	      goto err;
	    }
	}
    }


  if(scamper_writebuf_write(fd, client->wb) != 0)
    {
      printerror(errno, strerror, __func__, "fd %d", fd);
      goto err;
    }

  if(scamper_writebuf_len(client->wb) == 0 &&
     slist_count(client->txt) == 0 && client->sof_off == 0 &&
     (client->sof_objs == NULL || slist_count(client->sof_objs) == 0))
    {
      scamper_fd_write_pause(client->fdn);
      if(client->mode != CLIENT_MODE_FLUSH)
	return;
      if(client_isdone(client) == 0)
	return;
      client_free(client);
    }

  return;

 err:
  client_free(client);
  return;
}

/*
 * client_alloc
 *
 * given a new inbound client, allocate a new node for it.
 */
static client_t *client_alloc(struct sockaddr *sa, socklen_t slen, int fd)
{
  client_t *client = NULL;

  /* make the socket non-blocking, so a read or write will not hang scamper */
#ifndef _WIN32
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      return NULL;
    }
#endif

  /*
   * allocate the structure that holds the socket/client together
   * put the node into the list of sockets that are connected
   * make a copy of the sockaddr that connected to scamper
   * add the file descriptor to the event manager
   * put a wrapper around the socket to read from it one line at a time
   */
  if((client = malloc_zero(sizeof(struct client))) == NULL ||
     (client->node = dlist_tail_push(client_list, client)) == NULL ||
     (client->sa = memdup(sa, slen)) == NULL ||
     (client->fdn = scamper_fd_private(fd, client,
				       (scamper_fd_cb_t)client_read,
				       (scamper_fd_cb_t)client_write))==NULL ||
     (client->lp = scamper_linepoll_alloc(client_read_line, client)) == NULL ||
     (client->wb = scamper_writebuf_alloc()) == NULL ||
     (client->txt = slist_alloc()) == NULL)
    {
      goto cleanup;
    }
  scamper_fd_write_pause(client->fdn);

  client->mode = CLIENT_MODE_INTERACTIVE;

  return client;

 cleanup:
  if(client != NULL)
    {
      if(client->wb != NULL) scamper_writebuf_free(client->wb);
      if(client->lp != NULL) scamper_linepoll_free(client->lp, 0);
      if(client->node != NULL) dlist_node_pop(client_list, client->node);
      if(client->sa != NULL) free(client->sa);
      free(client);
    }
  return NULL;
}

static void control_accept(const int fd, void *param)
{
  struct sockaddr_storage ss;
  socklen_t socklen;
  int s;

  /* accept the new client */
  socklen = sizeof(ss);
  if((s = accept(fd, (struct sockaddr *)&ss, &socklen)) == -1)
    {
      return;
    }

  scamper_debug(__func__, "fd %d", s);

  /* allocate a client struct to keep track of data coming in on socket */
  if(client_alloc((struct sockaddr *)&ss, socklen, s) == NULL)
    {
      shutdown(s, SHUT_RDWR);
      close(s);
    }

  return;
}

static int control_init(int fd)
{
  if((client_list = dlist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc client_list");
      return -1;
    }

  if((fdn = scamper_fd_private(fd, NULL, control_accept, NULL)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not add fd");
      return -1;
    }

  return 0;
}

int scamper_control_init_unix(const char *file)
{
#if defined(AF_UNIX) && !defined(_WIN32)
  int fd = -1;

#ifdef WITHOUT_PRIVSEP
  struct sockaddr_un sn;
  uid_t uid;

  if(sockaddr_compose_un((struct sockaddr *)&sn, file) != 0)
    {
      printerror(errno, strerror, __func__, "could not compose socket");
      goto err;
    }

  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      printerror(errno, strerror, __func__, "could not create socket");
      goto err;
    }

  if(bind(fd, (struct sockaddr *)&sn, sizeof(sn)) != 0)
    {
      printerror(errno, strerror, __func__, "could not bind");
      goto err;
    }

  if((uid = getuid()) != geteuid() && chown(file, uid, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not chown");
      goto err;
    }

  if(listen(fd, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not listen");
      goto err;
    }

#else
  if((fd = scamper_privsep_open_unix(file)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open unix socket");
      goto err;
    }
#endif

  if(control_init(fd) != 0)
    goto err;

  if((ctrl_unix_name = strdup(file)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup file");
      goto err;
    }

  return 0;

 err:
  if(fd != -1 && fdn == NULL)
    close(fd);

#endif
  return -1;
}

int scamper_control_init_inet(const char *ip, int port)
{
  struct sockaddr_storage sas;
  struct sockaddr *sa = (struct sockaddr *)&sas;
  struct in_addr in;
  int af = AF_INET, fd = -1, opt;

  if(ip != NULL)
    {
      if(sockaddr_compose_str(sa, ip, port) != 0)
	{
	  printerror(errno, strerror, __func__,
		     "could not compose sockaddr from %s:%d", ip, port);
	  goto err;
	}
      af = sa->sa_family;
    }
  else
    {
      /* bind the socket to loopback on the specified port */
      in.s_addr = htonl(INADDR_LOOPBACK);
      sockaddr_compose(sa, AF_INET, &in, port);
    }
  
  /* open the TCP socket we are going to listen on */
  if((fd = socket(af, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not create socket");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) != 0)
    {
      printerror(errno, strerror, __func__, "could not set SO_REUSEADDR");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) != 0)
    {
      printerror(errno, strerror, __func__, "could not set TCP_NODELAY");
      goto err;
    }

  if(bind(fd, sa, sockaddr_len(sa)) != 0)
    {
      if(ip == NULL)
	printerror(errno, strerror, __func__,
		   "could not bind to port %d", port);
      else
	printerror(errno, strerror, __func__,
		   "could not bind to %s:%d", ip, port);
      goto err;
    }

  /* tell the system we want to listen for new clients on this socket */
  if(listen(fd, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not listen");
      goto err;
    }

  if(control_init(fd) != 0)
    goto err;

  return 0;

 err:
  if(fd != -1 && fdn == NULL)
    close(fd);
  return -1;
}

/*
 * scamper_control_cleanup
 *
 * go through and free all the clients that are connected.
 * write anything left in the writebuf to the clients (non-blocking) and
 * then close the socket.
 */
void scamper_control_cleanup()
{
  client_t *client;
  int fd;

  if(client_list != NULL)
    {
      while((client = dlist_head_pop(client_list)) != NULL)
	{
	  client->node = NULL;
	  scamper_writebuf_write(scamper_fd_fd_get(client->fdn),
				 client->wb);
	  client_free(client);
	}

      dlist_free(client_list);
      client_list = NULL;
    }

  /* stop monitoring the control socket for new connections */
  if(fdn != NULL)
    {
      if((fd = scamper_fd_fd_get(fdn)) != -1)
	{
	  close(fd);

#if defined(AF_UNIX) && !defined(_WIN32)
	  if(ctrl_unix_name != NULL)
#ifndef WITHOUT_PRIVSEP
	    scamper_privsep_unlink(ctrl_unix_name);
#else
	    unlink(ctrl_unix_name);
#endif
#endif
	}

      scamper_fd_free(fdn);
      fdn = NULL;
    }

#if defined(AF_UNIX) && !defined(_WIN32)
  if(ctrl_unix_name != NULL)
    {
      free(ctrl_unix_name);
      ctrl_unix_name = NULL;
    }
#endif

  return;
}
