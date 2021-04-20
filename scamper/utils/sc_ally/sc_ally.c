/*
 * sc_ally : scamper driver to collect data on candidate aliases using the
 *           Ally method.
 *
 * $Id: sc_ally.c,v 1.21 2014/11/01 15:21:35 mjl Exp $
 *
 * Copyright (C) 2009-2011 The University of Waikato
 * Copyright (C) 2013-2014 The Regents of the University of California
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
  "$Id: sc_ally.c,v 1.21 2014/11/01 15:21:35 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_heap.h"
#include "mjl_splaytree.h"
#include "utils.h"

#define TEST_PING   1
#define TEST_ALLY   2

#define IPID_NONE   0
#define IPID_INCR   1
#define IPID_RAND   2
#define IPID_ECHO   3
#define IPID_CONST  4
#define IPID_UNRESP 5

typedef struct sc_ipidseq
{
  scamper_addr_t   *addr;
  uint8_t           udp;
  uint8_t           icmp;
  uint8_t           tcp;
} sc_ipidseq_t;

typedef struct sc_test
{
  int               type;
  void             *data;
} sc_test_t;

/*
 * sc_target
 *
 */
typedef struct sc_target
{
  scamper_addr_t   *addr;
  sc_test_t        *test;
  splaytree_node_t *node;
  slist_t          *blocked;
} sc_target_t;

/*
 * sc_allytest
 *
 * keep state about the ally test being used to try and resolve a pair
 * of addresses to aliases.
 */
typedef struct sc_allytest
{
  sc_target_t      *a;
  sc_target_t      *b;
  int               attempt;
  int               method;
} sc_allytest_t;

typedef struct sc_pingtest
{
  sc_target_t      *target;
  int               step;
} sc_pingtest_t;

typedef struct sc_waittest
{
  struct timeval   tv;
  sc_test_t       *test;
} sc_waittest_t;

static uint32_t               options       = 0;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static int                    port          = 31337;
static char                  *unix_name     = NULL;
static char                  *addressfile   = NULL;
static char                  *outfile_name  = NULL;
static int                    outfile_fd    = -1;
static scamper_file_filter_t *decode_filter = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    data_left     = 0;
static char                   cmd[512];
static int                    more          = 0;
static int                    probing       = 0;
static int                    waittime      = 5;
static int                    attempts      = 5;
static int                    probe_wait    = 1000;
static int                    fudge         = 5000;
static struct timeval         now;
static FILE                  *text          = NULL;
static splaytree_t           *targets       = NULL;
static splaytree_t           *ipidseqs      = NULL;
static slist_t               *virgin        = NULL;
static heap_t                *waiting       = NULL;

#define OPT_HELP        0x0001
#define OPT_ADDRFILE    0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_UNIX        0x0010
#define OPT_TEXT        0x0020
#define OPT_DAEMON      0x0040
#define OPT_ATTEMPTS    0x0080
#define OPT_WAIT        0x0100
#define OPT_PROBEWAIT   0x0200
#define OPT_FUDGE       0x0400
#define OPT_NOBS        0x0800

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_ally [-D?] [-a infile] [-o outfile] [-p port] [-U unix]\n"
	  "               [-i waitprobe] [-f fudge] [-q attempts]\n"
	  "               [-t log] [-w waittime]\n");

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_trlinks\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a input addressfile\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_PROBEWAIT)
    fprintf(stderr, "     -i inter-probe gap\n");

  if(opt_mask & OPT_FUDGE)
    fprintf(stderr, "     -f fudge\n");

  if(opt_mask & OPT_ATTEMPTS)
    fprintf(stderr, "     -q number of probes for ally\n");

  if(opt_mask & OPT_TEXT)
    fprintf(stderr, "     -t logfile\n");

  if(opt_mask & OPT_WAIT)
    fprintf(stderr, "     -w waittime\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "a:Di:o:O:p:q:t:U:w:?";
  char     *opt_port = NULL, *opt_probewait = NULL;
  char     *opt_text = NULL, *opt_attempts = NULL, *opt_wait = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addressfile = optarg;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'i':
	  options |= OPT_PROBEWAIT;
	  opt_probewait = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case '0':
	  if(strcasecmp(optarg, "nobs") == 0)
	    options |= OPT_NOBS;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'q':
	  options |= OPT_ATTEMPTS;
	  opt_attempts = optarg;
	  break;

	case 't':
	  options |= OPT_TEXT;
	  opt_text = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  unix_name = optarg;
	  break;

	case 'w':
	  options |= OPT_WAIT;
	  opt_wait = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  if((options & (OPT_ADDRFILE|OPT_OUTFILE)) != (OPT_ADDRFILE|OPT_OUTFILE) ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX))
    {
      usage(OPT_ADDRFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
      return -1;
    }

  if(options & OPT_PORT)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  return -1;
	}
      port = lo;
    }

  if(options & OPT_ATTEMPTS)
    {
      if(string_tolong(opt_attempts, &lo) != 0 || lo < 1 || lo > 10)
	{
	  usage(OPT_ATTEMPTS);
	  return -1;
	}
      attempts = lo;
    }

  if(options & OPT_WAIT)
    {
      if(string_tolong(opt_wait, &lo) != 0 || lo < 1 || lo > 60)
	{
	  usage(OPT_WAIT);
	  return -1;
	}
      waittime = lo;
    }

  if(options & OPT_PROBEWAIT)
    {
      /* probe gap between 200 and 2000ms */
      if(string_tolong(opt_probewait, &lo) != 0 || lo < 200 || lo > 2000)
	{
	  usage(OPT_PROBEWAIT);
	  return -1;
	}
      probe_wait = lo;
    }

  if(opt_text != NULL)
    {
      if((text = fopen(opt_text, "w")) == NULL)
	{
	  usage(OPT_TEXT);
	  fprintf(stderr, "could not open %s\n", opt_text);
	  return -1;
	}
    }

  return 0;
}

static void print(char *format, ...)
{
  va_list ap;
  char msg[512];

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  printf("%ld: %s", (long int)now.tv_sec, msg);

  if(text != NULL)
    {
      fprintf(text, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(text);
    }

  return;
}

static void status(char *format, ...)
{
  va_list ap;
  char pref[32];
  char msg[512];

  snprintf(pref, sizeof(pref), "p %d, w %d, v %d",
	   probing, heap_count(waiting), slist_count(virgin));

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  print("%s : %s\n", pref, msg);
  return;
}

static sc_test_t *sc_test_alloc(int type, void *data)
{
  sc_test_t *test;

  if((test = malloc_zero(sizeof(sc_test_t))) == NULL)
    {
      fprintf(stderr, "could not malloc test\n");
      return NULL;
    }

  test->type = type;
  test->data = data;
  return test;
}

static void sc_test_free(sc_test_t *test)
{
  if(test != NULL) free(test);
  return;
}

static int sc_waittest_cmp(const void *va, const void *vb)
{
  const sc_waittest_t *a = va;
  const sc_waittest_t *b = vb;
  return timeval_cmp(&b->tv, &a->tv);
}

static int sc_waittest(sc_test_t *test)
{
  sc_waittest_t *wt;

  if((wt = malloc_zero(sizeof(sc_waittest_t))) == NULL)
    return -1;

  timeval_add_s(&wt->tv, &now, waittime);
  wt->test = test;

  if(heap_insert(waiting, wt) == NULL)
    return -1;

  return 0;
}

static void sc_target_detach(sc_target_t *tg)
{
  sc_test_t *test;

  if(tg == NULL)
    return;

  if(tg->node != NULL)
    {
      splaytree_remove_node(targets, tg->node);
      tg->node = NULL;
    }

  if(tg->blocked != NULL)
    {
      while((test = slist_head_pop(tg->blocked)) != NULL)
	sc_waittest(test);
      slist_free(tg->blocked);
      tg->blocked = NULL;
    }

  return;
}

static void sc_target_free(sc_target_t *tg)
{
  if(tg == NULL)
    return;

  sc_target_detach(tg);

  if(tg->addr != NULL)
    scamper_addr_free(tg->addr);

  free(tg);
  return;
}

static int sc_target_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_target_t *)a)->addr, ((sc_target_t *)b)->addr);
}

static sc_target_t *sc_target_alloc(char *addr)
{
  scamper_addr_t *sa = NULL;
  sc_target_t *tg = NULL;

  if((sa = scamper_addr_resolve(AF_INET, addr)) == NULL)
    {
      fprintf(stderr, "could not resolve '%s'\n", addr);
      goto err;
    }

  if((tg = malloc_zero(sizeof(sc_target_t))) == NULL)
    {
      fprintf(stderr, "could not malloc target\n");
      goto err;
    }

  tg->addr = sa;
  return tg;

 err:
  if(sa != NULL) scamper_addr_free(sa);
  if(tg != NULL) sc_target_free(tg);
  return NULL;
}

static int sc_target_block(sc_target_t *target, sc_test_t *block)
{
  if(target->blocked == NULL && (target->blocked = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc target->blocked list\n");
      return -1;
    }

  if(slist_tail_push(target->blocked, block) == NULL)
    {
      fprintf(stderr, "could not add test to blocked list\n");
      return -1;
    }

  return 0;
}

static sc_target_t *sc_target_find(sc_target_t *target)
{
  return splaytree_find(targets, target);
}

static sc_target_t *sc_target_findaddr(scamper_addr_t *addr)
{
  sc_target_t findme;
  findme.addr = addr;
  return sc_target_find(&findme);
}

static int sc_target_add(sc_target_t *target)
{
  assert(target->node == NULL);
  assert(target->test != NULL);
  if((target->node = splaytree_insert(targets, target)) == NULL)
    {
      fprintf(stderr, "could not add target to tree\n");
      return -1;
    }
  return 0;
}

static char *class_tostr(char *str, size_t len, uint8_t class)
{
  char *ptr;

  switch(class)
    {
    case IPID_NONE:   ptr = "none"; break;
    case IPID_INCR:   ptr = "incr"; break;
    case IPID_RAND:   ptr = "rand"; break;
    case IPID_ECHO:   ptr = "echo"; break;
    case IPID_CONST:  ptr = "const"; break;
    case IPID_UNRESP: ptr = "unresp"; break;
    default:
      snprintf(str, len, "class %d", class);
      return str;
    }

  snprintf(str, len, "%s", ptr);
  return str;
}

static void sc_ipidseq_free(sc_ipidseq_t *seq)
{
  if(seq == NULL)
    return;

  if(seq->addr != NULL)
    scamper_addr_free(seq->addr);
  free(seq);
  return;
}

static int sc_ipidseq_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_ipidseq_t *)a)->addr,((sc_ipidseq_t *)b)->addr);
}

static sc_ipidseq_t *sc_ipidseq_alloc(scamper_addr_t *addr)
{
  sc_ipidseq_t *seq;

  if((seq = malloc_zero(sizeof(sc_ipidseq_t))) == NULL)
    return NULL;

  seq->addr = scamper_addr_use(addr);

  if(splaytree_insert(ipidseqs, seq) == NULL)
    {
      scamper_addr_free(seq->addr);
      free(seq);
      return NULL;
    }

  return seq;
}

static sc_ipidseq_t *sc_ipidseq_get(scamper_addr_t *addr)
{
  sc_ipidseq_t findme;
  findme.addr = addr;
  return splaytree_find(ipidseqs, &findme);
}

/*
 * sc_ipidseq_method
 *
 * prefer icmp echo because it is benign.
 * prefer tcp to udp because it returns fewer false negatives --shared
 * counter held centrally (TCP) vs held on line card (UDP) on some routers.
 */
static int sc_ipidseq_method(sc_ipidseq_t *a, sc_ipidseq_t *b)
{
  if(a->icmp == IPID_INCR && a->icmp == b->icmp)
    return 1;
  if(a->tcp == IPID_INCR && a->tcp == b->tcp)
    return 3;
  if(a->udp == IPID_INCR && a->udp == b->udp)
    return 2;
  return 0;
}

static void sc_pingtest_free(sc_pingtest_t *pt)
{
  if(pt == NULL)
    return;
  if(pt->target != NULL)
    sc_target_free(pt->target);
  free(pt);
  return;
}

static void sc_allytest_free(sc_allytest_t *ally)
{
  if(ally == NULL)
    return;
  sc_target_free(ally->a);
  sc_target_free(ally->b);
  free(ally);
  return;
}

static sc_test_t *sc_pingtest_new(scamper_addr_t *addr)
{
  sc_pingtest_t *pt;
  sc_target_t *tg;

  assert(addr != NULL);

  if((pt = malloc_zero(sizeof(sc_pingtest_t))) == NULL)
    {
      fprintf(stderr, "could not malloc pingtest\n");
      goto err;
    }

  if((tg = malloc_zero(sizeof(sc_target_t))) == NULL)
    {
      fprintf(stderr, "could not malloc target\n");
      goto err;
    }
  tg->addr = scamper_addr_use(addr);
  pt->target = tg;

  /* create a generic test structure which we put in a list of tests */
  if((pt->target->test = sc_test_alloc(TEST_PING, pt)) == NULL)
    goto err;

  return pt->target->test;

 err:
  if(pt != NULL) sc_pingtest_free(pt);
  return NULL;
}

static int sc_allytest_new(char *buf, void *param)
{
  sc_allytest_t *ally = NULL;
  sc_test_t *test = NULL;
  char *a, *b;

  a = buf;
  b = buf;
  while(*b != '\0')
    {
      if(*b == ' ')
	break;
      b++;
    }
  if(*b == '\0')
    return -1;
  *b = '\0';
  b++;

  if((ally = malloc_zero(sizeof(sc_allytest_t))) == NULL ||
     (ally->a = sc_target_alloc(a)) == NULL ||
     (ally->b = sc_target_alloc(b)) == NULL)
    goto err;

  if((test = sc_test_alloc(TEST_ALLY, ally)) == NULL)
    goto err;
  ally->a->test = test;
  ally->b->test = test;

  slist_tail_push(virgin, test);
  return 0;

 err:
  return -1;
}

static int ping_classify(scamper_ping_t *ping)
{
  scamper_ping_reply_t *rx;
  int rc = -1, echo = 0, bs = 0, nobs = 0;
  int i, samples[65536];
  uint32_t u32, f, n0, n1;
  slist_t *list = NULL;
  slist_node_t *ln0, *ln1;

  if(ping->stop_reason == SCAMPER_PING_STOP_NONE ||
     ping->stop_reason == SCAMPER_PING_STOP_ERROR)
    return IPID_UNRESP;

  if((list = slist_alloc()) == NULL)
    goto done;

  memset(samples, 0, sizeof(samples));
  for(i=0; i<ping->ping_sent; i++)
    {
      if((rx = ping->ping_replies[i]) != NULL &&
	 SCAMPER_PING_REPLY_FROM_TARGET(ping, rx))
	{
	  /*
	   * if at least two of four samples have the same ipid as what was
	   * sent, then declare it echos.  this handles the observed case
	   * where some responses echo but others increment.
	   */
	  if(rx->probe_ipid == rx->reply_ipid && ++echo > 1)
	    {
	      rc = IPID_ECHO;
	      goto done;
	    }

	  /*
	   * if two responses have the same IPID value, declare that it
	   * replies with a constant IPID
	   */
	  if(++samples[rx->reply_ipid] > 1)
	    {
	      rc = IPID_CONST;
	      goto done;
	    }

	  if(slist_tail_push(list, rx) == NULL)
	    goto done;
	}
    }
  if(slist_count(list) < attempts)
    {
      rc = IPID_UNRESP;
      goto done;
    }

  f = (fudge == 0) ? 5000 : fudge;

  ln0 = slist_head_node(list);
  ln1 = slist_node_next(ln0);
  while(ln1 != NULL)
    {
      rx = slist_node_item(ln0); n0 = rx->reply_ipid;
      rx = slist_node_item(ln1); n1 = rx->reply_ipid;

      if(n0 < n1)
	u32 = n1 - n0;
      else
	u32 = (n1 + 0x10000) - n0;
      if(u32 <= f)
	nobs++;

      if((options & OPT_NOBS) == 0)
	{
	  n0 = byteswap16(n0);
	  n1 = byteswap16(n1);
	  if(n0 < n1)
	    u32 = n1 - n0;
	  else
	    u32 = (n1 + 0x10000) - n0;
	  if(u32 <= f)
	    bs++;
	}

      ln0 = ln1;
      ln1 = slist_node_next(ln0);
    }

  if(nobs != attempts-1 && bs != attempts-1)
    rc = IPID_RAND;
  else
    rc = IPID_INCR;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static int process_ping(sc_test_t *test, scamper_ping_t *ping)
{
  sc_pingtest_t *pt = test->data;
  sc_ipidseq_t *seq;
  char addr[64], icmp[10], tcp[10], udp[10];
  int class;

  assert(ping != NULL);

  if((seq = sc_ipidseq_get(pt->target->addr)) == NULL &&
     (seq = sc_ipidseq_alloc(pt->target->addr)) == NULL)
    goto err;

  class = ping_classify(ping);

  if(SCAMPER_PING_METHOD_IS_UDP(ping))
    seq->udp = class;
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    seq->tcp = class;
  else if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    seq->icmp = class;

  scamper_addr_tostr(pt->target->addr, addr, sizeof(addr));
  scamper_ping_free(ping); ping = NULL;

  pt->step++;

  if(pt->step < 3)
    {
      if(sc_waittest(test) != 0)
	goto err;
      status("wait ping %s step %d", addr, pt->step);
      return 0;
    }

  status("done ping %s icmp %s udp %s tcp %s", addr,
	 class_tostr(icmp, sizeof(icmp), seq->icmp),
	 class_tostr(udp, sizeof(udp), seq->udp),
	 class_tostr(tcp, sizeof(tcp), seq->tcp));

  sc_pingtest_free(pt);
  sc_test_free(test);

  return 0;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int process_ally(sc_test_t *test, scamper_dealias_t *dealias)
{
  scamper_dealias_ally_t *ally;
  scamper_addr_t *a;
  scamper_addr_t *b;
  sc_allytest_t *at = test->data;
  size_t off = 0;
  char msg[512];
  char buf[64];
  int rc = 0;

  assert(dealias != NULL);

  ally = dealias->data;
  a = ally->probedefs[0].dst;
  b = ally->probedefs[1].dst;

  string_concat(msg, sizeof(msg), &off, "ally %s:",
		scamper_addr_tostr(a, buf, sizeof(buf)));
  string_concat(msg, sizeof(msg), &off, "%s ",
		scamper_addr_tostr(b, buf, sizeof(buf)));

  at->attempt++;
  if(dealias->result == SCAMPER_DEALIAS_RESULT_NONE && at->attempt <= 4)
    {
      string_concat(msg, sizeof(msg), &off, "wait %d", at->attempt);
      if(sc_waittest(test) != 0)
	rc = -1;
    }
  else
    {
      if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	string_concat(msg, sizeof(msg), &off, "aliases");
      else if(dealias->result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
	string_concat(msg, sizeof(msg), &off, "not aliases");
      else
	string_concat(msg, sizeof(msg), &off, "no result");

      sc_allytest_free(test->data);
      sc_test_free(test);
    }

  status("%s", msg);
  scamper_dealias_free(dealias);
  return rc;
}

static int do_decoderead(void)
{
  sc_target_t            *target, findme;
  sc_test_t              *test;
  void                   *data;
  uint16_t                type;
  char                    buf[64];
  scamper_ping_t         *ping = NULL;
  scamper_dealias_t      *dealias = NULL;
  scamper_dealias_ally_t *ally;
  int rc;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, decode_filter, &type, &data) != 0)
    {
      fprintf(stderr, "do_decoderead: scamper_file_read errno %d\n", errno);
      goto err;
    }

  if(data == NULL)
    return 0;

  probing--;

  if(type == SCAMPER_FILE_OBJ_PING)
    {
      ping = (scamper_ping_t *)data;
      findme.addr = ping->dst;
    }
  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
    {
      dealias = (scamper_dealias_t *)data;
      ally = (scamper_dealias_ally_t *)dealias->data;
      findme.addr = ally->probedefs[0].dst;
    }
  else return -1;

  if((target = splaytree_find(targets, &findme)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n",
	      scamper_addr_tostr(findme.addr, buf, sizeof(buf)));
      goto err;
    }
  test = target->test;

  if(test->type == TEST_PING)
    rc = process_ping(test, ping);
  else if(test->type == TEST_ALLY)
    rc = process_ally(test, dealias);
  else
    rc = -1;

  return rc;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int sc_test_ping(sc_test_t *test, char *cmd, size_t len)
{
  sc_pingtest_t *pt = test->data;
  scamper_addr_t *dst = pt->target->addr;
  sc_target_t *found;
  size_t off = 0;
  char buf[64];

  assert(pt->step >= 0);
  assert(pt->step < 3);

  /* first, check to see if the test is runnable. if not block */
  if((found = sc_target_find(pt->target)) != NULL && found->test != test)
    {
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }
  else if(found == NULL)
    {
      /* add the test to the blocked list */
      if(sc_target_add(pt->target) != 0)
	return -1;
    }

  string_concat(cmd, len, &off, "ping -P ");
  if(pt->step == 0)
    string_concat(cmd, len, &off, "udp-dport");
  else if(pt->step == 1)
    string_concat(cmd, len, &off, "icmp-echo");
  else if(pt->step == 2)
    string_concat(cmd, len, &off, "tcp-ack-sport");
  else
    return -1;
  string_concat(cmd, len, &off, " -i %d", probe_wait / 1000);
  if((probe_wait % 1000) != 0)
    string_concat(cmd, len, &off, "%.d", probe_wait % 1000);
  string_concat(cmd, len, &off, " -c %d -o %d %s\n", attempts + 2, attempts,
		scamper_addr_tostr(dst, buf, sizeof(buf)));

  return off;
}

static int sc_test_ally(sc_test_t *test, char *cmd, size_t len)
{
  sc_allytest_t *at = test->data;
  sc_ipidseq_t *aseq = sc_ipidseq_get(at->a->addr);
  sc_ipidseq_t *bseq = sc_ipidseq_get(at->b->addr);
  sc_ipidseq_t *seq;
  scamper_addr_t *addr;
  sc_target_t *found;
  sc_pingtest_t *pt;
  sc_test_t *tt;
  char *method;
  size_t off = 0;
  char ab[64], bb[64];
  int i;

  if(at->method == 0)
    {
      for(i=0; i<2; i++)
	{
	  if(i == 0)
	    {
	      seq = aseq;
	      addr = at->a->addr;
	    }
	  else
	    {
	      seq = bseq;
	      addr = at->b->addr;
	    }

	  if(seq == NULL)
	    {
	      if((found = sc_target_findaddr(addr)) != NULL)
		{
		  if(sc_target_block(found, test) != 0)
		    return -1;
		  return 0;
		}

	      if((tt = sc_pingtest_new(addr)) == NULL)
		return -1;
	      pt = tt->data;
	      if(sc_target_block(pt->target, test) != 0)
		return -1;
	      if(sc_target_add(pt->target) != 0)
		return -1;
	      return sc_test_ping(tt, cmd, len);
	    }
	}

      if((at->method = sc_ipidseq_method(aseq, bseq)) == 0)
	{
	  sc_allytest_free(at);
	  sc_test_free(test);
	  return 0;
	}
    }

  if(((found = sc_target_find(at->a)) != NULL && found->test != test) ||
     ((found = sc_target_find(at->b)) != NULL && found->test != test))
    {
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }

  if(at->method == 1)
    method = "icmp-echo";
  else if(at->method == 2)
    method = "udp-dport";
  else if(at->method == 3)
    method = "tcp-ack-sport";
  else
    return -1;

  if((sc_target_find(at->a) == NULL && sc_target_add(at->a) != 0) ||
     (sc_target_find(at->b) == NULL && sc_target_add(at->b) != 0))
    return -1;

  string_concat(cmd, len, &off, "dealias -m ally");
  if(fudge == 0)
    string_concat(cmd, len, &off, " -O inseq");
  else
    string_concat(cmd, len, &off, " -f %d", fudge);
  if(options & OPT_NOBS)
    string_concat(cmd, len, &off, " -O nobs");
  string_concat(cmd, len, &off, " -W %d -q %d -p '-P %s' %s %s\n",
		probe_wait, attempts, method,
		scamper_addr_tostr(at->a->addr, ab, sizeof(ab)),
		scamper_addr_tostr(at->b->addr, bb, sizeof(bb)));

  return off;
}

static int do_method(void)
{
  static int (*const func[])(sc_test_t *, char *, size_t) = {
    sc_test_ping,     /* TEST_PING */
    sc_test_ally,     /* TEST_ALLY */
  };
  sc_waittest_t *wt;
  sc_test_t *test;
  int off;

  if(more < 1)
    return 0;

  for(;;)
    {
      if((wt = heap_head_item(waiting)) != NULL &&
	 timeval_cmp(&now, &wt->tv) >= 0)
	{
	  test = wt->test;
	  heap_remove(waiting);
	  free(wt);
	}
      else if((test = slist_head_pop(virgin)) == NULL)
	{
	  return 0;
	}

      /* something went wrong */
      if((off = func[test->type-1](test, cmd, sizeof(cmd))) == -1)
	{
	  fprintf(stderr, "something went wrong\n");
	  return -1;
	}

      /* got a command, send it */
      if(off != 0)
	{
	  write_wrap(scamper_fd, cmd, NULL, off);
	  probing++;
	  more--;

	  print("p %d, w %d, v %d : %s", probing, heap_count(waiting),
		slist_count(virgin), cmd);

	  break;
	}
    }

  return 0;
}

/*
 * do_files
 *
 * open a socketpair that can be used to feed warts data into one end and
 * have the scamper_file routines decode it via the other end.
 *
 * also open a file to send the binary warts data file to.
 */
static int do_files(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_DEALIAS, SCAMPER_FILE_OBJ_PING};
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  int pair[2];

  if((decode_filter = scamper_file_filter_alloc(types, 2)) == NULL)
    {
      return -1;
    }

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    return -1;

  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    {
      return -1;
    }

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    {
      return -1;
    }

  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    {
      return -1;
    }

  return 0;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
#ifdef HAVE_SOCKADDR_UN
  struct sockaddr_un sn;
#endif

  struct sockaddr_in sin;
  struct in_addr in;

  if(options & OPT_PORT)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "could not allocate new socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }
#ifdef HAVE_SOCKADDR_UN
  else if(options & OPT_UNIX)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sn, unix_name) != 0)
	{
	  fprintf(stderr, "could not build sockaddr_un\n");
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "could not allocate unix domain socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sn, sizeof(sn)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }
#endif

  return -1;
}

/*
 * do_scamperread
 *
 * the fd for the scamper process is marked as readable, so do a read
 * on it.
 */
static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      if(readbuf_len == 0)
	{
	  if((readbuf = memdup(buf, rc)) == NULL)
	    {
	      return -1;
	    }
	  readbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
	    {
	      readbuf = tmp;
	      memcpy(readbuf+readbuf_len, buf, rc);
	      readbuf_len += rc;
	    }
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    {
      goto done;
    }

  head = readbuf;
  for(i=0; i<readbuf_len; i++)
    {
      if(readbuf[i] == '\n')
	{
	  /* skip empty lines */
	  if(head == &readbuf[i])
	    {
	      head = &readbuf[i+1];
	      continue;
	    }

	  /* calculate the length of the line, excluding newline */
	  linelen = &readbuf[i] - head;

	  /* if currently decoding data, then pass it to uudecode */
	  if(data_left > 0)
	    {
	      uus = sizeof(uu);
	      if(uudecode_line(head, linelen, uu, &uus) != 0)
		{
		  fprintf(stderr, "could not uudecode_line\n");
		  goto err;
		}

	      if(uus != 0)
		{
		  write_wrap(decode_out_fd, uu, NULL, uus);
		  write_wrap(outfile_fd, uu, NULL, uus);
		}

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      more++;
	      if(do_method() != 0)
		goto err;
	    }
	  /* new piece of data */
	  else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	    {
	      l = strtol(head+5, &ptr, 10);
	      if(*ptr != '\n' || l < 1)
		{
		  head[linelen] = '\0';
		  fprintf(stderr, "could not parse %s\n", head);
		  goto err;
		}

	      data_left = l;
	    }
	  /* feedback letting us know that the command was accepted */
	  else if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
	    {
	      /* nothing to do */
	    }
	  /* feedback letting us know that the command was not accepted */
	  else if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
	    {
	      goto err;
	    }
	  else
	    {
	      head[linelen] = '\0';
	      fprintf(stderr, "unknown response '%s'\n", head);
	      goto err;
	    }

	  head = &readbuf[i+1];
	}
    }

  if(head != &readbuf[readbuf_len])
    {
      readbuf_len = &readbuf[readbuf_len] - head;
      ptr = memdup(head, readbuf_len);
      free(readbuf);
      readbuf = ptr;
    }
  else
    {
      readbuf_len = 0;
      free(readbuf);
      readbuf = NULL;
    }

 done:
  return 0;

 err:
  return -1;
}

static void cleanup(void)
{
  if(virgin != NULL)
    {
      slist_free(virgin);
      virgin = NULL;
    }

  if(waiting != NULL)
    {
      heap_free(waiting, NULL);
      waiting = NULL;
    }

  if(targets != NULL)
    {
      splaytree_free(targets, NULL);
      targets = NULL;
    }

  if(ipidseqs != NULL)
    {
      splaytree_free(ipidseqs, (splaytree_free_t)sc_ipidseq_free);
      ipidseqs = NULL;
    }

  if(decode_in != NULL)
    {
      scamper_file_close(decode_in);
      decode_in = NULL;
    }

  if(decode_filter != NULL)
    {
      scamper_file_filter_free(decode_filter);
      decode_filter = NULL;
    }

  if(text != NULL)
    {
      fclose(text);
      text = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  struct timeval tv, *tv_ptr;
  sc_waittest_t *wait;
  fd_set rfds;
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    {
      return -1;
    }

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      fprintf(stderr, "could not daemon");
      return -1;
    }
#endif

  random_seed();

  if((targets = splaytree_alloc(sc_target_cmp)) == NULL)
    return -1;
  if((ipidseqs = splaytree_alloc(sc_ipidseq_cmp)) == NULL)
    return -1;
  if((virgin = slist_alloc()) == NULL)
    return -1;
  if((waiting = heap_alloc(sc_waittest_cmp)) == NULL)
    return -1;
  if(file_lines(addressfile, sc_allytest_new, NULL) != 0)
    {
      fprintf(stderr, "could not read %s\n", addressfile);
      return -1;
    }

  /*
   * connect to the scamper process
   */
  if(do_scamperconnect() != 0)
    {
      return -1;
    }

  /*
   * sort out the files that we'll be working with.
   */
  if(do_files() != 0)
    {
      return -1;
    }

  /* attach */
  snprintf(cmd, sizeof(cmd), "attach\n");
  if(write_wrap(scamper_fd, cmd, NULL, 7) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0 && decode_in_fd < 0)
	break;

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	}

      if(decode_in_fd >= 0)
	{
	  FD_SET(decode_in_fd, &rfds);
	  if(nfds < decode_in_fd) nfds = decode_in_fd;
	}

      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  wait = heap_head_item(waiting);
	  if(slist_count(virgin) > 0 ||
	     (wait != NULL && timeval_cmp(&wait->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  wait = heap_head_item(waiting);
	  if(more > 0 && tv_ptr == NULL && wait != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&wait->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &wait->tv);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(splaytree_count(targets) == 0 && slist_count(virgin) == 0 &&
	 heap_count(waiting) == 0)
	{
	  break;
	}

      if(select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "select error\n");
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0)
	{
	  if(do_method() != 0)
	    return -1;
	}

      if(scamper_fd >= 0 && FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    return -1;
	}

      if(decode_in_fd >= 0 && FD_ISSET(decode_in_fd, &rfds))
	{
	  if(do_decoderead() != 0)
	    return -1;
	}
    }

  return 0;
}
