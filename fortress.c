/*
 * fortress.c
 *
 */

#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>            
#include <netlink/netlink.h>    
#include <netlink/genl/genl.h>  
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  
#include <linux/nl80211.h>

/******************************************************************/
//* STRUCTURES *//

struct iw_nl80211_survey {
  uint32_t  freq;
  int8_t    noise;
};

struct iw_nl80211_interface {
   char ifname[30];
   uint32_t ifindex;
 };

struct iw_nl80211_linkstat {
  int8_t      signal,
              signal_avg;

  int8_t      bss_signal;
  uint8_t     bss_signal_qual;

  struct iw_nl80211_survey  survey;
};

/**
 * struct cmd - stolen and modified from iw:iw.h
 * @cmd:    nl80211 command to send via GeNetlink
 * @sk:     netlink socket to be used for this command
 * @flags:    flags to set in the GeNetlink message
 * @handler:    netlink callback handler
 * @handler_arg:  argument for @handler
 * @msg_args:   additional attributes to pass into message
 * @msg_args_len: number of elements in @msg_args
 */
struct cmd {
  enum nl80211_commands cmd;
  struct nl_sock    *sk;
  int     flags;
  int (*handler)(struct nl_msg *msg, void *arg);
  void      *handler_arg;
};

/******************************************************************/
//* GLOBAL VARIABL *//

static struct iw_nl80211_linkstat linkstat;

static struct iw_nl80211_interface wifiInterface;

static volatile int keepRunning = 1;

/******************************************************************/
//* FUNCTION HANDLERS DEFINITIONS *//


static int ifName_handler(struct nl_msg *msg, void *arg) {
 
  //printf("ifName_handler\n");
  struct iw_nl80211_interface *ls = arg;
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

  nla_parse(tb_msg,
            NL80211_ATTR_MAX,
            genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0),
            NULL);

  if (tb_msg[NL80211_ATTR_IFNAME]) {
    strcpy(ls->ifname, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
  }

  if (tb_msg[NL80211_ATTR_IFINDEX]) {
    ls->ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
  }

  return NL_SKIP;
}

/**
 * survey_handler - channel survey data
 * This handler will be called multiple times, for each channel.
 * stolen from iw:survey.c
 */
static int survey_handler(struct nl_msg *msg, void *arg)
{
  //printf("toto survey handler\n");
  struct iw_nl80211_survey *sd = (struct iw_nl80211_survey *)arg;
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];

  static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    [NL80211_SURVEY_INFO_FREQUENCY]     = { .type = NLA_U32 },
    [NL80211_SURVEY_INFO_NOISE]         = { .type = NLA_U8 },
    [NL80211_SURVEY_INFO_IN_USE]        = { .type = NLA_FLAG },
    [NL80211_SURVEY_INFO_TIME]          = { .type = NLA_U64 },
    [NL80211_SURVEY_INFO_TIME_BUSY]     = { .type = NLA_U64 },
    [NL80211_SURVEY_INFO_TIME_EXT_BUSY] = { .type = NLA_U64 },
    [NL80211_SURVEY_INFO_TIME_RX]       = { .type = NLA_U64 },
    [NL80211_SURVEY_INFO_TIME_TX]       = { .type = NLA_U64 },
    [NL80211_SURVEY_INFO_TIME_SCAN]     = { .type = NLA_U64 },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_SURVEY_INFO])
    return NL_SKIP;

  if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
           tb[NL80211_ATTR_SURVEY_INFO], survey_policy))
    return NL_SKIP;

  /* The frequency is needed to match up with the associated station */
  if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY])
    return NL_SKIP;

  /* We are only interested in the data of the operating channel */
  if (!sinfo[NL80211_SURVEY_INFO_IN_USE])
    return NL_SKIP;

  sd->freq  = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);

  if (sinfo[NL80211_SURVEY_INFO_NOISE])
    sd->noise = (int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);

  return NL_SKIP;
}

static int link_sta_handler(struct nl_msg *msg, void *arg)
{
  //printf("toto sta handler\n");
  struct iw_nl80211_linkstat *ls = arg;
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_CONNECTED_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    [NL80211_STA_INFO_SIGNAL_AVG] = { .type = NLA_U8 },
    [NL80211_STA_INFO_T_OFFSET] = { .type = NLA_U64 },
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_DROP_MISC] = { .type = NLA_U64 },
    [NL80211_STA_INFO_BEACON_RX] = { .type = NLA_U64 },
    [NL80211_STA_INFO_BEACON_LOSS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_BEACON_SIGNAL_AVG] = { .type = NLA_U8 },
    [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
    [NL80211_STA_INFO_STA_FLAGS] =
      { .minlen = sizeof(struct nl80211_sta_flag_update) },
    [NL80211_STA_INFO_LOCAL_PM] = { .type = NLA_U32},
    [NL80211_STA_INFO_PEER_PM] = { .type = NLA_U32},
    [NL80211_STA_INFO_NONPEER_PM] = { .type = NLA_U32},
    [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = { .type = NLA_NESTED },
  };
  
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_STA_INFO])
    return NL_SKIP;

  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
           tb[NL80211_ATTR_STA_INFO],
           stats_policy))
    return NL_SKIP;

  if (sinfo[NL80211_STA_INFO_SIGNAL])
    ls->signal = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
  if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
    ls->signal_avg = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

  return NL_SKIP;
}

static int link_handler(struct nl_msg *msg, void *arg)
{
  //printf("toto link handler\n");
  struct iw_nl80211_linkstat *ls = arg;
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
    [NL80211_BSS_TSF] = { .type = NLA_U64 },
    [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
    [NL80211_BSS_BSSID] = { },
    [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
    [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
    [NL80211_BSS_INFORMATION_ELEMENTS] = { },
    [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
    [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
    [NL80211_BSS_STATUS] = { .type = NLA_U32 },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);


  if (!tb[NL80211_ATTR_BSS]){
    return NL_SKIP;
  }

  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy))
    return NL_SKIP;

  if (!bss[NL80211_BSS_BSSID])
    return NL_SKIP;

  if (!bss[NL80211_BSS_STATUS])
    return NL_SKIP;

  if (bss[NL80211_BSS_SIGNAL_UNSPEC])
    ls->bss_signal_qual = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);

  if (bss[NL80211_BSS_SIGNAL_MBM]) {
    int s = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
    //printf("signal level: %d dBm\n", s);
    ls->bss_signal = s / 100;
  }

  return NL_SKIP;
}

/* Predefined handlers, stolen from iw:iw.c */
static inline int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
       void *arg)
{
  //printf("toto error handler\n");
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static inline int finish_handler(struct nl_msg *msg, void *arg)
{
  //printf("toto finish handler\n");
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static inline int ack_handler(struct nl_msg *msg, void *arg)
{
  //printf("toto ack handler\n");
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}


/******************************************************************/
//* FUNCTION DEFINITIONS *//

static inline bool iw_nl80211_have_survey_data(struct iw_nl80211_linkstat *ls)
{
  return ls->survey.freq != 0 && ls->survey.noise != 0;
}

static void display_levels(void)
{
  static float qual, signal, qual_bss, signal_bss, noise, ssnr;
  uint32_t wifiindex;
    
  bool noise_data_valid;
  int sig_qual = -1, sig_qual_bss = -1, sig_qual_max, sig_level, sig_qual_bss_max, sig_level_bss;

  printf("Interface Name : %s\n", wifiInterface.ifname);

  if (wifiInterface.ifindex)
  {
    wifiindex = wifiInterface.ifindex;
    //printf("wifi Index : %d\n", wifiindex);
  }
 
  noise_data_valid = iw_nl80211_have_survey_data(&linkstat);
  sig_level = linkstat.signal_avg ?: linkstat.signal;

  if (sig_level) {
    if (sig_level < -110)
      sig_qual = 0;
    else if (sig_level > -40)
      sig_qual = 70;
    else
      sig_qual = sig_level + 110;
    sig_qual_max = 70;
  }

  sig_level_bss = linkstat.bss_signal;
  // not used
  if (sig_level_bss) {
    if (sig_level_bss < -110)
      sig_qual_bss = 0;
    else if (sig_level_bss > -40)
      sig_qual_bss = 70;
    else
      sig_qual_bss = sig_level_bss + 110;
    sig_qual_bss_max = 70;
  }


  if (sig_qual == -1 && !sig_level && !noise_data_valid) {
    printf("NO INTERFACE DATA\n");
  }
  
  if (sig_qual_bss != -1) {
    qual_bss = sig_qual_bss;
    //printf("bss link quality: %0.f%%    |   ", (1e2 * qual_bss)/sig_qual_bss_max); 
  }
  
  if (sig_level_bss != 0) {
    signal_bss = sig_level_bss;
    //printf("bss signal level: %.0f dBm\n", signal_bss);
  }

  if (sig_qual != -1) {
    qual = sig_qual;
    printf("link quality: %0.f%%    |   ", (1e2 * qual)/sig_qual_max); 
  }
  
  if (sig_level != 0) {
    signal = sig_level;
    printf("signal level: %.0f dBm    |   ", signal);
  }

  if (noise_data_valid) {
    noise = linkstat.survey.noise;
    //printf("noise level: %.0f dBm    |   ", noise);        
  }

  if (noise_data_valid && sig_level) {
    ssnr = sig_level - linkstat.survey.noise;    
    printf("SNR: %.0f dB\n", ssnr);
  }

}


void iw_nl80211_get_survey(struct iw_nl80211_survey *sd)
{
  static struct cmd cmd_survey = {
    .cmd   = NL80211_CMD_GET_SURVEY,
    .flags   = NLM_F_DUMP,
    .handler = survey_handler
  };

  cmd_survey.handler_arg = sd;
  memset(sd, 0, sizeof(*sd));
  handle_cmd(&cmd_survey);
}


void iw_nl80211_get_interface(struct iw_nl80211_interface *ls)
{

  static struct cmd cmd_ifName = {
    .cmd   = NL80211_CMD_GET_INTERFACE,
    .flags   = NLM_F_DUMP,
    .handler = ifName_handler
  };

  /* first handle_cmd to get wifi interface and index and send them back in next sockect when calling handle_cmd again*/

  cmd_ifName.handler_arg = ls;
  memset(ls, 0, sizeof(*ls));
  printf("toto before handle cmd_ifName\n");
  handle_cmd(&cmd_ifName);

}


void iw_nl80211_get_linkstat(struct iw_nl80211_linkstat *ls)
{
  
  static struct cmd cmd_linkstat = {
    .cmd   = NL80211_CMD_GET_SCAN,
    .flags   = NLM_F_DUMP,
    .handler = link_handler
  };

  cmd_linkstat.handler_arg = ls;
  memset(ls, 0, sizeof(*ls));
  handle_cmd(&cmd_linkstat);

  static struct cmd cmd_getstation = {
    .cmd   = NL80211_CMD_GET_STATION,
    .flags   = NLM_F_DUMP,
    .handler = link_sta_handler
  };

  cmd_getstation.handler_arg  = ls;
  handle_cmd(&cmd_getstation);

  /* Channel survey data */
  iw_nl80211_get_survey(&ls->survey);
}


/**
 * handle_cmd: process @cmd
 * Returns 0 if ok, -errno < 0 on failure
 * stolen/modified from iw:iw.c 
 */
int handle_cmd(struct cmd *cmd)
{
  struct nl_cb *cb;
  struct nl_msg* msg;
  static int nl80211_id = -1;
  int ret;
  uint32_t ifindex;

  /*
   * Initialization of static components:
   * - per-cmd socket
   * - global nl80211 ID
   * - per-cmd interface index (in case conf_ifname() changes)
   */
  if (!cmd->sk) {
	  
	/* allocate a netlink socket */  
    cmd->sk = nl_socket_alloc();
    if (!cmd->sk)
      err_sys("failed to allocate netlink socket");

    /* NB: not setting sk buffer size, using default 32Kb */
    if (genl_connect(cmd->sk))
      err_sys("failed to connect to GeNetlink");
  }

  if (nl80211_id < 0) {
	/* Resolve Generic Netlink family group name */  
    nl80211_id = genl_ctrl_resolve(cmd->sk, "nl80211");
    //printf("nl80211_id : %d\n", nl80211_id);
    if (nl80211_id < 0)
      err_sys("nl80211 not found");
  }

  /*
   * Message Preparation
   */
   
  /* Allocate a new netlink message with the default maximum payload size. */ 
  msg = nlmsg_alloc();
  if (!msg)
    err_sys("failed to allocate netlink message");

  /* Allocate a callback set and initialize it */
  cb = nl_cb_alloc(0 ? NL_CB_DEBUG : NL_CB_DEFAULT);
  if (!cb)
    err_sys("failed to allocate netlink callback");

  /* Add Generic Netlink headers to Netlink message */
  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, cmd->flags, cmd->cmd, 0);

  if (wifiInterface.ifindex){
    ifindex = wifiInterface.ifindex;
	/* Add a unspecific attribute to netlink message. */
    nla_put(msg, NL80211_ATTR_IFINDEX, sizeof(ifindex), &ifindex);
  }
  
  /* Finalize and transmit Netlink message */ 
  ret = nl_send_auto_complete(cmd->sk, msg);
  if (ret < 0){
    err_sys("failed to send netlink message");
  }

  /*-------------------------------------------------------------------------
   * Receive loop
   *-------------------------------------------------------------------------*/
   
  /* set callback functions for the recieved message */
  /* Set up an error callback */ 
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
  if (cmd->handler){
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cmd->handler, cmd->handler_arg);
  }

  while (ret > 0){
	/* Receive a set of messages from a netlink socket. */
    nl_recvmsgs(cmd->sk, cb);
  }

  nl_cb_put(cb);
  nlmsg_free(msg);
  //nl_close(cmd->sk);
  //nl_socket_free(cmd->sk);

  return ret;
}


void err_sys(const char* x) 
{ 
    perror(x); 
    exit(1); 
}


void ctrl_c_handler(int dummy) {
    keepRunning = 0;
}


/******************************************************************/
//* MAIN *//

int main(int argc, char **argv) {

  /* Used to detect if the user press Ctrl+C */
  signal(SIGINT, ctrl_c_handler);
  
  /* Gets wifi interface and index */
  iw_nl80211_get_interface(&wifiInterface);
  
  do {
	/* Gets signal informations */
    iw_nl80211_get_linkstat(&linkstat);
    system("clear");
    display_levels();
    sleep(1);
  } while(keepRunning);

  printf("\nThanks for using Fortress\n");
  
  return 0;
}
