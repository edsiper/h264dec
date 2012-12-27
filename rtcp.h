
#ifndef RTCP_H
#define RTCP_H

/* Payload types */
#define RTCP_SR     200   /*  sender report        */
#define RTCP_RR     201   /*  receiver report      */
#define RTCP_SDES   202   /*  source description   */
#define RTCP_BYE    203   /*  good bye             */
#define RTCP_APP    204   /*  application defined  */

struct rtcp_pkg {
  uint8_t  version;
  uint8_t  padding;
  uint8_t  extension;
  uint8_t  ccrc;
  uint8_t  type;
  uint16_t length;
  uint32_t ssrc;
  uint32_t ts_msw;
  uint32_t ts_lsw;
};


#endif
