#include <netinet/in.h>

typedef struct {
   #  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
   #  endif

   #  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
   #  endif
    //uint8_t version_and_ihl;

    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t s_addr;
    uint32_t d_addr;
} IpHdr;

typedef struct{
    u_int16_t s_port;
    u_int16_t d_port;
    u_int32_t seq_num;
    u_int32_t ack_num;

#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t reserved:4;
    u_int8_t offset:4;
#  endif

#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t offset:4;
    u_int8_t reserved:4;
#  endif

    u_int8_t flags;
#  define FIN  0x01
#  define SYN  0x02
#  define RST  0x04
#  define PUSH 0x08
#  define ACK  0x10
#  define URG  0x20

    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} TcpHdr;