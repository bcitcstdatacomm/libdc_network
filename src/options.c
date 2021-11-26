/*
 * Copyright 2021-2021 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "options.h"
#include <dc_posix/sys/dc_socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// List of options. TODO: need to verify this is complete
// https://www.ibm.com/docs/en/i/7.4?topic=ssw_ibm_i_74/apis/ssocko.htm

static void
set_bool_option(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, int level, int option, bool value)
{
    int flag;

    DC_TRACE(env);
    flag = value;
    dc_setsockopt(env, err, socket_fd, level, option, &flag, sizeof(flag));
}

/*
void dc_network_opt_ip_so_timestamp(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, int value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_TIMESTAMP, value);
}
*/

void dc_network_opt_ip_so_type(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_TYPE, value);
}

void dc_network_opt_ip_so_error(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_ERROR, value);
}

void dc_network_opt_ip_so_broadcast(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_BROADCAST, value);
}

void dc_network_opt_ip_so_debug(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_DEBUG, value);
}

void dc_network_opt_ip_so_do_not_route(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_DONTROUTE, value);
}

void dc_network_opt_ip_so_keep_alive(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_KEEPALIVE, value);
}

void dc_network_opt_ip_so_linger(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_LINGER, value);
}

void dc_network_opt_ip_so_oob_inline(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_OOBINLINE, value);
}

void dc_network_opt_ip_so_recv_buf(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_RCVBUF, value);
}

void dc_network_opt_ip_so_recv_low_water(const struct dc_posix_env *env,
                                         struct dc_error *err,
                                         int socket_fd,
                                         bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_RCVLOWAT, value);
}

void dc_network_opt_ip_so_recv_timeout(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_RCVTIMEO, value);
}

void dc_network_opt_ip_so_reuse_addr(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, SOL_SOCKET, SO_REUSEADDR, value);
}

void dc_network_opt_ip_so_send_buf(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_SNDBUF, value);
}

void dc_network_opt_ip_so_send_low_water(const struct dc_posix_env *env,
                                         struct dc_error *err,
                                         int socket_fd,
                                         bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_SNDLOWAT, value);
}

void dc_network_opt_ip_so_send_timeout(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_SNDTIMEO, value);
}

/*
void dc_network_opt_ip4_add_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, value);
}
*/

/*
void dc_network_opt_ip4_add_source_membership(const struct dc_posix_env *env,
                                              struct dc_error *err,
                                              int socket_fd,
                                              bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, value);
}
*/
/*
void dc_network_opt_ip4_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_BLOCK_SOURCE, value);
}
*/
/*
void dc_network_opt_ip4_do_not_fragment(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DONTFRAG, value);
}
*/

/*
void dc_network_opt_ip4_drop_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, value);
}
*/
/*
void dc_network_opt_ip4_header_include(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_HDRINCL, value);
}
*/
/*
void dc_network_opt_ip4_drop_source_membership(const struct dc_posix_env *env,
                                               struct dc_error *err,
                                               int socket_fd,
                                               bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, value);
}
*/
/*
void dc_network_opt_ip4_multicast_interface(const struct dc_posix_env *env,
                                            struct dc_error *err,
                                            int socket_fd,
                                            bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_MULTICAST_IF, value);
}
*/
/*
void dc_network_opt_ip4_multicast_loop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, value);
}
*/
/*
void dc_network_opt_ip4_multicast_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_MULTICAST_TTL, value);
}
*/
/*
void dc_network_opt_ip4_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_OPTIONS, value);
}
*/
/*
void dc_network_opt_ip4_port_range(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_PORTRANGE, value);
}
*/

/*
void dc_network_opt_ip4_recv_interface(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVIF, value);
}
*/
/*
void dc_network_opt_ip4_recv_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVOPTS, value);
}
*/
/*
void dc_network_opt_ip4_recv_ret_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVRETOPTS, value);
}
*/
/*
void dc_network_opt_ip4_recv_dest_addr(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVDSTADDR, value);
}
*/

/*
void dc_network_opt_ip4_recv_packet_info(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVPKTINFO, value);
}
*/
/*
void dc_network_opt_ip4_ret_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RETOPTS, value);
}
*/
/*
void dc_network_opt_ip4_ipsec_policy(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_IPSEC_POLICY, value);
}
*/
/*
void dc_network_opt_ip4_strip_header(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_STRIPHDR, value);
}
*/
/*
void dc_network_opt_ip4_recv_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVTTL, value);
}
*/
/*
void dc_network_opt_ip4_recv_tos(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_RECVTOS, value);
}
*/
/*
void dc_network_opt_ip4_tos(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_TOS, value);
}
*/
/*
void dc_network_opt_ip4_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_TTL, value);
}
*/
/*
void dc_network_opt_ip4_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_UNBLOCK_SOURCE, value);
}
*/
/*
void dc_network_opt_ip4_multicast_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, value);
}
*/

/*
void dc_network_opt_ip4_multicast_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_JOIN_GROUP, value);
}
*/

/*
void dc_network_opt_ip4_multicast_join_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP, value);
}
*/

/*
void dc_network_opt_ip4_multicast_leave_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_LEAVE_GROUP, value);
}
*/

/*
void dc_network_opt_ip4_leave_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP, value);
}
*/

/*
void dc_network_opt_ip4_multicast_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, MCAST_UNBLOCK_SOURCE, value);
}
*/

/*
void dc_network_opt_tcp_keep_alive(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_TCP, TCP_KEEPALIVE, value);
}
*/

void dc_network_opt_tcp_no_delay(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, TCP_NODELAY, value);
}

/*
void dc_network_opt_use_loopback(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_USELOOPBACK, value);
}
*/

void dc_network_opt_ip6_checksum(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_CHECKSUM, value);
}

void dc_network_opt_ip6_do_not_fragment(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_DONTFRAG, value);
}

void dc_network_opt_ip6_dest_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_DSTOPTS, value);
}

void dc_network_opt_ip6_hop_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_HOPOPTS, value);
}

void dc_network_opt_ip6_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, value);
}

void dc_network_opt_ip6_leave_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, value);
}

void dc_network_opt_ip6_multicast_hops(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, value);
}

void dc_network_opt_ip6_multicast_interface(const struct dc_posix_env *env,
                                            struct dc_error *err,
                                            int socket_fd,
                                            bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, value);
}

void dc_network_opt_ip6_multicast_loop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, value);
}

void dc_network_opt_ip6_nexthop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_NEXTHOP, value);
}

void dc_network_opt_ip6_packet_info(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_PKTINFO, value);
}

/*
void dc_network_opt_ip6_prefer_temp_addr(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, value);
}
*/

void dc_network_opt_ip6_recv_dest_options(const struct dc_posix_env *env,
                                          struct dc_error *err,
                                          int socket_fd,
                                          bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVDSTOPTS, value);
}

void dc_network_opt_ip6_recv_hop_limit(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, value);
}

void dc_network_opt_ip6_recv_hop_options(const struct dc_posix_env *env,
                                         struct dc_error *err,
                                         int socket_fd,
                                         bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, value);
}

void dc_network_opt_ip6_recv_path_mtu(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVPATHMTU, value);
}

void dc_network_opt_ip6_recv_packet_info(const struct dc_posix_env *env,
                                         struct dc_error *err,
                                         int socket_fd,
                                         bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, value);
}

void dc_network_opt_ip6_recv_route_heder(const struct dc_posix_env *env,
                                         struct dc_error *err,
                                         int socket_fd,
                                         bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVRTHDR, value);
}

void dc_network_opt_ip6_recv_traffic_class(const struct dc_posix_env *env,
                                           struct dc_error *err,
                                           int socket_fd,
                                           bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RECVTCLASS, value);
}

void dc_network_opt_ip6_route_header(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_RTHDR, value);
}

void dc_network_opt_ip6_route_header_options(const struct dc_posix_env *env,
                                             struct dc_error *err,
                                             int socket_fd,
                                             bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IP, IPV6_RTHDRDSTOPTS, value);
}

void dc_network_opt_ip6_traffic_class(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_TCLASS, value);
}

void dc_network_opt_ip6_unicast_hops(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, value);
}

/*
void dc_network_opt_ip6_use_min_mtu(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_USE_MIN_MTU, value);
}
*/

void dc_network_opt_ip6_v6_only(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, value);
}

/*
void dc_network_opt_ip6_multicast_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_BLOCK_SOURCE, value);
}
*/

/*
void dc_network_opt_ip6_multicast_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_JOIN_GROUP, value);
}
*/

/*
void dc_network_opt_ip6multicast_join_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, value);
}
*/

/*
void dc_network_opt_ip6_multicast_leave__group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_LEAVE_GROUP, value);
}
*/

/*
void dc_network_opt_ip6_multicast_leave_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_LEAVE_SOURCE_GROUP, value);
}
*/

/*
void dc_network_opt_ip6_multicast_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_IPV6, MCAST_UNBLOCK_SOURCE, value);
}
*/

/*
void dc_network_opt_icmp6_filter(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, ICMP6_FILTER, value);
}
*/

/*
void dc_network_opt_icmp6_hop_limit(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value)
{
    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_HOPLIMIT, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_BINDV6ONLY, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_IPSEC_POLICY, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_FW_ADD, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_FW_DEL, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_FW_FLUSH, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_FW_ZERO, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_FW_GET, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_ICMPV6, IPV6_BOUND_IF, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_REUSEPORT, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, SO_NOSIGPIPE, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_BOUND_IF, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_PKTINFO, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_ADD, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_DEL, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_FLUSH, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_ZERO, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_GET, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_FW_RESETLOG, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DUMMYNET_CONFIGURE, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DUMMYNET_DEL, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DUMMYNET_FLUSH, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_DUMMYNET_GET, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_TRAFFIC_MGT_BACKGROUND, value);
    //    set_bool_option(env, err, socket_fd, IPPROTO_IP, IP_MULTICAST_IFINDEX, value);
}
*/
