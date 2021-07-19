#ifndef LIBDC_NETWORK_OPTIONS_H
#define LIBDC_NETWORK_OPTIONS_H


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


#include <dc_posix/dc_posix_env.h>


void dc_network_opt_ip_so_timestamp(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, int value);
void dc_network_opt_ip_so_type(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_error(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_broadcast(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_debug(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_do_not_route(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_keep_alive(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_linger(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_oob_inline(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_recv_buf(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_recv_low_water(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_recv_timeout(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_reuse_addr(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_send_buf(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_send_low_water(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip_so_send_timeout(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_add_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_add_source_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_drop_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_header_include(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_drop_source_membership(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_interface(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_loop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_recv_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_recv_ret_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_ret_opts(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_recv_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_recv_tos(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_tos(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_ttl(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_join_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_leave_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_leave_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip4_multicast_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_tcp_no_delay(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_checksum(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_do_not_fragment(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_dest_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_hop_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_leave_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_hops(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_interface(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_loop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_nexthop(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_packet_info(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_dest_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_hop_limit(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_hop_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_path_mtu(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_packet_info(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_route_heder(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_recv_traffic_class(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_route_header(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_route_header_options(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_traffic_class(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_unicast_hops(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_v6_only(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_block_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_join_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6multicast_join_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_leave__group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_leave_source_group(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_ip6_multicast_unblock_source(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_icmp6_filter(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);
void dc_network_opt_icmp6_hop_limit(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, bool value);


#endif //LIBDC_NETWORK_OPTIONS_H
