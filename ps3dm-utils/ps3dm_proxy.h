
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _PS3DM_PROXY_H_
#define _PS3DM_PROXY_H_

#include "ps3dm.h"

int ps3dm_proxy_open(const char *path);

int ps3dm_proxy_close(int fd);

int ps3dm_proxy_user_to_lpar_addr(int fd, uint64_t user_addr, uint64_t *lpar_addr);

int ps3dm_proxy_get_repo_node_val(int fd, uint64_t lpar_id, const uint64_t key[4], uint64_t val[2]);

int ps3dm_proxy_do_request(int fd, struct ps3dm_hdr *sendbuf, unsigned int sendbuf_size,
	struct ps3dm_hdr *recvbuf, unsigned int recvbuf_size);

#endif
