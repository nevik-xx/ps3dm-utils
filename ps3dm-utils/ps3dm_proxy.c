
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

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <asm/ps3dmproxy.h>

#include "ps3dm_proxy.h"

int ps3dm_proxy_open(const char *path)
{
	return open(path, O_RDWR);
}

int ps3dm_proxy_close(int fd)
{
	return close(fd);
}

int ps3dm_proxy_user_to_lpar_addr(int fd, uint64_t user_addr, uint64_t *lpar_addr)
{
	struct ps3dmproxy_ioctl_user_to_lpar_addr arg;
	int error;

	memset(&arg, 0, sizeof(arg));
	arg.user_addr = user_addr;

	error = ioctl(fd, PS3DMPROXY_IOCTL_USER_TO_LPAR_ADDR, &arg);

	if (!error)
		*lpar_addr = arg.lpar_addr;

	return error;
}

int ps3dm_proxy_get_repo_node_val(int fd, uint64_t lpar_id, const uint64_t key[4], uint64_t val[2])
{
	struct ps3dmproxy_ioctl_get_repo_node_val arg;
	int error;

	memset(&arg, 0, sizeof(arg));
	arg.lpar_id = lpar_id;
	arg.key[0] = key[0];
	arg.key[1] = key[1];
	arg.key[2] = key[2];
	arg.key[3] = key[3];

	error = ioctl(fd, PS3DMPROXY_IOCTL_GET_REPO_NODE_VAL, &arg);

	if (!error) {
		val[0] = arg.val[0];
		val[1] = arg.val[1];
	}

	return error;
}

int ps3dm_proxy_do_request(int fd, struct ps3dm_hdr *sendbuf, unsigned int sendbuf_size,
	struct ps3dm_hdr *recvbuf, unsigned int recvbuf_size)
{
	struct ps3dmproxy_ioctl_do_request arg;

	memset(&arg, 0, sizeof(arg));
	arg.sendbuf = (uint64_t) sendbuf;
	arg.sendbuf_size = sendbuf_size;
	arg.recvbuf = (uint64_t) recvbuf;
	arg.recvbuf_size = recvbuf_size;

	return ioctl(fd, PS3DMPROXY_IOCTL_DO_REQUEST, &arg);
}
