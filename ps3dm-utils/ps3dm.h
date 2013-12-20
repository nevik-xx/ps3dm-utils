
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

#ifndef _PS3DM_H_
#define _PS3DM_H_

#include <stdint.h>

struct ps3dm_hdr {
	uint32_t request_id;
	uint32_t function_id;
	uint32_t request_size;
	uint32_t response_size;
};

#define PS3DM_HDR_SIZE		sizeof(struct ps3dm_hdr)

#endif
