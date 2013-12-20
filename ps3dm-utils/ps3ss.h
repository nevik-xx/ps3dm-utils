
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

#ifndef _PS3SS_H_
#define _PS3SS_H_

#include <stdint.h>

#define PS3SS_FID_VTRM					0x2000
#define PS3SS_PID_VTRM_GET_STATUS			0x2002

#define PS3SS_FID_SRTC					0x3000
#define PS3SS_PID_SRTC_GET_TIME				0x3002

#define PS3SS_FID_SM					0x5000
#define PS3SS_PID_SM_SET_ENCDEC_KEY			0x5001
#define PS3SS_PID_SM_SET_DEL_ENCDEC_KEY			0x5002
#define PS3SS_PID_SM_GET_RND_NUMBER			0x5003
#define PS3SS_PID_SM_DRIVE_AUTH				0x5004
#define PS3SS_PID_SM_PS2_DISC_AUTH			0x5005
#define PS3SS_PID_SM_GET_VERSION			0x5006
#define PS3SS_PID_SM_DRIVE_CTRL				0x5007

#define PS3SS_FID_UM					0x6000
#define PS3SS_PID_UM_UPDATE_PKG				0x6001
#define PS3SS_PID_UM_INSPECT_PKG			0x6002
#define PS3SS_PID_UM_GET_PKG_INFO			0x6003
#define PS3SS_PID_UM_GET_FIX_INSTR			0x6004
#define PS3SS_PID_UM_EXTRACT_PKG			0x6005
#define PS3SS_PID_UM_GET_EXTRACT_PKG			0x6006
#define PS3SS_PID_UM_GET_TOKEN_SEED			0x6009
#define PS3SS_PID_UM_SET_TOKEN				0x600a
#define PS3SS_PID_UM_READ_EPROM				0x600b
#define PS3SS_PID_UM_WRITE_EPROM			0x600c
#define PS3SS_PID_UM_CHECK_INT				0x6010
#define PS3SS_PID_UM_GET_APPL_VER			0x6011

#define PS3SS_FID_SCM					0x9000
#define PS3SS_PID_SCM_GET_REGION_DATA			0x9006
#define PS3SS_PID_SCM_GET_TIME				0x9009
#define PS3SS_PID_SCM_READ_EPROM			0x900b
#define PS3SS_PID_SCM_WRITE_EPROM			0x900c
#define PS3SS_PID_SCM_GET_SC_STATUS			0x900e

#define PS3SS_FID_IIM					0x17000
#define PS3SS_PID_IIM_GET_DATA_SIZE			0x17001
#define PS3SS_PID_IIM_GET_DATA				0x17002
#define PS3SS_PID_IIM_GET_CISD_SIZE			0x17015

#define PS3SS_FID_AIM					0x19000
#define PS3SS_PID_AIM_GET_DEV_TYPE			0x19002
#define PS3SS_PID_AIM_GET_DEV_ID			0x19003
#define PS3SS_PID_AIM_GET_PS_CODE			0x19004
#define PS3SS_PID_AIM_GET_OPEN_PS_ID			0x19005

#define PS3SS_FID_USB_DONGLE_AUTH			0x24000
#define PS3SS_PID_USB_DONGLE_AUTH_GEN_CHALLENGE		0x24001
#define PS3SS_PID_USB_DONGLE_AUTH_VERIFY_RESP		0x24002

struct ps3ss_hdr {
	uint64_t packet_id;
	uint64_t function_id;
	uint32_t retval;
	uint8_t res[4];
	uint64_t laid;
	uint64_t paid;
};

#define PS3SS_HDR_SIZE		sizeof(struct ps3ss_hdr)

struct ps3ss_vtrm_get_status {
	uint32_t field0;
	uint8_t res1[4];
	uint32_t field8;
	uint8_t res2[4];
	uint32_t field10;
	uint8_t res3[4];
};

struct ps3ss_srtc_get_time {
	uint64_t field0;
	uint64_t field8;
	uint64_t field10;
};

struct ps3ss_sm_set_encdec_key {
	uint8_t key[24];
	uint64_t key_size;
	uint64_t param;
};

struct ps3ss_sm_set_del_encdec_key {
	uint64_t param;
};

struct ps3ss_sm_get_rnd_number {
	uint8_t field0[24];
};

struct ps3ss_sm_drive_auth {
	uint64_t param;
};

struct ps3ss_sm_ps2_disc_auth {
	uint8_t field0[56];
};

struct ps3ss_sm_get_version {
	uint8_t field0[8];
};

struct ps3ss_sm_drive_ctrl {
	uint64_t param;
	uint8_t field8[16];
};

struct ps3ss_um_update_pkg {
	uint32_t in_lpar_mem;
	uint8_t res1[4];
	uint32_t pkg_type;
	uint8_t res2[4];
	uint32_t flags;
	uint8_t res3[4];
	uint64_t lpar_id;
	uint64_t pkg_size;
	union {
		struct {
			uint64_t lpar_addr;
			uint64_t size;
			uint64_t field10;
		} lpar_mem_segs[0];

		uint8_t raw[0];
	} pkg_data;
	/* uint64_t request_id */
};

struct ps3ss_um_get_pkg_info {
	uint32_t type;
	uint8_t res[4];
	uint64_t version;
};

struct ps3ss_um_get_fix_instr {
	uint8_t field0[12];
};

struct ps3ss_um_get_extract_pkg {
	uint32_t in_lpar_mem;
	uint8_t res1[4];
	uint64_t field8;
	uint32_t field10;
	uint8_t res2[4];
	uint64_t request_id;
	uint64_t buf_size;
	uint8_t buf[0];
};

struct ps3ss_um_get_token_seed {
	uint64_t token_size;
	uint8_t token[80];
	uint64_t seed_size;
	uint8_t seed[80];
};

struct ps3ss_um_read_eprom {
	uint32_t offset;
	uint8_t res[4];
	uint8_t val;
};

struct ps3ss_um_write_eprom {
	uint32_t offset;
	uint8_t res[4];
	uint8_t val;
};

struct ps3ss_scm_get_region_data {
	uint64_t id;
	uint64_t data_size;
	uint8_t data[0];
};

struct ps3ss_scm_get_time {
	uint64_t tid;
	uint64_t field8;
	uint64_t field10;
};

struct ps3ss_scm_read_eprom {
	uint32_t offset;
	uint8_t res1[4];
	uint32_t nread;
	uint8_t res2[4];
	uint64_t buf_size;
	uint8_t buf[0];
};

struct ps3ss_scm_write_eprom {
	uint32_t offset;
	uint8_t res1[4];
	uint32_t nwrite;
	uint8_t res2[4];
	uint64_t buf_size;
	uint8_t buf[0];
};

struct ps3ss_scm_get_sc_status {
	uint32_t version;
	uint8_t res1[4];
	uint32_t mode;
	uint8_t res2[4];
};

struct ps3ss_iim_get_data_size {
	uint64_t index;
	uint64_t size;
};

struct ps3ss_iim_get_data {
	uint64_t index;
	uint64_t buf_size;
	uint8_t buf[0];
	/* uint64_t data_size */
};

struct ps3ss_iim_get_cisd_size {
	uint64_t size;
};

struct ps3ss_aim_get_dev_type {
	uint8_t field0[16];
};

struct ps3ss_aim_get_dev_id {
	uint8_t field0[16];
};

struct ps3ss_aim_get_ps_code {
	uint8_t field0[8];
};

struct ps3ss_aim_get_open_ps_id {
	uint8_t field0[16];
};

struct ps3ss_usb_dongle_auth_gen_challenge {
	uint8_t header[3];
	uint8_t challenge[20];
};

struct ps3ss_usb_dongle_auth_verify_resp {
	uint8_t header[3];
	uint16_t dongle_id;
	uint8_t response[20];
} __attribute__ ((packed));

#endif
