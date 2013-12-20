
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "ps3dm_proxy.h"
#include "ps3dm.h"
#include "ps3ss.h"

#define PS3DM_SM_VERSION			"0.0.1"

#define PS3DM_SM_LAID				0x1070000002000001ull
#define PS3DM_SM_GET_RND_NUMBER_PAID		0x1070000031000001ull
#define PS3DM_SM_PAID				0x10700003ff000001ull

struct opts
{
	char *device_name;
	char *cmd;
	int do_help;
	int do_verbose;
	int do_version;
};

static struct option long_opts[] = {
	{ "help",	no_argument, NULL, 'h' },
	{ "verbose",	no_argument, NULL, 'v' },
	{ "version",	no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

/*
 * usage
 */
static void usage(void) {
	fprintf(stderr,
		"Usage: ps3dm_sm [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help				Show this message and exit\n"
		"	-v, --verbose				Increase verbosity\n"
		"	-V, --version				Show version information and exit\n"
		"Commands:\n"
		"	set_encdec_key KEY KEYSIZE		Sets ENCDEC/ATA key\n"
		"	set_del_encdec_key PARAM		Sets/Deletes ENCDEC/ATA key\n"
		"		PARAM:\n"
		"			0xC-0xF			Deletes ENCDEC/ATA key\n"
		"			0x10[0-F]		Sets default ENCDEC/ATA key\n"
		"			0x11[0-F]		Deletes default ENCDEC/ATA key\n"
		"	get_rnd_number				Returns random number\n"
		"	drive_auth PARAM			Authenticates BD drive\n"
		"		PARAM:\n"
		"			0x29			Authenticates BD drive\n"
		"			0x46			Resets BD drive\n"
		"	ps2_disc_auth PARAM			Authenticates PS2 disc\n"
		"	get_version				Returns version\n"
		"	drive_ctrl PARAM			Controls BD drive\n"
		"\n\n"
		"Simple example: Get random number:\n"
		"	ps3dm_sm /dev/ps3dmproxy get_rnd_number\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_sm " PS3DM_SM_VERSION "\n"
		"Copyright (C) 2011 graf_chokolo <grafchokolo@googlemail.com>\n"
		"This is free software.  You may redistribute copies of it "
		"under the terms of\n"
		"the GNU General Public License 2 "
		"<http://www.gnu.org/licenses/gpl2.html>.\n"
		"There is NO WARRANTY, to the extent permitted by law.\n");
}

/*
 * process_opts
 */
static int process_opts(int argc, char **argv, struct opts *opts)
{
	int c;

	while ((c = getopt_long(argc, argv, "hvV", long_opts, NULL)) != -1) {
		switch (c) {
		case 'h':
		case '?':
			opts->do_help = 1;
			return 0;

		case 'v':
			opts->do_verbose++;
			break;

		case 'V':
			opts->do_version = 1;
			return 0;

		default:
			fprintf(stderr, "Invalid command option: %c\n", c);
			return -1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No device specified\n");
		return -1;
	}

	opts->device_name = argv[optind];
	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No command specified\n");
		return -1;
	}

	opts->cmd = argv[optind];
	optind++;

	return 0;
}

/*
 * cmd_set_encdec_key
 */
static int cmd_set_encdec_key(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t val;
	uint8_t key[24];
	uint64_t key_size;
	char *endptr;
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_set_encdec_key *ss_sm_set_encdec_key;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No key specified\n");
		return -1;
	}

	key_size = 0;

	while (optind < argc) {
		val = strtoul(argv[optind], &endptr, 0);
		if ((*endptr != '\0') || (val > 0xff)) {
			fprintf(stderr, "Invalid key specified: %s\n", argv[optind]);
			return -1;
		}

		optind++;

		key[key_size++] = val;

		if (key_size == 24)
			break;
	}

	if (key_size < 24) {
		fprintf(stderr, "Key should be of size 24 bytes\n");
		return -1;
	}

	if (optind >= argc) {
		fprintf(stderr, "No key length specified\n");
		return -1;
	}

	key_size = strtoull(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid key length specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_set_encdec_key = (struct ps3ss_sm_set_encdec_key *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_set_encdec_key);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_set_encdec_key);

	ss_hdr->packet_id = PS3SS_PID_SM_SET_ENCDEC_KEY;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	memcpy(ss_sm_set_encdec_key->key, key, sizeof(key));
	ss_sm_set_encdec_key->key_size = key_size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%016lx\n", ss_sm_set_encdec_key->param);
	}

	return error;
}

/*
 * cmd_set_del_encdec_key
 */
static int cmd_set_del_encdec_key(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t param;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_set_del_encdec_key *ss_sm_set_del_encdec_key;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No parameter specified\n");
		return -1;
	}

	param = strtoull(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid parameter specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_set_del_encdec_key = (struct ps3ss_sm_set_del_encdec_key *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_set_del_encdec_key);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_set_del_encdec_key);

	ss_hdr->packet_id = PS3SS_PID_SM_SET_DEL_ENCDEC_KEY;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	ss_sm_set_del_encdec_key->param = param;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	}

	fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);

	return error;
}

/*
 * cmd_get_rnd_number
 */
static int cmd_get_rnd_number(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_get_rnd_number *ss_sm_get_rnd_number;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_get_rnd_number = (struct ps3ss_sm_get_rnd_number *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_get_rnd_number);

	ss_hdr->packet_id = PS3SS_PID_SM_GET_RND_NUMBER;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_GET_RND_NUMBER_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		for (i = 0; i < sizeof(ss_sm_get_rnd_number->field0); i++)
			fprintf(stdout, "0x%02x ", ss_sm_get_rnd_number->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_drive_auth
 */
static int cmd_drive_auth(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t param;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_drive_auth *ss_sm_drive_auth;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No parameter specified\n");
		return -1;
	}

	param = strtoull(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid parameter specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_drive_auth = (struct ps3ss_sm_drive_auth *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_drive_auth);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_drive_auth);

	ss_hdr->packet_id = PS3SS_PID_SM_DRIVE_AUTH;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	ss_sm_drive_auth->param = param;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	}

	fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);

	return error;
}

/*
 * cmd_ps2_disc_auth
 */
static int cmd_ps2_disc_auth(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_ps2_disc_auth *ss_sm_ps2_disc_auth;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_ps2_disc_auth = (struct ps3ss_sm_ps2_disc_auth *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_ps2_disc_auth);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_ps2_disc_auth);

	ss_hdr->packet_id = PS3SS_PID_SM_PS2_DISC_AUTH;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < sizeof(ss_sm_ps2_disc_auth->field0); i++)
			fprintf(stdout, "0x%02x ", ss_sm_ps2_disc_auth->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_version
 */
static int cmd_get_version(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_get_version *ss_sm_get_version;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_get_version = (struct ps3ss_sm_get_version *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_get_version);

	ss_hdr->packet_id = PS3SS_PID_SM_GET_VERSION;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		for (i = 0; i < sizeof(ss_sm_get_version->field0); i++)
			fprintf(stdout, "0x%02x ", ss_sm_get_version->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_drive_ctrl
 */
static int cmd_drive_ctrl(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t param;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_sm_drive_ctrl *ss_sm_drive_ctrl;
	int error, i;

	if (optind >= argc) {
		fprintf(stderr, "No parameter specified\n");
		return -1;
	}

	param = strtoull(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid parameter specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_sm_drive_ctrl = (struct ps3ss_sm_drive_ctrl *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_drive_ctrl);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_sm_drive_ctrl);

	ss_hdr->packet_id = PS3SS_PID_SM_DRIVE_CTRL;
	ss_hdr->function_id = PS3SS_FID_SM;
	ss_hdr->laid = PS3DM_SM_LAID;
	ss_hdr->paid = PS3DM_SM_PAID;

	ss_sm_drive_ctrl->param = param;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < sizeof(ss_sm_drive_ctrl->field8); i++)
			fprintf(stdout, "0x%02x ", ss_sm_drive_ctrl->field8[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	struct opts opts;
	int fd = 0, error = 0;

	memset(&opts, 0, sizeof(opts));

	if (process_opts(argc, argv, &opts)) {
		usage();
		error = 1;
		goto done;
	}

	if (opts.do_help) {
		usage();
		goto done;
	} else if (opts.do_version) {
		version();
		goto done;
	}

	fd = ps3dm_proxy_open(opts.device_name);
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", opts.device_name, strerror(errno));
		error = 2;
		goto done;
	}

	if (!strcmp(opts.cmd, "set_encdec_key")) {
		error = cmd_set_encdec_key(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "set_del_encdec_key")) {
		error = cmd_set_del_encdec_key(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_rnd_number")) {
		error = cmd_get_rnd_number(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "drive_auth")) {
		error = cmd_drive_auth(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "ps2_disc_auth")) {
		error = cmd_ps2_disc_auth(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_version")) {
		error = cmd_get_version(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "drive_ctrl")) {
		error = cmd_drive_ctrl(fd, &opts, argc, argv);
	} else {
		usage();
		error = 1;
		goto done;
	}

	if (error)
		error = 3;

done:

	if (fd >= 0)
		ps3dm_proxy_close(fd);

	exit(error);
}
