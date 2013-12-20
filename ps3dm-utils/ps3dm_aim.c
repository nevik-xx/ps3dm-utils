
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

#define PS3DM_AIM_VERSION		"0.0.1"

#define PS3DM_AIM_LAID			0x1070000002000001ull
#define PS3DM_AIM_PAID			0x10700003ff000001ull

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
		"Usage: ps3dm_aim [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help		Show this message and exit\n"
		"	-v, --verbose		Increase verbosity\n"
		"	-V, --version		Show version information and exit\n"
		"Commands:\n"
		"	get_dev_type		Returns device type\n"
		"	get_dev_id		Returns device id\n"
		"	get_ps_code		Returns ps code\n"
		"	get_open_ps_id		Returns open ps id\n"
		"\n\n"
		"Simple example: Get device type:\n"
		"	ps3dm_aim /dev/ps3dmproxy get_dev_type\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_aim " PS3DM_AIM_VERSION "\n"
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
 * cmd_get_dev_type
 */
static int cmd_get_dev_type(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_aim_get_dev_type *ss_aim_get_dev_type;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_aim_get_dev_type = (struct ps3ss_aim_get_dev_type *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_AIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_aim_get_dev_type);

	ss_hdr->packet_id = PS3SS_PID_AIM_GET_DEV_TYPE;
	ss_hdr->function_id = PS3SS_FID_AIM;
	ss_hdr->laid = PS3DM_AIM_LAID;
	ss_hdr->paid = PS3DM_AIM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);

		if (opts->do_verbose >= 2) {
			fprintf(stderr, "DM header:\n");

			for (i = 0; i < sizeof(*dm_hdr); i++)
				fprintf(stderr, "0x%02x ", *((uint8_t *) dm_hdr + i));

			fprintf(stderr, "\n");

			fprintf(stderr, "SS header:\n");

			for (i = 0; i < sizeof(*ss_hdr); i++)
				fprintf(stderr, "0x%02x ", *((uint8_t *) ss_hdr + i));

			fprintf(stderr, "\n");

			fprintf(stderr, "SS body:\n");

			for (i = 0; i < sizeof(struct ps3ss_aim_get_dev_type); i++)
				fprintf(stderr, "0x%02x ", *((uint8_t *) ss_hdr + sizeof(*ss_hdr) + i));

			fprintf(stderr, "\n");
		}
	} else {
		for (i = 0; i < sizeof(ss_aim_get_dev_type->field0); i++)
			fprintf(stdout, "0x%02x ", ss_aim_get_dev_type->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_dev_id
 */
static int cmd_get_dev_id(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_aim_get_dev_id *ss_aim_get_dev_id;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_aim_get_dev_id = (struct ps3ss_aim_get_dev_id *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_AIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_aim_get_dev_id);

	ss_hdr->packet_id = PS3SS_PID_AIM_GET_DEV_ID;
	ss_hdr->function_id = PS3SS_FID_AIM;
	ss_hdr->laid = PS3DM_AIM_LAID;
	ss_hdr->paid = PS3DM_AIM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		for (i = 0; i < sizeof(ss_aim_get_dev_id->field0); i++)
			fprintf(stdout, "0x%02x ", ss_aim_get_dev_id->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_ps_code
 */
static int cmd_get_ps_code(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_aim_get_ps_code *ss_aim_get_ps_code;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_aim_get_ps_code = (struct ps3ss_aim_get_ps_code *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_AIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_aim_get_ps_code);

	ss_hdr->packet_id = PS3SS_PID_AIM_GET_PS_CODE;
	ss_hdr->function_id = PS3SS_FID_AIM;
	ss_hdr->laid = PS3DM_AIM_LAID;
	ss_hdr->paid = PS3DM_AIM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		for (i = 0; i < sizeof(ss_aim_get_ps_code->field0); i++)
			fprintf(stdout, "0x%02x ", ss_aim_get_ps_code->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_open_ps_id
 */
static int cmd_get_open_ps_id(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_aim_get_open_ps_id *ss_aim_get_open_ps_id;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_aim_get_open_ps_id = (struct ps3ss_aim_get_open_ps_id *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_AIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_aim_get_open_ps_id);

	ss_hdr->packet_id = PS3SS_PID_AIM_GET_OPEN_PS_ID;
	ss_hdr->function_id = PS3SS_FID_AIM;
	ss_hdr->laid = PS3DM_AIM_LAID;
	ss_hdr->paid = PS3DM_AIM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		for (i = 0; i < sizeof(ss_aim_get_open_ps_id->field0); i++)
			fprintf(stdout, "0x%02x ", ss_aim_get_open_ps_id->field0[i]);

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

	if (!strcmp(opts.cmd, "get_dev_type")) {
		error = cmd_get_dev_type(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_dev_id")) {
		error = cmd_get_dev_id(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_ps_code")) {
		error = cmd_get_ps_code(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_open_ps_id")) {
		error = cmd_get_open_ps_id(fd, &opts, argc, argv);
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
