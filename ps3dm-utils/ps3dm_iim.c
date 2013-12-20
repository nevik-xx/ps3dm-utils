
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

#define PS3DM_IIM_VERSION		"0.0.1"

#define PS3DM_IIM_LAID			0x1070000002000001ull
#define PS3DM_IIM_PAID			0x1070000300000001ull

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
		"Usage: ps3dm_iim [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help			Show this message and exit\n"
		"	-v, --verbose			Increase verbosity\n"
		"	-V, --version			Show version information and exit\n"
		"Commands:\n"
		"	get_data_size INDEX 		Returns data size by index\n"
		"	get_data INDEX			Returns data by index\n"
		"		INDEX:\n"
		"			0x0		EID0\n"
		"			0x4		EID4\n"
		"			0x1000		metldr\n"
		"	get_cisd_size 			Returns cISD size\n"
		"\n\n"
		"Simple example: Get size of EID0:\n"
		"	ps3dm_iim /dev/ps3dmproxy get_data_size 0\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_iim " PS3DM_IIM_VERSION "\n"
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
 * cmd_get_data_size
 */
static int cmd_get_data_size(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t data_index;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_iim_get_data_size *ss_iim_get_data_size;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No data index specified\n");
		return -1;
	}

	data_index = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid data index specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_iim_get_data_size = (struct ps3ss_iim_get_data_size *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_IIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_data_size);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_data_size);

	ss_hdr->packet_id = PS3SS_PID_IIM_GET_DATA_SIZE;
	ss_hdr->function_id = PS3SS_FID_IIM;
	ss_hdr->laid = PS3DM_IIM_LAID;
	ss_hdr->paid = PS3DM_IIM_PAID;

	ss_iim_get_data_size->index = data_index;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%016lx\n", ss_iim_get_data_size->size);
	}

	return error;
}

/*
 * cmd_get_data
 */
static int cmd_get_data(int fd, struct opts *opts, int argc, char **argv)
{
#define BUF_SIZE	0x900

	uint64_t data_index;
	char *endptr;
	uint8_t buf[128 + BUF_SIZE];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_iim_get_data *ss_iim_get_data;
	uint64_t data_size;
	int error, i;

	if (optind >= argc) {
		fprintf(stderr, "No data index specified\n");
		return -1;
	}

	data_index = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid data index specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_iim_get_data = (struct ps3ss_iim_get_data *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_IIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_data) +
		BUF_SIZE + sizeof(uint64_t);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_data) +
		BUF_SIZE + sizeof(uint64_t);

	ss_hdr->packet_id = PS3SS_PID_IIM_GET_DATA;
	ss_hdr->function_id = PS3SS_FID_IIM;
	ss_hdr->laid = PS3DM_IIM_LAID;
	ss_hdr->paid = PS3DM_IIM_PAID;

	ss_iim_get_data->index = data_index;
	ss_iim_get_data->buf_size = BUF_SIZE;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		data_size = *(uint64_t *) (ss_iim_get_data->buf + ss_iim_get_data->buf_size);

		for (i = 0; i < data_size; i++)
			fprintf(stdout, "%c", ss_iim_get_data->buf[i]);
	}

	return error;

#undef BUF_SIZE
}

/*
 * cmd_get_cisd_size
 */
static int cmd_get_cisd_size(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_iim_get_cisd_size *ss_iim_get_cisd_size;
	int error;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_iim_get_cisd_size = (struct ps3ss_iim_get_cisd_size *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_IIM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_cisd_size);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_iim_get_cisd_size);

	ss_hdr->packet_id = PS3SS_PID_IIM_GET_CISD_SIZE;
	ss_hdr->function_id = PS3SS_FID_IIM;
	ss_hdr->laid = PS3DM_IIM_LAID;
	ss_hdr->paid = PS3DM_IIM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%016lx\n", ss_iim_get_cisd_size->size);
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

	if (!strcmp(opts.cmd, "get_data")) {
		error = cmd_get_data(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_data_size")) {
		error = cmd_get_data_size(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_cisd_size")) {
		error = cmd_get_cisd_size(fd, &opts, argc, argv);
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
