
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

#define PS3DM_SCM_VERSION		"0.0.1"

#define PS3DM_SCM_LAID			0x1070000002000001ull
#define PS3DM_SCM_PAID			0x10700003ff000001ull

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
		"Usage: ps3dm_scm [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help			Show this message and exit\n"
		"	-v, --verbose			Increase verbosity\n"
		"	-V, --version			Show version information and exit\n"
		"Commands:\n"
		"	get_region_data ID		Reads region data\n"
		"	get_time TID			Returns RTC time\n"
		"	read_eprom OFFSET SIZE		Reads EPROM data\n"
		"	get_sc_status 			Returns SYSCON status\n"
		"\n\n"
		"Simple example: Get SYSCON status:\n"
		"	ps3dm_scm /dev/ps3dmproxy get_sc_status\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_scm " PS3DM_SCM_VERSION "\n"
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
 * cmd_get_region_data
 */
static int cmd_get_region_data(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t id;
	char *endptr;
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_scm_get_region_data *ss_scm_get_region_data;
	int error, i;

	if (optind >= argc) {
		fprintf(stderr, "No id specified\n");
		return -1;
	}

	id = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid id specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_scm_get_region_data = (struct ps3ss_scm_get_region_data *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SCM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_region_data) + 0x30;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_region_data) + 0x30;

	ss_hdr->packet_id = PS3SS_PID_SCM_GET_REGION_DATA;
	ss_hdr->function_id = PS3SS_FID_SCM;
	ss_hdr->laid = PS3DM_SCM_LAID;
	ss_hdr->paid = PS3DM_SCM_PAID;

	ss_scm_get_region_data->id = id;
	ss_scm_get_region_data->data_size = 0x30;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < ss_scm_get_region_data->data_size; i++)
			fprintf(stdout, "0x%02x ", ss_scm_get_region_data->data[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_time
 */
static int cmd_get_time(int fd, struct opts *opts, int argc, char **argv)
{
	uint64_t tid;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_scm_get_time *ss_scm_get_time;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No TID specified\n");
		return -1;
	}

	tid = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid TID specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_scm_get_time = (struct ps3ss_scm_get_time *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SCM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_time);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_time);

	ss_hdr->packet_id = PS3SS_PID_SCM_GET_TIME;
	ss_hdr->function_id = PS3SS_FID_SCM;
	ss_hdr->laid = PS3DM_SCM_LAID;
	ss_hdr->paid = PS3DM_SCM_PAID;

	ss_scm_get_time->tid = tid;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%016lx 0x%016lx\n", ss_scm_get_time->field8,
			ss_scm_get_time->field10);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_read_eprom
 */
static int cmd_read_eprom(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t eprom_offset;
	uint64_t size;
	char *endptr;
	uint8_t buf[512];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_scm_read_eprom *ss_scm_read_eprom;
	int error, i;

	if (optind >= argc) {
		fprintf(stderr, "No EPROM offset specified\n");
		return -1;
	}

	eprom_offset = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid EPROM offset specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No size specified\n");
		return -1;
	}

	size = strtoull(argv[optind], &endptr, 0);
	if ((*endptr != '\0') || (size > 0x100)) {
		fprintf(stderr, "Invalid size specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_scm_read_eprom = (struct ps3ss_scm_read_eprom *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SCM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_read_eprom) + size;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_read_eprom) + size;

	ss_hdr->packet_id = PS3SS_PID_SCM_READ_EPROM;
	ss_hdr->function_id = PS3SS_FID_SCM;
	ss_hdr->laid = PS3DM_SCM_LAID;
	ss_hdr->paid = PS3DM_SCM_PAID;

	ss_scm_read_eprom->offset = eprom_offset;
	ss_scm_read_eprom->nread = size;
	ss_scm_read_eprom->buf_size = size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < ss_scm_read_eprom->nread; i++)
			fprintf(stdout, "0x%02x ", ss_scm_read_eprom->buf[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_get_sc_status
 */
static int cmd_get_sc_status(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_scm_get_sc_status *ss_scm_get_sc_status;
	int error;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_scm_get_sc_status = (struct ps3ss_scm_get_sc_status *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_SCM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_sc_status);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_scm_get_sc_status);

	ss_hdr->packet_id = PS3SS_PID_SCM_GET_SC_STATUS;
	ss_hdr->function_id = PS3SS_FID_SCM;
	ss_hdr->laid = PS3DM_SCM_LAID;
	ss_hdr->paid = PS3DM_SCM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%08x 0x%08x\n", ss_scm_get_sc_status->version,
			ss_scm_get_sc_status->mode);
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

	if (!strcmp(opts.cmd, "get_region_data")) {
		error = cmd_get_region_data(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_time")) {
		error = cmd_get_time(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "read_eprom")) {
		error = cmd_read_eprom(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_sc_status")) {
		error = cmd_get_sc_status(fd, &opts, argc, argv);
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
