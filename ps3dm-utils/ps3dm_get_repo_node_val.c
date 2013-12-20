
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
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "ps3dm_proxy.h"

#define PS3DM_GET_REPO_NODE_VAL_VERSION		"0.0.1"

struct opts {
	char *device_name;
	uint64_t lpar_id;
	uint64_t key[4];
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
		"Usage: ps3dm_get_repo_node_val [OPTIONS] DEVICE LPARID KEY0 KEY1 KEY2 KEY3\n"
		"\n"
		"Options:\n"
		"	-h, --help		Show this message and exit\n"
		"	-v, --verbose		Increase verbosity\n"
		"	-V, --version		Show version information and exit\n"
		"\n\n"
		"Simple example: Get value of repository node ss.laid.1:\n"
		"	ps3dm_get_repo_node_val /dev/ps3dmproxy 1 0x0000000073730000 "
		"0x6c61696400000000 0x0000000000000001 0x0000000000000000\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_get_repo_node_val " PS3DM_GET_REPO_NODE_VAL_VERSION "\n"
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
	int c, i;
	char *opt, *endptr;

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
		fprintf(stderr, "No lpar id specified\n");
		return -1;
	}

	opt = argv[optind++];
	opts->lpar_id = strtoull(opt, &endptr, 0);
	if ((*opt == '\0') || (*endptr != '\0')) {
		fprintf(stderr, "Invalid lpar id '%s'\n", opt);
		return -1;
	}

	for (i = 0; i < 4; i++) {
		if (optind >= argc) {
			fprintf(stderr, "No key #%d specified\n", i);
			return -1;
		}

		opt = argv[optind++];
		opts->key[i] = strtoull(opt, &endptr, 0);
		if ((*opt == '\0') || (*endptr != '\0')) {
			fprintf(stderr, "Invalid key #%d '%s'\n", i, opt);
			return -1;
		}
	}

	return 0;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	struct opts opts;
	int fd = 0, error = 0;
	uint64_t val[2];

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

	if (opts.do_verbose) {
		fprintf(stderr, "lpar id 0x%016lx\n", opts.lpar_id);

		fprintf(stderr, "repo node key 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
			opts.key[0], opts.key[1], opts.key[2], opts.key[3]);
	}

	error = ps3dm_proxy_get_repo_node_val(fd, opts.lpar_id, opts.key, val);
	if (error) {
		fprintf(stderr, "%s: %s\n", opts.device_name, strerror(errno));
		error = 3;
		goto done;
	}

	fprintf(stdout, "0x%016lx 0x%016lx\n", val[0], val[1]);

done:

	if (fd >= 0)
		ps3dm_proxy_close(fd);

	exit(error);
}
