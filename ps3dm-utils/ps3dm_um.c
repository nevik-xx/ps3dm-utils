
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
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "ps3dm_proxy.h"
#include "ps3dm.h"
#include "ps3ss.h"

#ifndef MAP_HUGETLB
#define MAP_HUGETLB				0x40000
#endif

#define PS3DM_UM_VERSION			"0.0.1"

#define PS3DM_UM_LAID				0x1070000002000001ull
#define PS3DM_UM_PAID				0x10700003ff000001ull

#define PS3DM_UM_LPAR_ID			2

#define PS3DM_UM_MAX_PKG_SIZE			(16 * 1024 * 1024)

#define PS3DM_UM_REPO_NODE_KEY_SS		0x0000000073730000ull
#define PS3DM_UM_REPO_NODE_KEY_UPDATE		0x7570646174650000ull
#define PS3DM_UM_REPO_NODE_KEY_INSPECT		0x696e737065637400ull
#define PS3DM_UM_REPO_NODE_KEY_EXTRACT		0x6578747261637400ull
#define PS3DM_UM_REPO_NODE_KEY_REQUEST		0x7265717565737400ull

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
		"Usage: ps3dm_um [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help				Show this message and exit\n"
		"	-v, --verbose				Increase verbosity\n"
		"	-V, --version				Show version information and exit\n"
		"Commands:\n"
		"	update_pkg TYPE FLAGS PKG		Updates package\n"
		"	inspect_pkg TYPE FLAGS PKG		Inspects package\n"
		"	get_pkg_info TYPE			Returns installed package information\n"
		"	get_fix_instr				Returns fix instruction\n"
		"	extract_pkg TYPE FLAGS PKG		Extracts package\n"
		"	get_token_seed				Returns token and seed\n"
		"	read_eprom OFFSET			Reads a value from EPROM\n"
		"	write_eprom OFFSET VALUE		Writes a value to EPROM\n"
		"	check_int				Checks integrity\n"
		"\n\n"
		"Simple example: Inspect package:\n"
		"	ps3dm_um /dev/ps3dmproxy inspect_pkg 1 0x9 CORE_OS_PACKAGE.pkg\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_um " PS3DM_UM_VERSION "\n"
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
 * mmap_huge_page
 */
static void *mmap_huge_page(int size)
{
	void *huge_page;
	int error;

	huge_page = mmap(0, PS3DM_UM_MAX_PKG_SIZE, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (!huge_page) {
		fprintf(stderr, "Allocate a huge page: %s\n", strerror(errno));
		return NULL;
	}

	error = mlock(huge_page, size);
	if (error) {
		fprintf(stderr, "Lock memory: %s\n", strerror(errno));
		return NULL;
	}

	return huge_page;
}

/*
 * load_pkg
 */
static void *load_pkg(const char *path, unsigned int *size)
{
	void *pkg;
	FILE *fp;
	int error;

	pkg = mmap_huge_page(PS3DM_UM_MAX_PKG_SIZE);
	if (!pkg)
		return NULL;

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Open package '%s': %s\n", path, strerror(errno));
		goto failed_munmap;
	}

	error = fseek(fp, 0, SEEK_END);
	if (error) {
		fprintf(stderr, "Seek package: %s\n", strerror(errno));
		goto failed_fclose;
	}

	*size = ftell(fp);
	if (!*size) {
		fprintf(stderr, "Package size is zero\n");
		goto failed_fclose;
	} else if (*size > PS3DM_UM_MAX_PKG_SIZE) {
		fprintf(stderr, "Package too large\n");
		goto failed_fclose;
	}

	error = fseek(fp, 0, SEEK_SET);
	if (error) {
		fprintf(stderr, "Seek package: %s\n", strerror(errno));
		goto failed_fclose;
	}

	error = fread(pkg, 1, *size, fp);
	if (error != *size) {
		fprintf(stderr, "Read package data: %s\n", strerror(errno));
		goto failed_fclose;
	}

	fclose(fp);

	return pkg;

failed_fclose:

	fclose(fp);

failed_munmap:

	munmap(pkg, PS3DM_UM_MAX_PKG_SIZE);

	return NULL;
}

/*
 * cmd_update_pkg
 */
static int cmd_update_pkg(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t pkg_type, flags;
	char *pkg_path, *endptr;
	void *pkg;
	unsigned int pkg_size;
	uint64_t pkg_lpar_addr;
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_update_pkg *ss_um_update_pkg;
	uint64_t request_id, key[4], val[2];
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No package type specified\n");
		return -1;
	}

	pkg_type = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid package type specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No flags specified\n");
		return -1;
	}

	flags = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid flags specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No package specified\n");
		return -1;
	}

	pkg_path = argv[optind];
	optind++;

	pkg = load_pkg(pkg_path, &pkg_size);
	if (!pkg) {
		fprintf(stderr, "Invalid package specified\n");
		return -1;
	}

	error = ps3dm_proxy_user_to_lpar_addr(fd, (uint64_t) pkg, &pkg_lpar_addr);
	if (error) {
		fprintf(stderr, "Convert user to lpar address: %s\n", strerror(errno));
		return error;
	}

	if (opts->do_verbose)
		fprintf(stderr, "package lpar address 0x%016lx size %d\n",
			pkg_lpar_addr, pkg_size);

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_update_pkg = (struct ps3ss_um_update_pkg *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t) + sizeof(uint64_t);

	ss_hdr->packet_id = PS3SS_PID_UM_UPDATE_PKG;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_update_pkg->in_lpar_mem = 1;
	ss_um_update_pkg->pkg_type = pkg_type;
	ss_um_update_pkg->flags = flags;
	ss_um_update_pkg->lpar_id = PS3DM_UM_LPAR_ID;
	ss_um_update_pkg->pkg_size = 1;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].lpar_addr = pkg_lpar_addr;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].size = pkg_size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	}

	if (ss_hdr->retval) {
		fprintf(stderr, "%s: top-half SS retval %d\n", opts->device_name, ss_hdr->retval);
		return -1;
	}

	request_id = *(uint64_t *) ((uint8_t *) ss_um_update_pkg +
		offsetof(struct ps3ss_um_update_pkg, pkg_data) + 3 * sizeof(uint64_t));

	key[0] = PS3DM_UM_REPO_NODE_KEY_SS;
	key[1] = PS3DM_UM_REPO_NODE_KEY_UPDATE;
	key[2] = PS3DM_UM_REPO_NODE_KEY_REQUEST;
	key[3] = request_id;

	fprintf(stdout, "%s: request id 0x%016lx\n", opts->device_name, request_id);

	while (1) {
		error = ps3dm_proxy_get_repo_node_val(fd, 1, key, val);
		if (error) {
			fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
			break;
		}

		if ((val[0] >> 32) == 3)
			break;

		usleep(1000);
	}

	fprintf(stdout, "%s: 0x%016lx 0x%016lx\n", opts->device_name, val[0], val[1]);

	return error;
}

/*
 * cmd_inspect_pkg
 */
static int cmd_inspect_pkg(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t pkg_type, flags;
	char *pkg_path, *endptr;
	void *pkg;
	unsigned int pkg_size;
	uint64_t pkg_lpar_addr;
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_update_pkg *ss_um_update_pkg;
	uint64_t request_id, key[4], val[2];
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No package type specified\n");
		return -1;
	}

	pkg_type = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid package type specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No flags specified\n");
		return -1;
	}

	flags = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid flags specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No package specified\n");
		return -1;
	}

	pkg_path = argv[optind];
	optind++;

	pkg = load_pkg(pkg_path, &pkg_size);
	if (!pkg) {
		fprintf(stderr, "Invalid package specified\n");
		return -1;
	}

	error = ps3dm_proxy_user_to_lpar_addr(fd, (uint64_t) pkg, &pkg_lpar_addr);
	if (error) {
		fprintf(stderr, "Convert user to lpar address: %s\n", strerror(errno));
		return error;
	}

	if (opts->do_verbose)
		fprintf(stderr, "package lpar address 0x%016lx size %d\n",
			pkg_lpar_addr, pkg_size);

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_update_pkg = (struct ps3ss_um_update_pkg *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t) + sizeof(uint64_t);

	ss_hdr->packet_id = PS3SS_PID_UM_INSPECT_PKG;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_update_pkg->in_lpar_mem = 1;
	ss_um_update_pkg->pkg_type = pkg_type;
	ss_um_update_pkg->flags = flags;
	ss_um_update_pkg->lpar_id = PS3DM_UM_LPAR_ID;
	ss_um_update_pkg->pkg_size = 1;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].lpar_addr = pkg_lpar_addr;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].size = pkg_size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	}

	if (ss_hdr->retval) {
		fprintf(stderr, "%s: top-half SS retval %d\n", opts->device_name, ss_hdr->retval);
		return -1;
	}

	request_id = *(uint64_t *) ((uint8_t *) ss_um_update_pkg +
		offsetof(struct ps3ss_um_update_pkg, pkg_data) + 3 * sizeof(uint64_t));

	key[0] = PS3DM_UM_REPO_NODE_KEY_SS;
	key[1] = PS3DM_UM_REPO_NODE_KEY_INSPECT;
	key[2] = PS3DM_UM_REPO_NODE_KEY_REQUEST;
	key[3] = request_id;

	fprintf(stdout, "%s: request id 0x%016lx\n", opts->device_name, request_id);

	while (1) {
		error = ps3dm_proxy_get_repo_node_val(fd, 1, key, val);
		if (error) {
			fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
			break;
		}

		if ((val[0] >> 32) == 3)
			break;

		usleep(1000);
	}

	fprintf(stdout, "%s: 0x%016lx 0x%016lx\n", opts->device_name, val[0], val[1]);

	return error;
}

/*
 * cmd_get_pkg_info
 */
static int cmd_get_pkg_info(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t pkg_type;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_get_pkg_info *ss_um_get_pkg_info;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No package type specified\n");
		return -1;
	}

	pkg_type = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid package type specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_get_pkg_info = (struct ps3ss_um_get_pkg_info *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_pkg_info);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_pkg_info);

	ss_hdr->packet_id = PS3SS_PID_UM_GET_PKG_INFO;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_get_pkg_info->type = pkg_type;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%016lx\n", ss_um_get_pkg_info->version);
	}

	return error;
}

/*
 * cmd_get_fix_instr
 */
static int cmd_get_fix_instr(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_get_fix_instr *ss_um_get_fix_instr;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_get_fix_instr = (struct ps3ss_um_get_fix_instr *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_fix_instr);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_fix_instr);

	ss_hdr->packet_id = PS3SS_PID_UM_GET_FIX_INSTR;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < sizeof(ss_um_get_fix_instr->field0); i++)
			fprintf(stdout, "0x%02x ", ss_um_get_fix_instr->field0[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_extract_pkg
 */
static int cmd_extract_pkg(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t pkg_type, flags;
	char *pkg_path, *endptr;
	void *pkg;
	unsigned int pkg_size;
	uint64_t pkg_lpar_addr;
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_update_pkg *ss_um_update_pkg;
	struct ps3ss_um_get_extract_pkg *ss_um_get_extract_pkg;
	uint64_t request_id, key[4], val[2];
	int error, i;

	if (optind >= argc) {
		fprintf(stderr, "No package type specified\n");
		return -1;
	}

	pkg_type = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid package type specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No flags specified\n");
		return -1;
	}

	flags = strtoul(argv[optind], &endptr, 0);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid flags specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	if (optind >= argc) {
		fprintf(stderr, "No package specified\n");
		return -1;
	}

	pkg_path = argv[optind];
	optind++;

	pkg = load_pkg(pkg_path, &pkg_size);
	if (!pkg) {
		fprintf(stderr, "Invalid package specified\n");
		return -1;
	}

	error = ps3dm_proxy_user_to_lpar_addr(fd, (uint64_t) pkg, &pkg_lpar_addr);
	if (error) {
		fprintf(stderr, "Convert user to lpar address: %s\n", strerror(errno));
		return error;
	}

	if (opts->do_verbose)
		fprintf(stderr, "package lpar address 0x%016lx size %d\n",
			pkg_lpar_addr, pkg_size);

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_update_pkg = (struct ps3ss_um_update_pkg *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_update_pkg) +
		3 * sizeof(uint64_t) + sizeof(uint64_t);

	ss_hdr->packet_id = PS3SS_PID_UM_EXTRACT_PKG;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_update_pkg->in_lpar_mem = 1;
	ss_um_update_pkg->pkg_type = pkg_type;
	ss_um_update_pkg->flags = flags;
	ss_um_update_pkg->lpar_id = PS3DM_UM_LPAR_ID;
	ss_um_update_pkg->pkg_size = 1;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].lpar_addr = pkg_lpar_addr;
	ss_um_update_pkg->pkg_data.lpar_mem_segs[0].size = pkg_size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
		return error;
	}

	if (ss_hdr->retval) {
		fprintf(stderr, "%s: top-half SS retval %d\n", opts->device_name, ss_hdr->retval);
		return -1;
	}

	request_id = *(uint64_t *) ((uint8_t *) ss_um_update_pkg +
		offsetof(struct ps3ss_um_update_pkg, pkg_data) + 3 * sizeof(uint64_t));

	key[0] = PS3DM_UM_REPO_NODE_KEY_SS;
	key[1] = PS3DM_UM_REPO_NODE_KEY_EXTRACT;
	key[2] = PS3DM_UM_REPO_NODE_KEY_REQUEST;
	key[3] = request_id;

	fprintf(stdout, "%s: request id 0x%016lx\n", opts->device_name, request_id);

	while (1) {
		error = ps3dm_proxy_get_repo_node_val(fd, 1, key, val);
		if (error) {
			fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
			break;
		}

		if ((val[0] >> 32) == 3)
			break;

		usleep(1000);
	}

	fprintf(stdout, "%s: 0x%016lx 0x%016lx\n", opts->device_name, val[0], val[1]);

	if (val[0] & 0xfffffffful)
		return -1;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_get_extract_pkg = (struct ps3ss_um_get_extract_pkg *)(ss_hdr + 1); 

	dm_hdr->request_id = 2;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_extract_pkg);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_extract_pkg);

	ss_hdr->packet_id = PS3SS_PID_UM_GET_EXTRACT_PKG;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_get_extract_pkg->in_lpar_mem = 1;
	ss_um_get_extract_pkg->field10 = 1;
	ss_um_get_extract_pkg->request_id = request_id;
	ss_um_get_extract_pkg->buf_size = pkg_size;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		for (i = 0; i < pkg_size; i++)
			fprintf(stdout, "%c", *((uint8_t *) pkg + i));
	}

	return error;
}

/*
 * cmd_get_token_seed
 */
static int cmd_get_token_seed(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[256];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_get_token_seed *ss_um_get_token_seed;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_get_token_seed = (struct ps3ss_um_get_token_seed *)(ss_hdr + 1);

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_token_seed);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_get_token_seed);

	ss_hdr->packet_id = PS3SS_PID_UM_GET_TOKEN_SEED;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_get_token_seed->token_size = sizeof(ss_um_get_token_seed->token);
	ss_um_get_token_seed->seed_size = sizeof(ss_um_get_token_seed->seed);

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "token:\n");

		for (i = 0; i < sizeof(ss_um_get_token_seed->token); i++)
			fprintf(stdout, "0x%02x ", ss_um_get_token_seed->token[i]);

		fprintf(stdout, "\n");

		fprintf(stdout, "seed:\n");

		for (i = 0; i < sizeof(ss_um_get_token_seed->seed); i++)
			fprintf(stdout, "0x%02x ", ss_um_get_token_seed->seed[i]);

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
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_read_eprom *ss_um_read_eprom;
	int error;

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

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_read_eprom = (struct ps3ss_um_read_eprom *)(ss_hdr + 1);

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_read_eprom);
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_read_eprom);

	ss_hdr->packet_id = PS3SS_PID_UM_READ_EPROM;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_read_eprom->offset = eprom_offset;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
		error = -1;
	} else {
		fprintf(stdout, "0x%02x\n", ss_um_read_eprom->val);
	}

	return error;
}

/*
 * cmd_write_eprom
 */
static int cmd_write_eprom(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t eprom_offset;
	uint32_t eprom_val;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_um_write_eprom *ss_um_write_eprom;
	int error;

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
		fprintf(stderr, "No EPROM value specified\n");
		return -1;
	}

	eprom_val = strtoul(argv[optind], &endptr, 0);
	if ((*endptr != '\0') || (eprom_val > 0xff)) {
		fprintf(stderr, "Invalid EPROM value specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_um_write_eprom = (struct ps3ss_um_write_eprom *)(ss_hdr + 1);

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_um_write_eprom);
	dm_hdr->response_size = PS3SS_HDR_SIZE;

	ss_hdr->packet_id = PS3SS_PID_UM_WRITE_EPROM;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

	ss_um_write_eprom->offset = eprom_offset;
	ss_um_write_eprom->val = eprom_val;

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
 * cmd_check_int
 */
static int cmd_check_int(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	int error;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_UM;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE;

	ss_hdr->packet_id = PS3SS_PID_UM_CHECK_INT;
	ss_hdr->function_id = PS3SS_FID_UM;
	ss_hdr->laid = PS3DM_UM_LAID;
	ss_hdr->paid = PS3DM_UM_PAID;

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

	if (!strcmp(opts.cmd, "update_pkg")) {
		error = cmd_update_pkg(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "inspect_pkg")) {
		error = cmd_inspect_pkg(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_pkg_info")) {
		error = cmd_get_pkg_info(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_fix_instr")) {
		error = cmd_get_fix_instr(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "extract_pkg")) {
		error = cmd_extract_pkg(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "get_token_seed")) {
		error = cmd_get_token_seed(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "read_eprom")) {
		error = cmd_read_eprom(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "write_eprom")) {
		error = cmd_write_eprom(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "check_int")) {
		error = cmd_check_int(fd, &opts, argc, argv);
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
