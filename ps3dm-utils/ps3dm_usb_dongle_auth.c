
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

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "ps3dm_proxy.h"
#include "ps3dm.h"
#include "ps3ss.h"

#define PS3DM_USB_DONGLE_AUTH_VERSION		"0.0.1"

#define PS3DM_USB_DONGLE_AUTH_LAID		0x1070000002000001ull
#define PS3DM_USB_DONGLE_AUTH_PAID		0x1070000044000001ull

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

static uint8_t usb_dongle_master_key[] = {
	0x46, 0xdc, 0xea, 0xd3, 0x17, 0xfe, 0x45, 0xd8, 0x09, 0x23,
	0xeb, 0x97, 0xe4, 0x95, 0x64, 0x10, 0xd4, 0xcd, 0xb2, 0xc2
};

/*
 * usage
 */
static void usage(void) {
	fprintf(stderr,
		"Usage: ps3dm_usb_dongle_auth [OPTIONS] DEVICE COMMAND [ARGS]\n"
		"\n"
		"Options:\n"
		"	-h, --help			Show this message and exit\n"
		"	-v, --verbose			Increase verbosity\n"
		"	-V, --version			Show version information and exit\n"
		"Commands:\n"
		"	gen_challenge			Generates challenge\n"
		"	verify_resp DONGLEID RESPONSE	Verifies response\n"
		"	gen_resp DONGLEID CHALLENGE	Generates valid response for challenge\n"
		"\n\n"
		"Simple example: Generate challenge:\n"
		"	ps3dm_usb_dongle_auth /dev/ps3dmproxy gen_challenge\n");
}

/*
 * version
 */
static void version(void)
{
	fprintf(stderr,
		"ps3dm_usb_dongle_auth " PS3DM_USB_DONGLE_AUTH_VERSION "\n"
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
 * cmd_gen_challenge
 */
static int cmd_gen_challenge(int fd, struct opts *opts, int argc, char **argv)
{
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_usb_dongle_auth_gen_challenge *ss_usb_dongle_auth_gen_challenge;
	int error, i;

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_usb_dongle_auth_gen_challenge = (struct ps3ss_usb_dongle_auth_gen_challenge *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_USB_DONGLE_AUTH;
	dm_hdr->request_size = PS3SS_HDR_SIZE;
	dm_hdr->response_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_usb_dongle_auth_gen_challenge);

	ss_hdr->packet_id = PS3SS_PID_USB_DONGLE_AUTH_GEN_CHALLENGE;
	ss_hdr->function_id = PS3SS_FID_USB_DONGLE_AUTH;
	ss_hdr->laid = PS3DM_USB_DONGLE_AUTH_LAID;
	ss_hdr->paid = PS3DM_USB_DONGLE_AUTH_PAID;

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error) {
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	} else if (ss_hdr->retval != 0) {
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);
	} else {
		if (opts->do_verbose) {
			fprintf(stdout, "Challenge header:\n");

			for (i = 0; i < sizeof(ss_usb_dongle_auth_gen_challenge->header); i++)
				fprintf(stdout, "0x%02x ", ss_usb_dongle_auth_gen_challenge->header[i]);

			fprintf(stdout, "\n");
		}

		for (i = 0; i < sizeof(ss_usb_dongle_auth_gen_challenge->challenge); i++)
			fprintf(stdout, "0x%02x ", ss_usb_dongle_auth_gen_challenge->challenge[i]);

		fprintf(stdout, "\n");
	}

	return error;
}

/*
 * cmd_verify_resp
 */
static int cmd_verify_resp(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t dongle_id, val;
	uint8_t response[20];
	int response_size = 0;
	char *endptr;
	uint8_t buf[128];
	struct ps3dm_hdr *dm_hdr;
	struct ps3ss_hdr *ss_hdr;
	struct ps3ss_usb_dongle_auth_verify_resp *ss_usb_dongle_auth_verify_resp;
	int error;

	if (optind >= argc) {
		fprintf(stderr, "No dongle id specified\n");
		return -1;
	}

	dongle_id = strtoul(argv[optind], &endptr, 0);
	if ((*endptr != '\0') || (dongle_id > 0xffff)) {
		fprintf(stderr, "Invalid dongle id specified: %s\n", argv[optind]);
		return -1;
	}

	optind++;

	while (optind < argc) {
		val = strtoul(argv[optind], &endptr, 0);
		if ((*endptr != '\0') || (val > 0xff)) {
			fprintf(stderr, "Invalid response specified: %s\n", argv[optind]);
			return -1;
		}

		optind++;

		response[response_size++] = val;

		if (response_size == 20)
			break;
	}

	if (response_size < 20) {
		fprintf(stderr, "Response should be of size 20 bytes\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	dm_hdr = (struct ps3dm_hdr *) buf;
	ss_hdr = (struct ps3ss_hdr *)(dm_hdr + 1); 
	ss_usb_dongle_auth_verify_resp = (struct ps3ss_usb_dongle_auth_verify_resp *)(ss_hdr + 1); 

	dm_hdr->request_id = 1;
	dm_hdr->function_id = PS3SS_FID_USB_DONGLE_AUTH;
	dm_hdr->request_size = PS3SS_HDR_SIZE + sizeof(struct ps3ss_usb_dongle_auth_verify_resp);
	dm_hdr->response_size = PS3SS_HDR_SIZE;

	ss_hdr->packet_id = PS3SS_PID_USB_DONGLE_AUTH_VERIFY_RESP;
	ss_hdr->function_id = PS3SS_FID_USB_DONGLE_AUTH;
	ss_hdr->laid = PS3DM_USB_DONGLE_AUTH_LAID;
	ss_hdr->paid = PS3DM_USB_DONGLE_AUTH_PAID;

	ss_usb_dongle_auth_verify_resp->header[0] = 0x2e;
	ss_usb_dongle_auth_verify_resp->header[1] = 0x02;
	ss_usb_dongle_auth_verify_resp->header[2] = 0x02;
	ss_usb_dongle_auth_verify_resp->dongle_id = dongle_id;
	memcpy(ss_usb_dongle_auth_verify_resp->response, response, sizeof(response));

	error = ps3dm_proxy_do_request(fd, dm_hdr, PS3DM_HDR_SIZE + dm_hdr->request_size,
		dm_hdr, PS3DM_HDR_SIZE + dm_hdr->response_size);

	if (error)
		fprintf(stderr, "%s: %s\n", opts->device_name, strerror(errno));
	else
		fprintf(stderr, "%s: SS retval %d\n", opts->device_name, ss_hdr->retval);

	return error;
}

/*
 * cmd_gen_resp
 */
static int cmd_gen_resp(int fd, struct opts *opts, int argc, char **argv)
{
	uint32_t val;
	uint16_t dongle_id;
	uint8_t challenge[20], dongle_key[20], response[20];
	int challenge_size = 0;
	char *endptr;
	int i;

	if (optind >= argc) {
		fprintf(stderr, "No dongle id specified\n");
		return -1;
	}

	val = strtoul(argv[optind], &endptr, 0);
	if ((*endptr != '\0') || (val > 0xffff)) {
		fprintf(stderr, "Invalid dongle id specified: %s\n", argv[optind]);
		return -1;
	}

	dongle_id = val;
	optind++;

	while (optind < argc) {
		val = strtoul(argv[optind], &endptr, 0);
		if ((*endptr != '\0') || (val > 0xff)) {
			fprintf(stderr, "Invalid challenge specified: %s\n", argv[optind]);
			return -1;
		}

		optind++;

		challenge[challenge_size++] = val;

		if (challenge_size == 20)
			break;
	}

	if (challenge_size < 20) {
		fprintf(stderr, "Challenge should be of size 20 bytes\n");
		return -1;
	}

	HMAC(EVP_sha1(), usb_dongle_master_key, sizeof(usb_dongle_master_key),
		(uint8_t *) &dongle_id, sizeof(dongle_id), dongle_key, NULL);

	if (opts->do_verbose) {
		fprintf(stdout, "USB dongle key:\n");

		for (i = 0; i < sizeof(dongle_key); i++)
			fprintf(stdout, "0x%02x ", dongle_key[i]);

		fprintf(stdout, "\n");
	}

	HMAC(EVP_sha1(), dongle_key, sizeof(dongle_key),
		challenge, sizeof(challenge), response, NULL);

	for (i = 0; i < sizeof(response); i++)
		fprintf(stdout, "0x%02x ", response[i]);

	fprintf(stdout, "\n");

	return 0;
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

	if (!strcmp(opts.cmd, "gen_challenge")) {
		error = cmd_gen_challenge(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "verify_resp")) {
		error = cmd_verify_resp(fd, &opts, argc, argv);
	} else if (!strcmp(opts.cmd, "gen_resp")) {
		error = cmd_gen_resp(fd, &opts, argc, argv);
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
