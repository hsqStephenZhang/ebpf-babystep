#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <getopt.h>
#include <signal.h>

#include "libbpf.h"
#include <bpf/bpf.h>

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 3

static const char *__doc__ = " XDP demo";

static char ifname_buf[IF_NAMESIZE];

static char *ifname = NULL;
static int ifindex = -1;
static __u32 prog_id = -1;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "progname", required_argument, NULL, 'p' },
	{ "dev", required_argument, NULL, 'd' },
	{ 0, 0, NULL, 0 }
};

static void print_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	bpf_object__for_each_program(pos, obj)
	{
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__title(pos, false));
	}
}

static void usage(char *argv[], struct bpf_object *obj)
{
	int i;

	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c", long_options[i].val);
		printf("\n");
	}
	printf("\n Programs to be used for --progname:\n");
	print_avail_progs(obj);
	printf("\n");
}

int find_map_fd(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map;
	int map_fd = -1;
	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		fprintf(stderr, "Map %s not found\n", map_name);
	}
	map_fd = bpf_map__fd(map);
	return map_fd;
}

void status_collect(int map_fd)
{
	__u64 cnt;
	int ret = bpf_map_lookup_elem(map_fd, &ifindex, &cnt);
	if (ret != 0) {
		fprintf(stderr, "bpf_map_lookup_elem failed");
	} else {
		printf("rx packet cnt on ifindex %d:%d\n", ifindex, cnt);
	}
}

void stats_poll(int map_fd, int interval)
{
	status_collect(map_fd);

	while (1) {
		status_collect(map_fd);
		sleep(interval);
	}
}

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (ifindex > -1) {
		if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
			printf("bpf_get_link_xdp_id failed\n");
			exit(EXIT_FAIL);
		}
		if (prog_id == curr_prog_id) {
			fprintf(stderr,
				"Interrupted: Removing XDP program on ifindex:%d device:%s\n",
				ifindex, ifname);
			bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		} else if (!curr_prog_id) {
			printf("couldn't find a prog id on a given iface\n");
		} else {
			printf("program on interface changed, not removing\n");
		}
	}

	exit(EXIT_OK);
}

int main(int argc, char **argv)
{
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	char *prog_name = "xdp_pass";

	int err = 0;
	int opt = 0;
	int attach = 0;
	int longindex = 0;

	int prog_fd = 0;
	char filename[256];
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_prog_info info = {};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
	};

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return EXIT_FAIL;

	if (prog_fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
			strerror(errno));
		return EXIT_FAIL;
	}

	while ((opt = getopt_long(argc, argv, "hSd:s:p:q:c:xzF", long_options,
				  &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'p':
			prog_name = optarg;
			break;
		case 'h':
		error:
		default:
			usage(argv, obj);
			return EXIT_FAIL_OPTION;
		}
	}

	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv, obj);
		return EXIT_FAIL_OPTION;
	}

	prog = bpf_object__find_program_by_title(obj, prog_name);

	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_title failed\n");
		print_avail_progs(obj);
		return EXIT_FAIL;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "bpf_program__fd failed\n");
		return EXIT_FAIL;
	}

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "link set xdp fd failed\n");
		return EXIT_FAIL_XDP;
	}

	__u32 info_len = sizeof(info);
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	} else {
		printf("Success: Loading "
		       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
		       info.name, info.id, ifname, ifindex);
	}

	prog_id = info.id;

	int map_fd = find_map_fd(obj, "nic_rx_cnt_map");

	stats_poll(map_fd, 1);

	return 0;
}