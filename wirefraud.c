/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2017 Nathaniel McCallum <nathaniel@mccallum.life>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <sysexits.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>

#define ADDRP "%02X:%02X:%02X:%02X:%02X:%02X"
#define ADDR(x) x[0], x[1], x[2], x[3], x[4], x[5]

typedef struct __attribute__((packed)) {
    struct ethhdr hdr;
    uint8_t body[1508];
} eth_frame_t;

static const char *sopts = "dw:l:";
static const struct option lopts[] = {
    { "wan",       required_argument, .val = 'w' },
    { "lan",       required_argument, .val = 'l' },
    { "daemonize", no_argument,       .val = 'd' },
    {}
};

static const char *usage =
"Usage: wirefraud -w WAN -l LAN [-d]"
"\n"
"\nThis program proxies 802.1x packets between the specified WAN and LAN ports."
"\n"
"\nBasically, you connect a client device (and nothing else) to the LAN port"
"\nand connect the uplink to the WAN port. This program will proxy only the"
"\n802.1x traffic between these two ports. Normally, this program will never"
"\nexit. To run this program in daemon (background) mode, use the -d option."
"\n"
"\nNOTE WELL: This program does not do any interface preparation or management."
"\n           It is your responsibility to clone the MAC address of the client"
"\n           device onto the WAN interface and bring it up. Similarly, you are"
"\n           responsible to bring up the LAN interface in promiscuous mode."
"\n"
"\n           Usually, WAN configuration just follows your standard operating"
"\n           system conventions (NetworkManager, init scripts, et cetera). If "
"\n           these conventions don't work for your LAN port as well, this"
"\n           command should be sufficient: ifconfig LAN promisc up"
"\n"
"\n";

static int
mksock(const char *ifname)
{
    struct sockaddr_ll addr = {
        .sll_protocol = htons(ETH_P_PAE),
        .sll_family = PF_PACKET,
    };
    int sock;

    addr.sll_ifindex = if_nametoindex(ifname);
    if (addr.sll_ifindex == 0)
        return -errno;

    /* Open a raw socket which is filtered on 802.1x packets. */
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
    if (sock < 0)
        return -errno;

    /* Only receive packets from the specified interface. */
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        close(sock);
        return -errno;
    }

    return sock;
}

int
main(int argc, char* argv[])
{
    struct pollfd pfds[] = {
        { .events = POLLIN | POLLPRI },
        { .events = POLLIN | POLLPRI },
    };
    char wan[IFNAMSIZ + 1] = {};
    char lan[IFNAMSIZ + 1] = {};
    bool daemonize = false;

    for (int o; (o = getopt_long(argc, argv, sopts, lopts, NULL)) != -1; ) {
        switch (o) {
        case 'w': snprintf(wan, sizeof(wan), "%s", optarg); break;
        case 'l': snprintf(lan, sizeof(lan), "%s", optarg); break;
        case 'd': daemonize = true; break;
        default:
            fprintf(stderr, "%s", usage);
            return EX_USAGE;
        }
    }

    if (!wan[0] || !lan[0]) {
        fprintf(stderr, "%s", usage);
        return EX_USAGE;
    }

    pfds[0].fd = mksock(wan);
    if (pfds[0].fd < 0) {
        fprintf(stderr, "Error opening WAN socket! %m\n");
        goto error;
    }

    pfds[1].fd = mksock(lan);
    if (pfds[1].fd < 0) {
        fprintf(stderr, "Error opening LAN socket! %m\n");
        goto error;
    }

    if (daemonize) {
        pid_t pid;

        pid = fork();
        if (pid == -1) {
            fprintf(stderr, "Error during fork()! %m\n");
            goto error;
        }

        if (pid > 0) {
            close(pfds[0].fd);
            close(pfds[1].fd);
            return EX_OK;
        }

        umask(0);
        setsid();
        chdir("/");
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
    }

    while (poll(pfds, 2, -1) > 0) {
        for (size_t i = 0; i < 2; i++) {
            if (pfds[i].revents & (POLLIN | POLLPRI)) {
                eth_frame_t frame = {};
                ssize_t r = 0;

                r = read(pfds[i].fd, &frame, sizeof(frame));
                if (r < 0) {
                    if (errno == EAGAIN)
                        continue;
                    goto error;
                }

                fprintf(stderr, "%c src:" ADDRP " dst:" ADDRP " prt:%02hX %zd\n",
                        i == 0 ? '>' : '<',
                        ADDR(frame.hdr.h_source),
                        ADDR(frame.hdr.h_dest),
                        ntohs(frame.hdr.h_proto), r);

                write(pfds[(i + 1) % 2].fd, &frame, r);
            }
        }
    }

error:
    for (size_t i = 0; i < sizeof(pfds) / sizeof(*pfds); i++) {
        if (pfds[i].fd >= 0)
            close(pfds[i].fd);
    }

    return EX_IOERR;
}
