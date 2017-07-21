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
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>

#define ADDRP "%02X:%02X:%02X:%02X:%02X:%02X"
#define ADDR(x) x[0], x[1], x[2], x[3], x[4], x[5]

typedef struct __attribute__((packed)) {
    struct ethhdr hdr;
    uint8_t body[1508];
} eth_frame_t;

static const char *sopts = "hfw:d:";
static const struct option lopts[] = {
    { "help",       no_argument,       .val = 'h' },
    { "wan",        required_argument, .val = 'w' },
    { "dev",        required_argument, .val = 'd' },
    { "foreground", no_argument,       .val = 'f' },
    {}
};

static const char *usage =
"Usage: wirefraud -w WAN -d DEV [-f]"
"\n"
"\nWirefraud proxies 802.1x between the specified WAN and DEV interfaces."
"\n"
"\nBasically, you connect a client device (and nothing else) to the DEV"
"\ninterface and connect the uplink to the WAN interface. Wirefraud will"
"\nproxy only the 802.1x traffic between these two interfaces."
"\n"
"\nBy default, Wirefraud will daemonize for background operation. To run"
"\nit in the foreground, use the -f option."
"\n"
"\nWirefraud does not do any interface preparation or management. Therefore,"
"\na few extra steps may be necessary. If your network provider performs MAC"
"\naddress validation, you will need to clone the MAC address of the device"
"\nto the WAN interface. Likewise, if your network provider uses VLANs, you"
"\nshould set up VLAN interfaces to ensure proper tagging."
"\n"
"\n";

typedef char ifname_t[IFNAMSIZ];

static int
mksock(const ifname_t ifname)
{
    struct sockaddr_ll addr = {
        .sll_protocol = htons(ETH_P_PAE),
        .sll_family = PF_PACKET,
    };
    struct packet_mreq mreq = {
        .mr_address = "\x01\x80\xC2\x00\x00\x03",
        .mr_type = PACKET_MR_MULTICAST,
        .mr_alen = ETH_ALEN,
    };
    int sock;

    mreq.mr_ifindex = addr.sll_ifindex = if_nametoindex(ifname);
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

    /* Receive packets on the non-TPMR bridge group address. */
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        close(sock);
        return -errno;
    }

    return sock;
}

static bool
isup(const ifname_t ifname)
{
    struct ifreq ifr = { .ifr_addr.sa_family = AF_INET };
    bool ret = false;
    int sock = -1;

    strcpy(ifr.ifr_name, ifname);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFADDR, &ifr) == 0;
        close(sock);
    }

    return ret;
}

int
main(int argc, char* argv[])
{
    struct pollfd pfds[] = {
        { .events = POLLIN | POLLPRI },
        { .events = POLLIN | POLLPRI },
    };
    ifname_t wan = {};
    ifname_t dev = {};
    bool fg = false;

    for (int o; (o = getopt_long(argc, argv, sopts, lopts, NULL)) != -1; ) {
        switch (o) {
        case 'w': snprintf(wan, sizeof(wan), "%s", optarg); break;
        case 'd': snprintf(dev, sizeof(dev), "%s", optarg); break;
        case 'f': fg = true; break;
        default:
            fprintf(stderr, "%s", usage);
            return EX_USAGE;
        }
    }

    if (!wan[0] || !dev[0]) {
        fprintf(stderr, "%s", usage);
        return EX_USAGE;
    }

    pfds[0].fd = mksock(wan);
    if (pfds[0].fd < 0) {
        fprintf(stderr, "Error opening WAN socket! %m\n");
        goto error;
    }

    pfds[1].fd = mksock(dev);
    if (pfds[1].fd < 0) {
        fprintf(stderr, "Error opening LAN socket! %m\n");
        goto error;
    }

    if (!fg) {
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

                /* While the WAN is up, we drop packets. We do this to
                 * prevent additional packets from causing network
                 * connectivity to drop. However, if the WAN goes down,
                 * then we can start forwarding again. */
                if (isup(wan))
                    continue;

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
