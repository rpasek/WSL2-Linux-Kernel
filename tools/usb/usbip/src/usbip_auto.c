/*
 * Copyright (C) 2011 matt mooney <mfm@muteddisk.com>
 *               2005-2007 Takahiro Hirofuchi
 * Copyright (C) 2015-2016 Samsung Electronics
 *               Igor Kotrasinski <i.kotrasinsk@samsung.com>
 *               Krzysztof Opasiak <k.opasiak@samsung.com>
 * Copyright (C) 2019 Richard Pasek <richard.pasek@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include "vhci_driver.h"
#include "usbip_common.h"
#include "usbip_network.h"
#include "usbip.h"

extern int attach_device(char *host, char *busid);

static struct usbip_usb_device * alloc_fetch_exported_udevs(char *host, int * num_devices)
{
	int sockfd;
	struct op_devlist_reply reply;
	uint16_t code = OP_REP_DEVLIST;
	unsigned int i;
	int rc;
	int status;
	struct usbip_usb_device * udevs = NULL;

	sockfd = usbip_net_tcp_connect(host, usbip_port_string);
	if (sockfd < 0) {
		err("could not connect to %s:%s: %s", host,
			usbip_port_string, gai_strerror(sockfd));
		goto FAIL;
	}

	rc = usbip_net_send_op_common(sockfd, OP_REQ_DEVLIST, 0);
	if (rc < 0) {
		err("usbip_net_send_op_common failed");
		goto FAIL_AFTER_CONNECT;
	}

	rc = usbip_net_recv_op_common(sockfd, &code, &status);
	if (rc < 0) {
		err("Exported Device List Request failed - %s\n",
			usbip_op_common_status_string(status));
		goto FAIL_AFTER_CONNECT;
	}

	memset(&reply, 0, sizeof(reply));
	rc = usbip_net_recv(sockfd, &reply, sizeof(reply));
	if (rc < 0) {
		err("usbip_net_recv_op_devlist failed");
		goto FAIL_AFTER_CONNECT;
	}
	PACK_OP_DEVLIST_REPLY(0, &reply);

	if (reply.ndev == 0) {
		info("no exportable devices found on %s", host);
	} else {
		udevs = calloc(reply.ndev, sizeof(struct usbip_usb_device));
		if (udevs == NULL) {
			err("out of memory");
			goto FAIL_AFTER_CONNECT;
		}
	}

	for (i = 0; i < reply.ndev; i++) {
		rc = usbip_net_recv(sockfd, &udevs[i], sizeof(struct usbip_usb_device));
		if (rc < 0) {
			err("usbip_net_recv failed: usbip_usb_device[%d]", i);
			goto FAIL_AFTER_ALLOC;
		}
		usbip_net_pack_usb_device(0, &udevs[i]);
	}

	close(sockfd);
	*num_devices = reply.ndev; 
	return udevs;

FAIL_AFTER_ALLOC:
	free(udevs);
FAIL_AFTER_CONNECT:
	close(sockfd);
FAIL:
	*num_devices = -1; 
	return NULL;
}

static struct usbip_imported_device * alloc_fetch_imported_udevs(int * num_devices)
{
	int i;
	struct usbip_imported_device * idevs = NULL;
	int ret;
	int current_devices = 0;

	ret = usbip_vhci_driver_open();
	if (ret < 0) {
		err("open vhci_driver");
		goto FAIL;
	}

	if (vhci_driver->nports == 0) {
		info("no imported devices found");
	} else {
		idevs = calloc(vhci_driver->nports, sizeof(struct usbip_imported_device));
		if (idevs == NULL) {
			err("out of memory");
			goto FAIL_AFTER_OPEN;
		}
	}

	for (i = 0; i < vhci_driver->nports; i++) {
		if (vhci_driver->idev[i].status != VDEV_ST_NULL && vhci_driver->idev[i].status != VDEV_ST_NOTASSIGNED) {
			memcpy(&idevs[current_devices], &vhci_driver->idev[i], sizeof(struct usbip_imported_device));
			current_devices++;
		}
	}

	*num_devices = current_devices;
	usbip_vhci_driver_close();
	return idevs;

FAIL_AFTER_OPEN:
	usbip_vhci_driver_close();
FAIL:
	*num_devices = -1;
	return NULL;
}

static int detach_portnum(uint8_t portnum)
{
	int ret;
	char path[PATH_MAX+1];
	int i;
	struct usbip_imported_device *idev;
	bool found = false;

	ret = usbip_vhci_driver_open();
	if (ret < 0) {
		err("open vhci_driver");
		goto FAIL;
	}

	/* check for invalid port */
	for (i = 0; i < vhci_driver->nports; i++) {
		idev = &vhci_driver->idev[i];

		if (idev->port == portnum) {
			found = true;
			if (idev->status != VDEV_ST_NULL)
				break;
			info("Port %d is already detached!\n", idev->port);
			goto FAIL_AFTER_OPEN;
		}
	}

	if (!found) {
		err("Invalid port %d > maxports %d",
			portnum, vhci_driver->nports);
		goto FAIL_AFTER_OPEN;
	}

	/* remove the port state file */
	snprintf(path, PATH_MAX, VHCI_STATE_PATH"/port%d", portnum);

	remove(path);
	rmdir(VHCI_STATE_PATH);

	ret = usbip_vhci_detach_device(portnum);
	if (ret < 0) {
		err("Port %d detach request failed!\n", portnum);
		goto FAIL_AFTER_OPEN;
	}

FAIL_AFTER_OPEN:
	usbip_vhci_driver_close();
FAIL:
	return -1;
}

static const char usbip_auto_usage_string[] =
	"usbip auto <args>\n"
	"    -r, --remote=<host>      The machine with exported USB devices\n";

void usbip_auto_usage(void)
{
	printf("usage: %s", usbip_auto_usage_string);
}

int usbip_auto(int argc, char *argv[])
{			
	static const struct option opts[] = {
		{ "remote", required_argument, NULL, 'r' },
		{ NULL, 0,  NULL, 0 }
	};
	char *host = NULL;
	int opt;
	struct usbip_imported_device * imported_idevs = NULL;
	int imported_idevs_num, imported_index;
	struct usbip_usb_device * exported_udevs = NULL;
	int exported_udevs_num, exported_index;
	bool needs_attaching;
	bool needs_detaching;
	char busid_tmp[SYSFS_BUS_ID_SIZE];

	for (;;) {
		opt = getopt_long(argc, argv, "r", opts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'r':
			host = optarg;
			break;
		default:
			usbip_auto_usage();
			goto FAIL;
		}
	}

	if (!host) {
		usbip_auto_usage();
		goto FAIL;
	}

	while (1) {
		imported_idevs = alloc_fetch_imported_udevs(&imported_idevs_num);
		if (imported_idevs_num == -1) {
			err("Couldn't fetch imported devices");
			goto FAIL;
		}

		exported_udevs = alloc_fetch_exported_udevs(host, &exported_udevs_num);
		if (exported_udevs_num == -1) {
			err("Couldn't fetch exported devices");
			goto FAIL;
		}

		for (imported_index = 0; imported_index < imported_idevs_num; imported_index++) {
			needs_detaching = true;
				for (exported_index = 0; exported_index < exported_udevs_num; exported_index++) {
				sprintf(busid_tmp, "%d-%d", imported_idevs[imported_index].busnum, imported_idevs[imported_index].devnum);
				if (!strncmp(exported_udevs[exported_index].busid, busid_tmp, SYSFS_BUS_ID_SIZE) &&
							 exported_udevs[exported_index].idVendor == imported_idevs[imported_index].udev.idVendor &&
							 exported_udevs[exported_index].idProduct == imported_idevs[imported_index].udev.idProduct) {
					needs_detaching = false;
					break;
				}
			}
			if (needs_detaching) {
				info("detaching %s, vid=%x, pid=%x", busid_tmp, imported_idevs[imported_index].udev.idVendor, imported_idevs[imported_index].udev.idProduct);
				detach_portnum(imported_idevs[imported_index].port);
			}
		}

		for (exported_index = 0; exported_index < exported_udevs_num; exported_index++) {
			needs_attaching = false;
			for (imported_index = 0; imported_index < imported_idevs_num; imported_index++) {
				sprintf(busid_tmp, "%d-%d", imported_idevs[imported_index].busnum, imported_idevs[imported_index].devnum);
				if (!strncmp(exported_udevs[exported_index].busid, busid_tmp, SYSFS_BUS_ID_SIZE) &&
							 exported_udevs[exported_index].idVendor == imported_idevs[imported_index].udev.idVendor &&
							 exported_udevs[exported_index].idProduct == imported_idevs[imported_index].udev.idProduct) {
					needs_attaching = true;
					break;
				}
			}
			if (!needs_attaching) {
				info("attaching %s, vid=%x, pid=%x", exported_udevs[exported_index].busid, exported_udevs[exported_index].idVendor, exported_udevs[exported_index].idProduct);
				attach_device(host, exported_udevs[exported_index].busid);
			}
		}

		if (imported_idevs) {
			free(imported_idevs);
			imported_idevs = NULL;
		}
		if (exported_udevs) {
			free(exported_udevs);
			exported_udevs = NULL;
		}
		
		sleep(3);
	}

FAIL:
	if (imported_idevs) {
		free(imported_idevs);
		imported_idevs = NULL;
	}
	if (exported_udevs) {
		free(exported_udevs);
		exported_udevs = NULL;
	}
	return -1;
}
