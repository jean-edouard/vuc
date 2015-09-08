/******************************************************************************
 * vusb.c
 *
 * OpenXT vUSB frontend driver
 *
 * Copyright (c) 2015, Assured Information Security, Inc.
 *
 * Author:
 * Ross Philipson <philipsonr@ainfosec.com>
 *
 * Previous version:
 * Julien Grall
 * Thomas Horsten
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* TODO
 * Use DMA buffers
 * Handle errors on internal cmds
 * Sleep/resume and recover functionality
 * Refactor vusb_put_urb and vusb_put_isochronous_urb into one function.
 * Add branch prediction
 */

#include <linux/mm.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) )
#include <linux/aio.h>
#endif

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/grant_table.h>

#include <xen/interface/io/usbif.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>

#include <linux/usb/hcd.h>

#define VUSB_INTERFACE_VERSION		3
#define VUSB_INVALID_REQ_ID		((u64)-1)

#define VUSB_PLATFORM_DRIVER_NAME	"vuc"
#define VUSB_HCD_DRIVER_NAME		"vuc-hcd"
#define VUSB_DRIVER_DESC		"Virtual USB Controller"
#define VUSB_DRIVER_VERSION		"1.0.0"
#define VUSB_POWER_BUDGET		5000 /* mA */

#define INDIRECT_PAGES_REQUIRED(p) (((p - 1)/USBIF_MAX_SEGMENTS_PER_IREQUEST) + 1)
#define MAX_INDIRECT_PAGES USBIF_MAX_SEGMENTS_PER_REQUEST
#define MAX_PAGES_FOR_INDIRECT_REQUEST (MAX_INDIRECT_PAGES * USBIF_MAX_SEGMENTS_PER_IREQUEST)
#define MAX_PAGES_FOR_INDIRECT_ISO_REQUEST (MAX_PAGES_FOR_INDIRECT_REQUEST - 1)

#define D_VUSB1 (1 << 0)
#define D_VUSB2 (1 << 1)
#define D_URB1  (1 << 2)
#define D_URB2  (1 << 3)
#define D_STATE (1 << 4)
#define D_PORT1 (1 << 5)
#define D_PORT2 (1 << 6)
#define D_CTRL  (1 << 8)
#define D_MISC  (1 << 9)
#define D_PM    (1 << 10)
#define D_RING1 (1 << 11)
#define D_RING2 (1 << 12)

#define DEBUGMASK (D_STATE | D_PORT1 | D_URB1 | D_PM)

/* #define VUSB_DEBUG */

#ifdef VUSB_DEBUG
#  define dprintk(mask, args...)					\
	do {								\
		if (DEBUGMASK & mask)					\
			printk(KERN_DEBUG "vusb: "args);		\
	} while (0)

#  define dprint_hex_dump(mask, args...)				\
	do {								\
		if (DEBUGMASK & mask)					\
			print_hex_dump(KERN_DEBUG, "vusb: "args);	\
	} while (0)
#else
#  define dprintk(args...) do {} while (0)
#  define dprint_hex_dump(args...) do {} while (0)
#endif

#define eprintk(args...) printk(KERN_ERR "vusb: "args)
#define wprintk(args...) printk(KERN_WARNING "vusb: "args)
#define iprintk(args...) printk(KERN_INFO "vusb: "args)

/* How many ports on the root hub */
#define VUSB_PORTS	USB_MAXCHILDREN

/* Port are numbered from 1 in linux */
#define vusb_vdev_by_port(v, port) (&((v)->vrh_ports[(port) - 1].vdev))
#define vusb_vhcd_by_vdev(d) ((container_of(d, struct vusb_rh_port, vdev))->vhcd)
#define vusb_vport_by_vdev(d) (container_of(d, struct vusb_rh_port, vdev))
#define vusb_vport_by_port(v, port) (&(v)->vrh_ports[(port) - 1])
#define vusb_check_port(index) \
	(((index) < 1 || (index) > VUSB_PORTS) ? false : true)
#define vusb_dir_to_string(d) (d ? "IN" : "OUT")
#define vusb_start_processing(v) vusb_start_processing_caller(v, (__FUNCTION__))

#define BYTE_OFFSET(a) ((u32)((unsigned long)a & (PAGE_SIZE - 1)))
#define SPAN_PAGES(a, s) ((u32)((s >> PAGE_SHIFT) + ((BYTE_OFFSET(a) + BYTE_OFFSET(s) + PAGE_SIZE - 1) >> PAGE_SHIFT)))

/* Possible state of an urbp */
enum vusb_urbp_state {
	VUSB_URBP_NEW,
	VUSB_URBP_SENT,
	VUSB_URBP_DONE,
	VUSB_URBP_DROP, /* when an error occurs and unsent */
	VUSB_URBP_CANCEL
};

/* URB tracking structure */
struct vusb_urbp {
	struct urb		*urb;
	u64			id;
	enum vusb_urbp_state	state;
	struct list_head	urbp_list;
	int			port;
	usbif_response_t	rsp;
	usbif_iso_packet_info_t	*iso_packet_info;
};

/* Virtual USB device on of the RH ports */
struct vusb_device {
	spinlock_t			lock;
	u16				address;
	enum usb_device_speed		speed;
	bool				is_ss;
	bool				rflush;
	bool				resuming;

	/* This VUSB device's lists of pending URB work */
	struct list_head		pending_list;
	struct list_head		release_list;
	struct list_head		finish_list;

	struct work_struct		work;
	wait_queue_head_t		wait_queue;
};

/* Virtual USB HCD/RH pieces */
enum vusb_rh_state {
	VUSB_RH_SUSPENDED,
	VUSB_RH_RUNNING
};

enum vusb_hcd_state {
	VUSB_HCD_INACTIVE,
	VUSB_HCD_RUNNING
};

struct vusb_rh_port {
	u32				port;
	u32				port_status;

	/* Pointer back to the virtual HCD core device */
	struct vusb_vhcd		*vhcd;

	u16				device_id;
	struct vusb_device		vdev;

	/* State of device attached to this vRH port */
	unsigned			connecting:1;
	unsigned			present:1;
	unsigned			closing:1;

	/* Current counter for jobs processing for device */
	u32				processing;

	/* Reset gate for port/device resets */
	atomic_t			reset_pending;
	bool				reset_done;

	struct work_struct		work;
	wait_queue_head_t		wait_queue;
};

struct vusb_vhcd {
	spinlock_t			lock;

	enum vusb_hcd_state		hcd_state;
	enum vusb_rh_state		rh_state;

	struct vusb_rh_port		vrh_ports[VUSB_PORTS];
};

static struct platform_device *vusb_platform_device = NULL;

static bool
vusb_start_processing_caller(struct vusb_rh_port *vport,
		const char *caller);
static void
vusb_stop_processing(struct vusb_rh_port *vport);
static void
vusb_process(struct vusb_device *vdev, struct vusb_urbp *urbp, bool more_work);
static void
vusb_port_work_handler(struct work_struct *work);
static void
vusb_urbp_queue_release(struct vusb_device *vdev, struct vusb_urbp *urbp,
		bool more_work);

/****************************************************************************/
/* Miscellaneous Routines                                                   */

static inline struct vusb_vhcd*
hcd_to_vhcd(struct usb_hcd *hcd)
{
	return (struct vusb_vhcd *)(hcd->hcd_priv);
}

static inline struct usb_hcd*
vhcd_to_hcd(struct vusb_vhcd *vhcd)
{
	return container_of((void *)vhcd, struct usb_hcd, hcd_priv);
}

static inline struct device*
vusb_dev(struct vusb_vhcd *vhcd)
{
	return vhcd_to_hcd(vhcd)->self.controller;
}

#ifdef VUSB_DEBUG

/* Convert urb pipe type to string */
static const char *
vusb_pipe_to_string(struct urb *urb)
{
	switch (usb_pipetype(urb->pipe)) {
	case PIPE_ISOCHRONOUS:
		return "ISOCHRONOUS";
	case PIPE_CONTROL:
		return "CONTROL";
	case PIPE_INTERRUPT:
		return "INTERRUPT";
	case PIPE_BULK:
		return "BULK";
	default:
		return "Unknown";
	}
}

/* Convert urbp state to string */
static const char *
vusb_state_to_string(const struct vusb_urbp *urbp)
{
	switch (urbp->state) {
	case VUSB_URBP_NEW:
		return "NEW";
	case VUSB_URBP_SENT:
		return "SENT";
	case VUSB_URBP_DONE:
		return "DONE";
	case VUSB_URBP_DROP:
		return "DROP";
	case VUSB_URBP_CANCEL:
		return "CANCEL";
	default:
		return "unknown";
	}
}

#endif /* VUSB_DEBUG */

/****************************************************************************/
/* VUSB HCD & RH                                                            */

static inline u16
vusb_speed_to_port_stat(enum usb_device_speed speed)
{
	switch (speed) {
	case USB_SPEED_HIGH:
		return USB_PORT_STAT_HIGH_SPEED;
	case USB_SPEED_LOW:
		return USB_PORT_STAT_LOW_SPEED;
	case USB_SPEED_FULL:
	default:
		return 0;
	}
}

static inline u16
vusb_pipe_type_to_optype(u16 type)
{
	switch (type) {
	case PIPE_ISOCHRONOUS:
		return USBIF_T_ISOC;
	case PIPE_INTERRUPT:
		return USBIF_T_INT;
	case PIPE_CONTROL:
		return USBIF_T_CNTRL;
	case PIPE_BULK:
		return USBIF_T_BULK;
	default:
		return 0xffff;
	}
}

static void
vusb_set_link_state(struct vusb_rh_port *vport)
{
	u32 newstatus, diff;

	newstatus = vport->port_status;
	dprintk(D_STATE, "SLS: Port index %u status 0x%08x\n",
			vport->port, newstatus);

	if (vport->present && !vport->closing) {
		newstatus |= (USB_PORT_STAT_CONNECTION) |
					vusb_speed_to_port_stat(vport->vdev.speed);
	}
	else {
		newstatus &= ~(USB_PORT_STAT_CONNECTION |
					USB_PORT_STAT_LOW_SPEED |
					USB_PORT_STAT_HIGH_SPEED |
					USB_PORT_STAT_ENABLE |
					USB_PORT_STAT_SUSPEND);
	}
	if ((newstatus & USB_PORT_STAT_POWER) == 0) {
		newstatus &= ~(USB_PORT_STAT_CONNECTION |
					USB_PORT_STAT_LOW_SPEED |
					USB_PORT_STAT_HIGH_SPEED |
					USB_PORT_STAT_SUSPEND);
	}
	diff = vport->port_status ^ newstatus;

	if ((newstatus & USB_PORT_STAT_POWER) &&
		(diff & USB_PORT_STAT_CONNECTION)) {
		newstatus |= (USB_PORT_STAT_C_CONNECTION << 16);
		dprintk(D_STATE, "Port %u connection state changed: %08x\n",
				vport->port, newstatus);
	}

	vport->port_status = newstatus;
}

/* SetFeaturePort(PORT_RESET) */
static void
vusb_port_reset(struct vusb_vhcd *vhcd, struct vusb_rh_port *vport)
{
	printk(KERN_DEBUG "vusb: port reset %u 0x%08x",
		   vport->port, vport->port_status);

	vport->port_status |= USB_PORT_STAT_ENABLE | USB_PORT_STAT_POWER;

	/* Test reset gate, only want one reset in flight at a time per
	 * port. If the gate is set, it will return the "unless" value. */
	if (__atomic_add_unless(&vport->reset_pending, 1, 1) == 1)
		return;

	/* Schedule it for the device, can't do it here in the vHCD lock */
	schedule_work(&vport->work);
}

static void
vusb_set_port_feature(struct vusb_vhcd *vhcd, struct vusb_rh_port *vport, u16 val)
{
	switch (val) {
	case USB_PORT_FEAT_INDICATOR:
	case USB_PORT_FEAT_SUSPEND:
		/* Ignored now */
		break;

	case USB_PORT_FEAT_POWER:
		vport->port_status |= USB_PORT_STAT_POWER;
		break;
	case USB_PORT_FEAT_RESET:
		vusb_port_reset(vhcd, vport);
		break;
	case USB_PORT_FEAT_C_CONNECTION:
	case USB_PORT_FEAT_C_RESET:
	case USB_PORT_FEAT_C_ENABLE:
	case USB_PORT_FEAT_C_SUSPEND:
	case USB_PORT_FEAT_C_OVER_CURRENT:
		vport->port_status &= ~(1 << val);
		break;
	default:
		/* No change needed */
		return;
	}
	vusb_set_link_state(vport);
}

static void
vusb_clear_port_feature(struct vusb_rh_port *vport, u16 val)
{
	switch (val) {
	case USB_PORT_FEAT_INDICATOR:
	case USB_PORT_FEAT_SUSPEND:
		/* Ignored now */
		break;
	case USB_PORT_FEAT_ENABLE:
		vport->port_status &= ~USB_PORT_STAT_ENABLE;
		vusb_set_link_state(vport);
		break;
	case USB_PORT_FEAT_POWER:
		vport->port_status &= ~(USB_PORT_STAT_POWER | USB_PORT_STAT_ENABLE);
		vusb_set_link_state(vport);
		break;
	case USB_PORT_FEAT_C_CONNECTION:
	case USB_PORT_FEAT_C_RESET:
	case USB_PORT_FEAT_C_ENABLE:
	case USB_PORT_FEAT_C_SUSPEND:
	case USB_PORT_FEAT_C_OVER_CURRENT:
		dprintk(D_PORT1, "Clear bit %d, old 0x%08x mask 0x%08x new 0x%08x\n",
				val, vport->port_status, ~(1 << val),
				vport->port_status & ~(1 << val));
		vport->port_status &= ~(1 << val);
		break;
	default:
		/* No change needed */
		return;
	}
}

/* Hub descriptor */
static void
vusb_hub_descriptor(struct usb_hub_descriptor *desc)
{
	u16 temp;

	desc->bDescriptorType = 0x29;
	desc->bPwrOn2PwrGood = 10; /* echi 1.0, 2.3.9 says 20ms max */
	desc->bHubContrCurrent = 0;
	desc->bNbrPorts = VUSB_PORTS;

	/* size of DeviceRemovable and PortPwrCtrlMask fields */
	temp = 1 + (VUSB_PORTS / 8);
	desc->bDescLength = 7 + 2 * temp;

	/* bitmaps for DeviceRemovable and PortPwrCtrlMask */

	/* The union was introduced to support USB 3.0 */
	memset(&desc->u.hs.DeviceRemovable[0], 0, temp);
	memset(&desc->u.hs.DeviceRemovable[temp], 0xff, temp);

	/* per-port over current reporting and no power switching */
	temp = 0x00a;
	desc->wHubCharacteristics = cpu_to_le16(temp);
}

static int
vusb_hcd_start(struct usb_hcd *hcd)
{
	struct vusb_vhcd *vhcd = hcd_to_vhcd(hcd);
	int i;

	iprintk("XEN HCD start\n");

	dprintk(D_MISC, ">vusb_start\n");

	/* Initialize root hub ports */
	for (i = 0; i < VUSB_PORTS; i++) {
		memset(&vhcd->vrh_ports[i], 0, sizeof(struct vusb_rh_port));
		vhcd->vrh_ports[i].port = i + 1;
		vhcd->vrh_ports[i].vhcd = vhcd;
		INIT_WORK(&vhcd->vrh_ports[i].work, vusb_port_work_handler);
		init_waitqueue_head(&vhcd->vrh_ports[i].wait_queue);
	}

	/* Enable HCD/RH */
	vhcd->rh_state = VUSB_RH_RUNNING;
	vhcd->hcd_state = VUSB_HCD_RUNNING;

	hcd->power_budget = VUSB_POWER_BUDGET;
	hcd->state = HC_STATE_RUNNING;
	hcd->uses_new_polling = 1;

	dprintk(D_MISC, "<vusb_start 0\n");

	return 0;
}

static void
vusb_hcd_stop(struct usb_hcd *hcd)
{
	struct vusb_vhcd *vhcd;

	iprintk("XEN HCD stop\n");

	dprintk(D_MISC, ">vusb_stop\n");

	vhcd = hcd_to_vhcd(hcd);

	hcd->state = HC_STATE_HALT;
	/* TODO: remove all URBs */
	/* TODO: "cleanly make HCD stop writing memory and doing I/O" */

	dev_info(vusb_dev(vhcd), "stopped\n");
	dprintk(D_MISC, "<vusb_stop\n");
}

static int
vusb_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct vusb_vhcd *vhcd;
	unsigned long flags;
	struct vusb_urbp *urbp;
	struct vusb_rh_port *vport;
	struct vusb_device *vdev;
	int ret = -ENOMEM;

	dprintk(D_MISC, ">vusb_urb_enqueue\n");

	vhcd = hcd_to_vhcd(hcd);

	if (!urb->transfer_buffer && urb->transfer_buffer_length)
		return -EINVAL;

	if (!vusb_check_port(urb->dev->portnum))
		return -EPIPE;

	urbp = kzalloc(sizeof(*urbp), mem_flags);
	if (!urbp)
		return -ENOMEM;

	urbp->state = VUSB_URBP_NEW;
	/* Port numbered from 1 */
	urbp->port = urb->dev->portnum;
	urbp->urb = urb;
	/* No req ID until shadow is allocated */
	urbp->id = VUSB_INVALID_REQ_ID;

	spin_lock_irqsave(&vhcd->lock, flags);

	vport = vusb_vport_by_port(vhcd, urbp->port);
	if (vhcd->hcd_state == VUSB_HCD_INACTIVE || !vport->present) {
		kfree(urbp);
		spin_unlock_irqrestore(&vhcd->lock, flags);
		eprintk("Enqueue processing called with device/port invalid states\n");
		return -ENXIO;
	}

	if (vport->closing) {
		kfree(urbp);
		spin_unlock_irqrestore(&vhcd->lock, flags);
		return -ESHUTDOWN;
	}

	ret = usb_hcd_link_urb_to_ep(hcd, urb);
	if (ret) {
		kfree(urbp);
		spin_unlock_irqrestore(&vhcd->lock, flags);
		return ret;
	}

	/* Bump the processing counter so it is not nuked out from under us */
	vport->processing++;
	vdev = vusb_vdev_by_port(vhcd, urbp->port);
	spin_unlock_irqrestore(&vhcd->lock, flags);

	vusb_process(vdev, urbp, true);

	/* Finished processing */
	vusb_stop_processing(vport);

	return 0;
}

static int
vusb_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct vusb_vhcd *vhcd;
	unsigned long flags;
	int ret;
	bool found = false, skip = false;
	struct vusb_rh_port *vport;
	struct vusb_device *vdev;
	struct vusb_urbp *urbp;

	dprintk(D_MISC, "*vusb_urb_dequeue\n");

	if (!vusb_check_port(urb->dev->portnum))
		return -EPIPE;

	vhcd = hcd_to_vhcd(hcd);

	spin_lock_irqsave(&vhcd->lock, flags);

	/* Supposed to hold HCD lock when calling this */
	ret = usb_hcd_check_unlink_urb(hcd, urb, status);
	if (ret) {
		spin_unlock_irqrestore(&vhcd->lock, flags);
		return ret;
	}

	urb->status = status;

	/* If it can't be processed, the urbp and urb will be released
	 * in the device teardown code which is where this device is going
	 * (or gone). */
	vport = vusb_vport_by_port(vhcd, urb->dev->portnum);
	if (vhcd->hcd_state == VUSB_HCD_INACTIVE || !vport->present) {
		spin_unlock_irqrestore(&vhcd->lock, flags);
		eprintk("Dequeue processing called with device/port invalid states\n");
		return -ENXIO;
	}

	if (vport->closing) {
		spin_unlock_irqrestore(&vhcd->lock, flags);
		return -ESHUTDOWN;
	}

	/* Bump the processing counter so it is not nuked out from under us */
	vport->processing++;
	vdev = vusb_vdev_by_port(vhcd, urb->dev->portnum);
	spin_unlock_irqrestore(&vhcd->lock, flags);

	spin_lock_irqsave(&vdev->lock, flags);

	/* Need to find the urbp. Note the urbp can be in 4 states:
	 * 1. In the pending queue not sent. In this case we just grab it and
	 *    release it.
	 * 2. In the pending queue sent. In this case we need to flag it as
	 *    cancelled, snipe it with the internal cancel command and clean it
	 *    up in response finish processing.
	 * 3. In the finish queue. Not much can be done but to let it get
	 *    finished and released.
	 * 4. In the release queue. Again just let it get released.
	 * In both 3 and 4, we can just drive response processing to drive the
	 * urbp through to completion. Note there is a window in enqueue where
	 * the new urbp is not yet on the pending list outside the vdev lock.
	 * It seems this would be OK - it seems it is unlikely the core would
	 * call dequeue on the same URB it was currently calling enqueue for. */
	list_for_each_entry(urbp, &vdev->pending_list, urbp_list) {
		if (urbp->urb == urb) {
			found = true;
			break;
		}
	}

	while (found) {
		/* Found it in the pending list, see if it is in state 1 and
		 * and get rid of it right here and can skip processing. */
		if (urbp->state != VUSB_URBP_SENT) {
			vusb_urbp_queue_release(vdev, urbp, true);
			skip = true;
			break;
		}

		/* State 2, this is the hardest one. The urbp cannot be simply
		 * discarded because it has shadow associated with it. It will
		 * have to be flagged as canceled and left for response
		 * processing to handle later. It also has to be shot down in
		 * the backend processing. */
		urbp->state = VUSB_URBP_CANCEL;
		break;
	}

	/* For urbp's in states 3 and 4, they will be fishished and released
	 * and their status is what it is at this point. */

	spin_unlock_irqrestore(&vdev->lock, flags);

	/* Drive processing requests and responses if needed */
	if (!skip)
		vusb_process(vdev, NULL, true);

	vusb_stop_processing(vport);

	return 0;
}

static int
vusb_hcd_get_frame(struct usb_hcd *hcd)
{
	struct timeval	tv;

	dprintk(D_MISC, "*vusb_get_frame\n");
	/* TODO can we use the internal cmd to do this? */
	do_gettimeofday(&tv);

	return tv.tv_usec / 1000;
}

#define PORT_C_MASK \
	((USB_PORT_STAT_C_CONNECTION \
	| USB_PORT_STAT_C_ENABLE \
	| USB_PORT_STAT_C_SUSPEND \
	| USB_PORT_STAT_C_OVERCURRENT \
	| USB_PORT_STAT_C_RESET) << 16)

static int
vusb_hcd_hub_status(struct usb_hcd *hcd, char *buf)
{
	struct vusb_vhcd *vhcd = hcd_to_vhcd(hcd);
	unsigned long flags;
	int resume = 0;
	int changed = 0;
	u16 length = 0;
	int ret = 0;
	u16 i;

	dprintk(D_MISC, ">vusb_hub_status\n");

	/* TODO FIXME: Not sure it's good */
	if (!HCD_HW_ACCESSIBLE(hcd)) {
		wprintk("Hub is not running %u\n", hcd->state);
		dprintk(D_MISC, ">vusb_hub_status 0\n");
		return 0;
	}

	/* Initialize the status to no-change */
	length = 1 + (VUSB_PORTS / 8);
	for (i = 0; i < length; i++)
		buf[i] = 0;

	spin_lock_irqsave(&vhcd->lock, flags);

	for (i = 0; i < VUSB_PORTS; i++) {
		struct vusb_rh_port *vport = &vhcd->vrh_ports[i];

		/* Check status for each port */
		dprintk(D_PORT2, "check port %u (%08x)\n", vport->port,
				vport->port_status);
		if ((vport->port_status & PORT_C_MASK) != 0) {
			if (i < 7)
				buf[0] |= 1 << (i + 1);
			else if (i < 15)
				buf[1] |= 1 << (i - 7);
			else if (i < 23)
				buf[2] |= 1 << (i - 15);
			else
				buf[3] |= 1 << (i - 23);
			dprintk(D_PORT2, "port %u status 0x%08x has changed\n",
					vport->port, vport->port_status);
			changed = 1;
		}

		if (vport->port_status & USB_PORT_STAT_CONNECTION)
			resume = 1;
	}

	if (resume && vhcd->rh_state == VUSB_RH_SUSPENDED)
		usb_hcd_resume_root_hub(hcd);

	ret = (changed) ? length : 0;

	spin_unlock_irqrestore(&vhcd->lock, flags);
	dprintk(D_MISC, "<vusb_hub_status %d\n", ret);

	return ret;
}

static int
vusb_hcd_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
		u16 wIndex, char *buf, u16 wLength)
{
	struct vusb_vhcd *vhcd;
	int retval = 0;
	unsigned long flags;
	u32 status;

	/* TODO fix param names */
	dprintk(D_CTRL, ">vusb_hub_control %04x %04x %04x\n",
			typeReq, wIndex, wValue);

	if (!HCD_HW_ACCESSIBLE(hcd)) {
		dprintk(D_CTRL, "<vusb_hub_control %d\n", ETIMEDOUT);
		return -ETIMEDOUT;
	}

	vhcd = hcd_to_vhcd(hcd);
	spin_lock_irqsave(&vhcd->lock, flags);

	switch (typeReq) {
	case ClearHubFeature:
		break;
	case ClearPortFeature:
		dprintk(D_CTRL, "ClearPortFeature port %d val: 0x%04x\n",
				wIndex, wValue);
		if (!vusb_check_port(wIndex)) {
			wprintk("ClearPortFeature invalid port %u", wIndex);
        	        retval = -EPIPE;
	                break;
		}
		vusb_clear_port_feature(vusb_vport_by_port(vhcd, wIndex), wValue);
		break;
	case GetHubDescriptor:
		vusb_hub_descriptor((struct usb_hub_descriptor *)buf);
		break;
	case GetHubStatus:
		/* Always local power supply good and no over-current exists. */
		*(__le32 *)buf = cpu_to_le32(0);
		break;
	case GetPortStatus:
		if (!vusb_check_port(wIndex)) {
			wprintk("GetPortStatus invalid port %u", wIndex);
        	        retval = -EPIPE;
	                break;
		}
		status = vusb_vport_by_port(vhcd, wIndex)->port_status;
		dprintk(D_CTRL, "GetPortStatus port %d = 0x%08x\n", wIndex, status);
		((__le16 *) buf)[0] = cpu_to_le16(status);
		((__le16 *) buf)[1] = cpu_to_le16(status >> 16);
		break;
	case SetHubFeature:
		retval = -EPIPE;
		break;
	case SetPortFeature:
		if (!vusb_check_port(wIndex)) {
			wprintk("SetPortFeature invalid port %u", wIndex);
        	        retval = -EPIPE;
	                break;
		}
		dprintk(D_CTRL, "SetPortFeature port %d val: 0x%04x\n", wIndex, wValue);
		vusb_set_port_feature(vhcd, vusb_vport_by_port(vhcd, wIndex), wValue);
		break;

	default:
		dev_dbg(vusb_dev(vhcd),
			"hub control req%04x v%04x i%04x l%d\n",
			typeReq, wValue, wIndex, wLength);

		/* "protocol stall" on error */
		retval = -EPIPE;
	}
	spin_unlock_irqrestore(&vhcd->lock, flags);

	if (wIndex >= 1 && wIndex <= VUSB_PORTS) {
		if ((vusb_vport_by_port(vhcd, wIndex)->port_status & PORT_C_MASK) != 0)
			 usb_hcd_poll_rh_status(hcd);
	}

	dprintk(D_MISC, "<vusb_hub_control %d\n", retval);
	return retval;
}

#ifdef CONFIG_PM
static int
vusb_hcd_bus_suspend(struct usb_hcd *hcd)
{
	struct vusb_vhcd *vhcd = hcd_to_vhcd(hcd);
	unsigned long flags;

	dprintk(D_PM, "Bus suspend\n");

	spin_lock_irqsave(&vhcd->lock, flags);
	vhcd->rh_state = VUSB_RH_SUSPENDED;
	spin_unlock_irqrestore(&vhcd->lock, flags);

	return 0;
}

static int
vusb_hcd_bus_resume(struct usb_hcd *hcd)
{
	struct vusb_vhcd *vhcd = hcd_to_vhcd(hcd);
	int ret = 0;

	dprintk(D_PM, "Bus resume\n");

	spin_lock_irq(&vhcd->lock);
	if (!HCD_HW_ACCESSIBLE(hcd)) {
		ret = -ESHUTDOWN;
	} else {
		vhcd->rh_state = VUSB_RH_RUNNING;
		vhcd->hcd_state = VUSB_HCD_RUNNING;
		hcd->state = HC_STATE_RUNNING;
	}
	spin_unlock_irq(&vhcd->lock);

	return ret;
}
#endif /* CONFIG_PM */

static const struct hc_driver vusb_hcd_driver = {
	.description = VUSB_HCD_DRIVER_NAME,
	.product_desc =	VUSB_DRIVER_DESC,
	.hcd_priv_size = sizeof(struct vusb_vhcd),

	.flags = HCD_USB2,

	/* .reset not used since our HCD is so simple, everything is done in start */
	.start = vusb_hcd_start,
	.stop =	vusb_hcd_stop,

	.urb_enqueue = vusb_hcd_urb_enqueue,
	.urb_dequeue = vusb_hcd_urb_dequeue,

	.get_frame_number = vusb_hcd_get_frame,

	.hub_status_data = vusb_hcd_hub_status,
	.hub_control = vusb_hcd_hub_control,
#ifdef CONFIG_PM
	.bus_suspend = vusb_hcd_bus_suspend,
	.bus_resume = vusb_hcd_bus_resume,
#endif /* CONFIG_PM */
};

static int
vusb_put_urb(struct vusb_device *vdev, struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	u32 nr_mfns = 0, nr_ind_pages;
	int ret = 0;

	BUG_ON(!urb);

	/* Is there any data to transfer, e.g. a control transaction may
	 * just be the setup packet. */
	if (urb->transfer_buffer_length > 0)
		nr_mfns = SPAN_PAGES(urb->transfer_buffer,
				urb->transfer_buffer_length);

	if (nr_mfns > USBIF_MAX_SEGMENTS_PER_REQUEST) {
		/* Need indirect support here, only used with bulk transfers */
		if (!usb_pipebulk(urb->pipe)) {
			eprintk("%p too many pages for non-bulk transfer: %d\n",
				vdev, nr_mfns);
			ret = -E2BIG;
			goto err;
		}

		if (nr_mfns > MAX_PAGES_FOR_INDIRECT_REQUEST) {
			eprintk("%p too many pages for any transfer: %d\n",
				vdev, nr_mfns);
			ret = -E2BIG;
			goto err;
		}

		nr_ind_pages = INDIRECT_PAGES_REQUIRED(nr_mfns);
	}

	return 0;
err:
	return ret;
}

static int
vusb_put_isochronous_urb(struct vusb_device *vdev, struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	usbif_iso_packet_info_t *iso_packets;
	u32 nr_mfns = 0, nr_ind_pages;
	u16 seg_length;
	int ret = 0, i;

	BUG_ON(!urb);

	iso_packets = (usbif_iso_packet_info_t*)kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (!iso_packets) {
		ret = -ENOMEM;
		goto err;
	}

	seg_length = (u16)urb->transfer_buffer_length/urb->number_of_packets;
	for (i = 0; i < urb->number_of_packets; i++) {
		iso_packets[i].offset = urb->iso_frame_desc[i].offset;
		iso_packets[i].length = seg_length;
	}

	nr_mfns = SPAN_PAGES(urb->transfer_buffer, urb->transfer_buffer_length);
	if (nr_mfns == 0) {
		eprintk("ISO URB urbp: %p with no data buffers\n", urbp);
		ret = -EINVAL;
		goto err;
	}

	if (nr_mfns > USBIF_MAX_ISO_SEGMENTS) {
		if (nr_mfns > MAX_PAGES_FOR_INDIRECT_ISO_REQUEST) {
			eprintk("%p too many pages for ISO transfer: %d\n",
				vdev, nr_mfns);
			ret = -E2BIG;
			goto err;
		}

		/* +1 for the ISO packet page */
		nr_ind_pages = INDIRECT_PAGES_REQUIRED(nr_mfns + 1);
	}

	return 0;
err:
	return ret;
}

/****************************************************************************/
/* URB Processing                                                           */

#ifdef VUSB_DEBUG
/* Dump URBp */
static inline void
vusb_urbp_dump(struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	unsigned int type;

	type = usb_pipetype(urb->pipe);

	iprintk("URB urbp: %p state: %s status: %d pipe: %s(%u)\n",
		urbp, vusb_state_to_string(urbp),
		urb->status, vusb_pipe_to_string(urb), type);
	iprintk("device: %u endpoint: %u in: %u\n",
		usb_pipedevice(urb->pipe), usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));
}
#endif /* VUSB_DEBUG */

static void
vusb_urbp_release(struct vusb_vhcd *vhcd, struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	unsigned long flags;

#ifdef VUSB_DEBUG
	if (urb->status)
		vusb_urbp_dump(urbp);
#endif

	dprintk(D_URB2, "Giveback URB urpb: %p status %d length %u\n",
		urbp, urb->status, urb->actual_length);
	if (urbp->iso_packet_info)
		kfree(urbp->iso_packet_info);
	kfree(urbp);

	/* Now to be more specific, the first function must be called holding
	 * the HCDs private lock, the second must not because it calls the
	 * completion routine of the driver that owns the URB. */
	spin_lock_irqsave(&vhcd->lock, flags);
	usb_hcd_unlink_urb_from_ep(vhcd_to_hcd(vhcd), urb);
	spin_unlock_irqrestore(&vhcd->lock, flags);
	usb_hcd_giveback_urb(vhcd_to_hcd(vhcd), urb, urb->status);
}

static void
vusb_urbp_queue_release(struct vusb_device *vdev, struct vusb_urbp *urbp,
		bool more_work)
{
	/* Remove from the active urbp list and place it on the release list.
	 * Called from the urb processing routines holding the vdev lock. */
	list_del(&urbp->urbp_list);

	list_add_tail(&urbp->urbp_list, &vdev->release_list);

	/* If this is being called from work item processing, there is no
	 * need to schedule more work since the work item processing will
	 * also process the release_list as a last step. */
	if (more_work)
		schedule_work(&vdev->work);
}

/* Convert status to errno */
static int
vusb_status_to_errno(u32 status)
{
	switch (status) {
	case USBIF_RSP_OKAY:
		return 0;
	case USBIF_RSP_EOPNOTSUPP:
		return -ENOENT;
	case USBIF_RSP_USB_CANCELED:
		return -ECANCELED;
	case USBIF_RSP_USB_PENDING:
		return -EINPROGRESS;
	case USBIF_RSP_USB_PROTO:
		return -EPROTO;
	case USBIF_RSP_USB_CRC:
		return -EILSEQ;
	case USBIF_RSP_USB_TIMEOUT:
		return -ETIME;
	case USBIF_RSP_USB_STALLED:
		return -EPIPE;
	case USBIF_RSP_USB_INBUFF:
		return -ECOMM;
	case USBIF_RSP_USB_OUTBUFF:
		return -ENOSR;
	case USBIF_RSP_USB_OVERFLOW:
		return -EOVERFLOW;
	case USBIF_RSP_USB_SHORTPKT:
		return -EREMOTEIO;
	case USBIF_RSP_USB_DEVRMVD:
		return -ENODEV;
	case USBIF_RSP_USB_PARTIAL:
		return -EXDEV;
	case USBIF_RSP_USB_INVALID:
		return -EINVAL;
	case USBIF_RSP_USB_RESET:
		return -ECONNRESET;
	case USBIF_RSP_USB_SHUTDOWN:
		return -ESHUTDOWN;
	case USBIF_RSP_ERROR:
	case USBIF_RSP_USB_UNKNOWN:
	default:
		return -EIO;
	}
}

static void
vusb_urb_common_finish(struct vusb_device *vdev, struct vusb_urbp *urbp,
			bool in)
{
	struct urb *urb = urbp->urb;

	/* If the URB was canceled and shot down in the backend then
	 * just use the error code set in dequeue and don't bother
	 * setting values. */
	if (urbp->state == VUSB_URBP_CANCEL)
		return;

	urb->status = vusb_status_to_errno(urbp->rsp.status);
	if (unlikely(urb->status)) {
		wprintk("Failed %s URB urbp: %p urb: %p status: %d\n",
			vusb_dir_to_string(in), urbp, urb, urb->status);
		return;
	}

	dprintk(D_URB2, "%s URB completed status %d len %u\n",
		vusb_dir_to_string(in), urb->status, urbp->rsp.actual_length);

	/* Sanity check on len, should be less or equal to
	 * the length of the transfer buffer */
	if (unlikely(in && urbp->rsp.actual_length >
		urb->transfer_buffer_length)) {
		wprintk("IN URB too large (expect %u got %u)\n",
			urb->transfer_buffer_length,
			urbp->rsp.actual_length);
		urb->status = -EIO;
		return;
	}

	/* Set to what the backend said we sent or received */
	urb->actual_length = urbp->rsp.actual_length;
}

static void
vusb_urb_control_finish(struct vusb_device *vdev, struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct usb_ctrlrequest *ctrl
		= (struct usb_ctrlrequest *)urb->setup_packet;
	u8 *buf = (u8*)urb->transfer_buffer;
	bool in;

	/* This is fun. If a USB 3 device is in a USB 3 port, we get a USB 3
	 * device descriptor. Since we are a USB 2 HCD, things get unhappy
	 * above us. So this code will make the descriptor look more
	 * USB 2ish by fixing the bcdUSB  and bMaxPacketSize0
	 */
	if (vdev->is_ss && ctrl->bRequest == USB_REQ_GET_DESCRIPTOR &&
		(ctrl->wValue & 0xff00) == 0x0100 &&
		urbp->rsp.actual_length >= 0x12 &&
		buf[1] == 0x01 && buf[3] == 0x03) {
		iprintk("Modifying USB 3 device descriptor to be USB 2\n");
		buf[2] = 0x10;
		buf[3] = 0x02;
		buf[7] = 0x40;
	}

	/* Get direction of control request and do common finish */
	in = ((ctrl->bRequestType & USB_DIR_IN) != 0) ? true : false;
	vusb_urb_common_finish(vdev, urbp, in);
}

static void
vusb_urb_isochronous_finish(struct vusb_device *vdev, struct vusb_urbp *urbp,
				bool in)
{
	struct urb *urb = urbp->urb;
	struct usb_iso_packet_descriptor *iso_desc = &urb->iso_frame_desc[0];
	u32 total_length = 0, packet_length;
	int i;

	BUG_ON(!urbp->iso_packet_info);

	/* Same for ISO URBs, clear everything, set the status and release */
	if (urbp->state == VUSB_URBP_CANCEL) {
		urb->status = -ECANCELED;
		goto iso_err;
	}

	urb->status = vusb_status_to_errno(urbp->rsp.status);

	/* Did the entire ISO request fail? */
	if (urb->status)
		goto iso_err;

	/* Reset packet error count */
	urb->error_count = 0;

	for (i = 0; i < urb->number_of_packets; i++) {
		packet_length = urbp->iso_packet_info[i].length;

		/* Sanity check on packet length */
		if (packet_length > iso_desc[i].length) {
			wprintk("ISO packet %d too much data\n", i);
			goto iso_io;
		}

		iso_desc[i].actual_length = packet_length;
		iso_desc[i].status =
			vusb_status_to_errno(urbp->iso_packet_info[i].status);
		iso_desc[i].offset = urbp->iso_packet_info[i].offset;

		/* Do sanity check each time on effective data length */
		if ((in) && (urb->transfer_buffer_length <
				(total_length + packet_length))) {
			wprintk("ISO response %d to much data - "
				"expected %u got %u\n",
				i, total_length + packet_length,
				urb->transfer_buffer_length);
				goto iso_err;
		}

		if (!iso_desc[i].status)
			total_length += packet_length;
		else
			urb->error_count++;
	}

	/* Check for new start frame */
	if (urb->transfer_flags & URB_ISO_ASAP)
		urb->start_frame = urbp->rsp.data;

	urb->actual_length = total_length;
	dprintk(D_URB2, "ISO response urbp: %s total: %u errors: %d\n",
		urbp, total_length, urb->error_count);

	return;

iso_io:
	urb->status = -EIO;
iso_err:
	for (i = 0; i < urb->number_of_packets; i++) {
		urb->iso_frame_desc[i].actual_length = 0;
		urb->iso_frame_desc[i].status = urb->status;
	}
	urb->actual_length = 0;
}

static void
vusb_urb_finish(struct vusb_device *vdev, struct vusb_urbp *urbp, bool more_work)
{
	struct urb *urb = urbp->urb;
	int type = usb_pipetype(urb->pipe);
	bool in;

	in = usb_urb_dir_in(urbp->urb) ? true : false;

	switch (type) {
	case PIPE_CONTROL:
		vusb_urb_control_finish(vdev, urbp);
		break;
	case PIPE_ISOCHRONOUS:
		vusb_urb_isochronous_finish(vdev, urbp, in);
		break;
	case PIPE_INTERRUPT:
	case PIPE_BULK:
		vusb_urb_common_finish(vdev, urbp, in);
		break;
	default:
		eprintk("Unknown pipe type %u\n", type);
	}

	/* No matter what, move this urbp to the release list */
	urbp->state = VUSB_URBP_DONE;
	vusb_urbp_queue_release(vdev, urbp, more_work);
}

static void
vusb_send(struct vusb_device *vdev, struct vusb_urbp *urbp, int type)
{
	int ret = (type != PIPE_ISOCHRONOUS) ?
		vusb_put_urb(vdev, urbp) :
		vusb_put_isochronous_urb(vdev, urbp);
	switch (ret) {
	case 0:
		urbp->state = VUSB_URBP_SENT;
		break;
	case -EAGAIN:
		schedule_work(&vdev->work);
	case -EBUSY:
		/* grant callback restarts work */
		break;
	default:
		urbp->state = VUSB_URBP_DROP;
		urbp->urb->status = ret;
	}
}

static void
vusb_send_control_urb(struct vusb_device *vdev, struct vusb_urbp *urbp)
{
	struct urb *urb = urbp->urb;
	const struct usb_ctrlrequest *ctrl;
	u16 ctrl_tr, ctrl_value;

	/* Convenient aliases on setup packet*/
	ctrl = (struct usb_ctrlrequest *)urb->setup_packet;
	ctrl_tr = (ctrl->bRequestType << 8) | ctrl->bRequest;
	ctrl_value = le16_to_cpu(ctrl->wValue);

	dprintk(D_URB2, "Send Control URB dev: %u in: %u cmd: 0x%x 0x%02x\n",
		usb_pipedevice(urb->pipe), ((ctrl->bRequestType & USB_DIR_IN) != 0),
		ctrl->bRequest, ctrl->bRequestType);
	dprintk(D_URB2, "SETUP packet, tb_len=%d\n",
		urb->transfer_buffer_length);
	dprint_hex_dump(D_URB2, "SET: ",
		DUMP_PREFIX_OFFSET, 16, 1, ctrl, 8, true);

	/* The only special case it a set address request. We can't actually
	 * let the guest do this in the backend - it would cause mayhem */
	if (ctrl_tr == (DeviceOutRequest | USB_REQ_SET_ADDRESS)) {
		vdev->address = ctrl_value;
		dprintk(D_URB1, "SET ADDRESS %u\n", vdev->address);
		urb->status = 0;
		urbp->state = VUSB_URBP_DONE;
		return;
	}

	vusb_send(vdev, urbp, PIPE_CONTROL);
}

static void
vusb_send_urb(struct vusb_device *vdev, struct vusb_urbp *urbp, bool more_work)
{
	struct urb *urb = urbp->urb;
	unsigned int type = usb_pipetype(urb->pipe);

	dprintk(D_URB2, "Send URB urbp: %p state: %s pipe: %s(t:%u e:%u d:%u)\n",
		urbp, vusb_state_to_string(urbp),
		vusb_pipe_to_string(urb), type, usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));

	if (urbp->state == VUSB_URBP_NEW) {
		switch (type) {
		case PIPE_CONTROL:
			vusb_send_control_urb(vdev, urbp);
			break;
		case PIPE_ISOCHRONOUS:
		case PIPE_INTERRUPT:
		case PIPE_BULK:
			vusb_send(vdev, urbp, type);
			break;
		default:
			wprintk("Unknown urb type %x\n", type);
			urbp->state = VUSB_URBP_DROP;
			urb->status = -ENODEV;
		}
	}

	/* This will pick up canceled urbp's from dequeue too */
	if (urbp->state == VUSB_URBP_DONE ||
		urbp->state == VUSB_URBP_DROP) {
		/* Remove URB */
		dprintk(D_URB1, "URB immediate %s\n",
			vusb_state_to_string(urbp));
		vusb_urbp_queue_release(vdev, urbp, more_work);
	}
}

/****************************************************************************/
/* VUSB Port                                                                */

static bool
vusb_start_processing_caller(struct vusb_rh_port *vport, const char *caller)
{
	struct vusb_vhcd *vhcd = vport->vhcd;
	unsigned long flags;

	spin_lock_irqsave(&vhcd->lock, flags);

	if (vhcd->hcd_state == VUSB_HCD_INACTIVE || !vport->present) {
		spin_unlock_irqrestore(&vhcd->lock, flags);
		eprintk("%s called start processing - device %p "
			"invalid state - vhcd: %d vport: %d\n",
			caller, &vport->vdev, vhcd->hcd_state, vport->present);
		return false;
	}

	if (vport->closing) {
		/* Normal, shutdown of this device pending */
		spin_unlock_irqrestore(&vhcd->lock, flags);
		return false;
	}

	vport->processing++;
	spin_unlock_irqrestore(&vhcd->lock, flags);

	return true;
}

static void
vusb_stop_processing(struct vusb_rh_port *vport)
{
	struct vusb_vhcd *vhcd = vport->vhcd;
	unsigned long flags;

	spin_lock_irqsave(&vhcd->lock, flags);
	vport->processing--;
	spin_unlock_irqrestore(&vhcd->lock, flags);
}

static void
vusb_process_reset(struct vusb_rh_port *vport)
{
	struct vusb_vhcd *vhcd = vport->vhcd;
	unsigned long flags;

	/* Wait for the reset with no lock */
	wait_event_interruptible(vport->wait_queue, (vport->reset_done));

	iprintk("Reset complete for vdev: %p on port: %d\n",
		&vport->vdev, vport->port);

	/* Reset the reset gate */
	vport->reset_done = false;
	atomic_set(&vport->reset_pending, 0);

	spin_lock_irqsave(&vhcd->lock, flags);
	/* Signal reset completion */
	vport->port_status |= (USB_PORT_STAT_C_RESET << 16);

	vusb_set_link_state(vport);
	spin_unlock_irqrestore(&vhcd->lock, flags);

	/* Update RH outside of critical section */
	usb_hcd_poll_rh_status(vhcd_to_hcd(vhcd));
}

static void
vusb_port_work_handler(struct work_struct *work)
{
	struct vusb_rh_port *vport = container_of(work, struct vusb_rh_port, work);

	if (!vusb_start_processing(vport))
		return;

	/* Process port/device reset in port work */
	vusb_process_reset(vport);

	vusb_stop_processing(vport);
}

/****************************************************************************/
/* VUSB Devices                                                             */

static void
vusb_process(struct vusb_device *vdev, struct vusb_urbp *urbp, bool more_work)
{
	struct vusb_urbp *pos;
	struct vusb_urbp *next;
	unsigned long flags;

	spin_lock_irqsave(&vdev->lock, flags);

	/* Always drive any response processing since this could make room for
	 * requests. */
	list_for_each_entry_safe(pos, next, &vdev->finish_list, urbp_list) {
		vusb_urb_finish(vdev, pos, more_work);
	}

	/* New URB, queue it at the back */
	if (urbp)
		list_add_tail(&urbp->urbp_list, &vdev->pending_list);

	/* Drive request processing */
	list_for_each_entry_safe(pos, next, &vdev->pending_list, urbp_list) {
		/* Work scheduled if 1 or more URBs cannot be sent */
		vusb_send_urb(vdev, pos, more_work);
	}

	spin_unlock_irqrestore(&vdev->lock, flags);
}

/****************************************************************************/
/* VUSB Platform Device & Driver                                            */

static void
vusb_platform_sanity_disable(struct vusb_vhcd *vhcd)
{
	unsigned long flags;
	u16 i = 0;

	iprintk("Disable vHCD with sanity check.\n");

	spin_lock_irqsave(&vhcd->lock, flags);

	/* Check for any vUSB devices - lotsa trouble if there are any */
	for (i = 0; i < VUSB_PORTS; i++) {
		if (!vhcd->vrh_ports[i].present)
			continue;

		/* Active vUSB device, now in a world of pain */
		eprintk("Danger! Shutting down while"
			" xenbus device at %d is present!!\n", i);
	}

	/* Shut down the vHCD */
	vhcd->hcd_state = VUSB_HCD_INACTIVE;

	spin_unlock_irqrestore(&vhcd->lock, flags);
}

/* Platform probe */
static int
vusb_platform_probe(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	int ret;
	struct vusb_vhcd *vhcd;

	if (usb_disabled())
		return -ENODEV;

	dprintk(D_MISC, ">vusb_hcd_probe\n");
	dev_info(&pdev->dev, "%s, driver " VUSB_DRIVER_VERSION "\n", VUSB_DRIVER_DESC);

	hcd = usb_create_hcd(&vusb_hcd_driver, &pdev->dev, dev_name(&pdev->dev));
	if (!hcd)
		return -ENOMEM;

	/* Indicate the USB stack that both High and Full speed are supported */
	hcd->has_tt = 1;

	vhcd = hcd_to_vhcd(hcd);

	spin_lock_init(&vhcd->lock);
	vhcd->hcd_state = VUSB_HCD_INACTIVE;

	ret = usb_add_hcd(hcd, 0, 0);
	if (ret != 0)
		goto err_add;

	iprintk("xen_usbif initialized\n");

	dprintk(D_MISC, "<vusb_hcd_probe %d\n", ret);

	return 0;

err_add:
	usb_put_hcd(hcd);

	eprintk("%s failure - ret: %d\n", __FUNCTION__, ret);

	return ret;
}

/* Platform remove */
static int
vusb_platform_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct vusb_vhcd *vhcd = hcd_to_vhcd(hcd);

	/* Sanity check the state of the platform. Unloading this module
	 * should only be done for debugging and development purposes. */
	vusb_platform_sanity_disable(vhcd);

	/* A warning will result: "IRQ 0 already free". It seems the Linux
	 * kernel doesn't set hcd->irq to -1 when IRQ is not enabled for a USB
	 * driver. So we put an hack for this before usb_remove_hcd(). */
	hcd->irq = -1;

	usb_remove_hcd(hcd);

	usb_put_hcd(hcd);

	return 0;
}

#ifdef CONFIG_PM
static int
vusb_platform_freeze(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct usb_hcd *hcd;
	struct vusb_vhcd *vhcd;
	unsigned long flags;

	iprintk("HCD freeze\n");

	hcd = platform_get_drvdata(pdev);
	vhcd = hcd_to_vhcd(hcd);
	spin_lock_irqsave(&vhcd->lock, flags);

	dprintk(D_PM, "root hub state %u\n", vhcd->rh_state);

	if (vhcd->rh_state == VUSB_RH_RUNNING) {
		wprintk("Root hub isn't suspended!\n");
		vhcd->hcd_state = VUSB_HCD_INACTIVE;
		return -EBUSY;
	}

	clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	spin_unlock_irqrestore(&vhcd->lock, flags);

	return 0;
}

static int
vusb_platform_restore(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct usb_hcd *hcd;
	unsigned long flags;
	struct vusb_vhcd *vhcd;

	iprintk("HCD restore\n");

	hcd = platform_get_drvdata(pdev);
	vhcd = hcd_to_vhcd(hcd);

	spin_lock_irqsave(&vhcd->lock, flags);
	set_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	/* TODO used to be vusb_init_hcd which was wrong - what needs to happen here */
	spin_unlock_irqrestore(&vhcd->lock, flags);

	return 0;
}
#endif /* CONFIG_PM */

#ifdef CONFIG_PM
static const struct dev_pm_ops vusb_platform_pm = {
	.freeze = vusb_platform_freeze,
	.restore = vusb_platform_restore,
	.thaw = vusb_platform_restore,
};
#endif /* CONFIG_PM */

static struct platform_driver vusb_platform_driver = {
	.probe = vusb_platform_probe,
	.remove = vusb_platform_remove,
	.driver = {
		.name = VUSB_PLATFORM_DRIVER_NAME,
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &vusb_platform_pm,
#endif /* CONFIG_PM */
	},
};

/****************************************************************************/
/* Module Init & Cleanup                                                    */

static bool module_ref_counted = false;

static ssize_t vusb_enable_unload(struct device_driver *drv, const char *buf,
				size_t count)
{
	/* In general we don't want this module to ever be unloaded since
	 * it is highly unsafe when there are active xenbus devices running
	 * in this module. This sysfs attribute allows this module to be
	 * unloaded for development and debugging work */
	if (module_ref_counted) {
		module_put(THIS_MODULE);
		module_ref_counted = false;
	} 

        return count;
}

static DRIVER_ATTR(enable_unload, S_IWUSR, NULL, vusb_enable_unload);

static void
vusb_cleanup(void)
{
	iprintk("clean up\n");
	if (vusb_platform_device) {
		driver_remove_file(&vusb_platform_driver.driver,
				&driver_attr_enable_unload);
		platform_device_unregister(vusb_platform_device);
		platform_driver_unregister(&vusb_platform_driver);
	}
}

static int __init
vusb_init(void)
{
	int ret;

	iprintk("Virtual USB controller\n");

	if (usb_disabled()) {
		wprintk("USB is disabled\n");
		return -ENODEV;
	}

	ret = platform_driver_register(&vusb_platform_driver);
	if (ret < 0) {
		eprintk("Unable to register the platform\n");
		goto fail_platform_driver;
	}

	vusb_platform_device =
		platform_device_alloc(VUSB_PLATFORM_DRIVER_NAME, -1);
	if (!vusb_platform_device) {
		eprintk("Unable to allocate platform device\n");
		ret = -ENOMEM;
		goto fail_platform_device1;
	}

	ret = platform_device_add(vusb_platform_device);
	if (ret < 0) {
		eprintk("Unable to add the platform\n");
		goto fail_platform_device2;
	}

	ret = driver_create_file(&vusb_platform_driver.driver,
				&driver_attr_enable_unload);
	if (ret < 0) {
		eprintk("Unable to add driver attr\n");
		goto fail_platform_device3;
	}

	if (!try_module_get(THIS_MODULE)) {
		eprintk("Failed to get module ref count\n");
		ret = -ENODEV;
		goto fail_driver_create_file;
	}
	module_ref_counted = true;

	return 0;

fail_driver_create_file:
	driver_remove_file(&vusb_platform_driver.driver,
			&driver_attr_enable_unload);
fail_platform_device3:
        platform_device_del(vusb_platform_device);
fail_platform_device2:
	platform_device_put(vusb_platform_device);
fail_platform_device1:
	platform_driver_unregister(&vusb_platform_driver);
fail_platform_driver:
	return ret;
}

module_init(vusb_init);
module_exit(vusb_cleanup);

MODULE_DESCRIPTION("Virtual USB controller");
MODULE_LICENSE ("GPL");
