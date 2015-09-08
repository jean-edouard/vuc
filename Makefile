#
# Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

obj-m += vuc.o
KVERSION := $(shell uname -r)

all:
	make -C /lib/modules/${KVERSION}/build M=$(PWD) modules -I$(PWD) EXTRA_CFLAGS="-g -I$(PWD)/include -I$(PWD)"

module_install:
	install -d ${DESTDIR}/lib/modules/${KVERSION}/extra
	install -m 0644 vuc.ko ${DESTDIR}/lib/modules/${KVERSION}/extra
	depmod -a

modules:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules EXTRA_CFLAGS="-DXC_KERNEL=1 -I$(PWD)/include -I$(PWD)"

modules_install:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
