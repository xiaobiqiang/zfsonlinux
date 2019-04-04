/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://zfsonlinux.org/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
\*****************************************************************************/

#ifndef _SPL_DKIO_H
#define	_SPL_DKIO_H

struct dk_callback {
	void (*dkc_callback)(void *dkc_cookie, int error);
	void *dkc_cookie;
	int dkc_flag;
};

typedef struct dkioc_free_s {
	uint32_t df_flags;
	uint32_t df_reserved;   /* For easy 64-bit alignment below... */
	diskaddr_t df_start;
	diskaddr_t df_length;
} dkioc_free_t;

#define	DF_WAIT_SYNC	0x00000001	/* Wait for full write-out of free. */

#define	DKIOC			(0x04 << 8)
#define	DKIOCFLUSHWRITECACHE	(DKIOC | 34)
#define	DKIOCTRIM		(DKIOC | 35)
#define	DKIOCGETWCE		(DKIOC | 36)	/* Get current write cache */
#define	DKIOCSETWCE		(DKIOC | 37)	/* Enable/Disable write cache */
#define	DKIOCFREE		(DKIOC | 50)	/* free space (e.g. SCSI UNMAP) off a disk */

#endif /* _SPL_DKIO_H */
