/*
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
 *
 *  Solaris Porting Layer (SPL) Credential Implementation.
 */

#include <sys/timer.h>

#define	MAXCLOCK_T LONG_MAX

/*
 *  * Convert from system time units (hz) to microseconds.
 *  *
 *  * If ticks <= 0, return 0.
 *  * If converting ticks to usecs would overflow, return MAXCLOCK_T.
 *  * Otherwise, convert ticks to microseconds.
 *  */
clock_t
drv_hztousec(clock_t ticks)
{
	if (ticks <= 0)
		return (0);

	if (ticks > MAXCLOCK_T / USEC_PER_TICK)
		return (MAXCLOCK_T);

	return (TICK_TO_USEC(ticks));
}

EXPORT_SYMBOL(drv_hztousec);

/*
 *  * Convert from microseconds to system time units (hz), rounded up.
 *  *
 *  * If ticks <= 0, return 0.
 *  * Otherwise, convert microseconds to ticks, rounding up.
 *  */
clock_t
drv_usectohz(clock_t microsecs)
{
	if (microsecs <= 0)
		return (0);

	return (USEC_TO_TICK_ROUNDUP(microsecs));
}

EXPORT_SYMBOL(drv_usectohz);

time_t
ddi_get_time(void)
{
	return gethrestime_sec(); 
}

EXPORT_SYMBOL(ddi_get_time);
