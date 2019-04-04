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

#ifndef _SPL_TIMER_H
#define _SPL_TIMER_H

#include <linux/module.h>
#include <linux/sched.h>
#include <sys/time.h>
#include <linux/timer.h>

#define lbolt				((clock_t)jiffies)
#define lbolt64				((int64_t)get_jiffies_64())

#define ddi_get_lbolt()			((clock_t)jiffies)
#define ddi_get_lbolt64()		((int64_t)get_jiffies_64())

#define ddi_time_before(a, b)		(typecheck(clock_t, a) && \
					typecheck(clock_t, b) && \
					((a) - (b) < 0))
#define ddi_time_after(a, b)		ddi_time_before(b, a)
#define ddi_time_before_eq(a, b)	(!ddi_time_after(a, b))
#define ddi_time_after_eq(a, b)		ddi_time_before_eq(b, a)

#define ddi_time_before64(a, b)		(typecheck(int64_t, a) && \
					typecheck(int64_t, b) && \
					((a) - (b) < 0))
#define ddi_time_after64(a, b)		ddi_time_before64(b, a)
#define ddi_time_before_eq64(a, b)	(!ddi_time_after64(a, b))
#define ddi_time_after_eq64(a, b)	ddi_time_before_eq64(b, a)

#define delay(ticks)			schedule_timeout_uninterruptible(ticks)

/*
 *  * Macros to convert from common units of time (sec, msec, usec, nsec,
 *  * timeval, timestruc) to clock ticks and vice versa.
 *  */
#define	TICK_PER_MSEC			(HZ / MILLISEC)

#define	MSEC_PER_TICK			(MILLISEC / HZ)
#define	USEC_PER_TICK			(MICROSEC / HZ)
#define	NSEC_PER_TICK			(NANOSEC / HZ)

#define	TICK_TO_SEC(tick)		((tick) / HZ)
#define	SEC_TO_TICK(sec)		((sec) * HZ)

#define	TICK_TO_MSEC(tick)	\
		(MSEC_PER_TICK ? (tick) * MSEC_PER_TICK : (tick) / TICK_PER_MSEC)
#define MSEC_TO_TICK(ms)		msecs_to_jiffies(ms)
#define	MSEC_TO_TICK_ROUNDUP(msec)	\
		(MSEC_PER_TICK ? \
		((msec) == 0 ? 0 : ((msec) - 1) / MSEC_PER_TICK + 1) : \
		(msec) * TICK_PER_MSEC)

#define	TICK_TO_USEC(tick)		((tick) * USEC_PER_TICK)
#define USEC_TO_TICK(us)		usecs_to_jiffies(us)
#define	USEC_TO_TICK_ROUNDUP(usec)	\
		((usec) == 0 ? 0 : USEC_TO_TICK((usec) - 1) + 1)

#define	TICK_TO_NSEC(tick)		((hrtime_t)(tick) * NSEC_PER_TICK)
#define NSEC_TO_TICK(ns)		usecs_to_jiffies(ns / NSEC_PER_USEC)
#define	NSEC_TO_TICK_ROUNDUP(nsec)	\
		((nsec) == 0 ? 0 : NSEC_TO_TICK((nsec) - 1) + 1)

#define	TICK_TO_TIMEVAL(tick, tvp) {	\
		clock_t __tmptck = (tick);	\
		(tvp)->tv_sec = TICK_TO_SEC(__tmptck);	\
		(tvp)->tv_usec = TICK_TO_USEC(__tmptck - SEC_TO_TICK((tvp)->tv_sec)); \
}

#define	TICK_TO_TIMEVAL32(tick, tvp) {	\
		clock_t __tmptck = (tick);	\
		time_t __tmptm = TICK_TO_SEC(__tmptck);	\
		(tvp)->tv_sec = (time32_t)__tmptm;	\
		(tvp)->tv_usec = TICK_TO_USEC(__tmptck - SEC_TO_TICK(__tmptm)); \
}

#define	TICK_TO_TIMESTRUC(tick, tsp) {	\
		clock_t __tmptck = (tick);	\
		(tsp)->tv_sec = TICK_TO_SEC(__tmptck);	\
		(tsp)->tv_nsec = TICK_TO_NSEC(__tmptck - SEC_TO_TICK((tsp)->tv_sec)); \
}

#define	TICK_TO_TIMESTRUC32(tick, tsp) {	\
		clock_t __tmptck = (tick);			\
		time_t __tmptm = TICK_TO_SEC(__tmptck);		\
		(tsp)->tv_sec = (time32_t)__tmptm;		\
		(tsp)->tv_nsec = TICK_TO_NSEC(__tmptck - SEC_TO_TICK(__tmptm));	\
}

#define	TIMEVAL_TO_TICK(tvp)	\
		(SEC_TO_TICK((tvp)->tv_sec) + USEC_TO_TICK((tvp)->tv_usec))

#define	TIMESTRUC_TO_TICK(tsp)	\
		(SEC_TO_TICK((tsp)->tv_sec) + NSEC_TO_TICK((tsp)->tv_nsec))


clock_t drv_hztousec(clock_t ticks);
clock_t drv_usectohz(clock_t microsecs);
time_t ddi_get_time(void);

#endif  /* _SPL_TIMER_H */

