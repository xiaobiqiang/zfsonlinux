/*****************************************************************************\
 *  Copyright (c) 2008-2010 Sun Microsystems, Inc.
 *  Written by Ricardo Correia <Ricardo.M.Correia@Sun.COM>
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
 *****************************************************************************
 *  Solaris Porting Layer (SPL) XDR Implementation.
\*****************************************************************************/

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/types.h>

static bool_t
xdrmem_sizeof_control(XDR *xdrs, int req, void *info)
{
	return TRUE;
}

static bool_t
xdrmem_sizeof_uint(XDR *xdrs, unsigned *up)
{
	xdrs->x_handy += sizeof(uint32_t);
	return TRUE;
}

static bool_t
xdrmem_sizeof_char(XDR *xdrs, char *cp)
{
	return xdrmem_sizeof_uint(xdrs, (unsigned *)cp);
}

static bool_t
xdrmem_sizeof_ushort(XDR *xdrs, unsigned short *usp)
{
	return xdrmem_sizeof_uint(xdrs, (unsigned *)usp);
}

static bool_t
xdrmem_sizeof_ulonglong(XDR *xdrs, u_longlong_t *ullp)
{
	xdrs->x_handy += sizeof(uint32_t);
	xdrs->x_handy += sizeof(uint32_t);
	return TRUE;
}

static bool_t
xdrmem_sizeof_bytes(XDR *xdrs, caddr_t cp, const uint_t cnt)
{
	uint_t size = roundup(cnt, 4);

	if (size < cnt)
		return FALSE; /* Integer overflow */

	xdrs->x_handy += size;
	return TRUE;
}

static bool_t
xdr_sizeof_string(XDR *xdrs, char **sp, const uint_t maxsize)
{
	size_t slen = strlen(*sp);
	uint_t len = slen;

	if (slen > maxsize)
		return FALSE;

	if (!xdrmem_sizeof_uint(xdrs, &len))
		return FALSE;

	return xdrmem_sizeof_bytes(xdrs, *sp, len);
}

static bool_t
xdr_sizeof_array(XDR *xdrs, caddr_t *arrp, uint_t *sizep, const uint_t maxsize,
    const uint_t elsize, const xdrproc_t elproc)
{
	if (*sizep > maxsize || *sizep > UINT_MAX / elsize)
		return FALSE;

	if (!xdrmem_sizeof_uint(xdrs, sizep))
		return FALSE;

	xdrs->x_handy += (*sizep * elsize);
	return TRUE;
}

static struct xdr_ops xdrmem_sizeof_ops = {
	.xdr_control      = xdrmem_sizeof_control,
	.xdr_char         = xdrmem_sizeof_char,
	.xdr_u_short      = xdrmem_sizeof_ushort,
	.xdr_u_int        = xdrmem_sizeof_uint,
	.xdr_u_longlong_t = xdrmem_sizeof_ulonglong,
	.xdr_opaque       = xdrmem_sizeof_bytes,
	.xdr_string       = xdr_sizeof_string,
	.xdr_array        = xdr_sizeof_array
};

unsigned int
xdr_sizeof(xdrproc_t func, void *data)
{
	XDR x;
	bool_t stat;

	x.x_op = XDR_ENCODE;
	x.x_ops = &xdrmem_sizeof_ops;
	x.x_handy = 0;

	stat = func(&x, data);
	return (stat == TRUE ? (unsigned int)x.x_handy: 0);
}
EXPORT_SYMBOL(xdr_sizeof);
