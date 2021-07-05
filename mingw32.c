//
// Created by caiiiycuk on 01.07.2021.
//

#include "mingw32.h"

#ifndef HAVE_POLL

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {

	return WSAPoll(fds, nfds, timeout);

}

#endif

/***********************************************************************
 * Copyright (c) 2009, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **********************************************************************/

#ifndef HAVE_GETIFADDRS

static struct sockaddr *dupaddr(const sockaddr_gen * src)
{
	sockaddr_gen * d = malloc(sizeof(*d));

	if (d) {
		memcpy(d, src, sizeof(*d));
	}

	return (struct sockaddr *) d;
}

int getifaddrs(struct ifaddrs **ifpp)
{
	SOCKET s = INVALID_SOCKET;
	size_t il_len = 8192;
	int ret = -1;
	INTERFACE_INFO *il = NULL;

	*ifpp = NULL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET)
		return -1;

	for (;;) {
		DWORD cbret = 0;

		il = malloc(il_len);
		if (!il)
			break;

		ZeroMemory(il, il_len);

		if (WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0,
			 (LPVOID) il, (DWORD) il_len, &cbret,
			 NULL, NULL) == 0) {
			il_len = cbret;
			break;
		}

		free (il);
		il = NULL;

		if (WSAGetLastError() == WSAEFAULT && cbret > il_len) {
			il_len = cbret;
		} else {
			break;
		}
	}

	if (!il)
		goto _exit;

	/* il is an array of INTERFACE_INFO structures.  il_len has the
	   actual size of the buffer.  The number of elements is
	   il_len/sizeof(INTERFACE_INFO) */

	{
		size_t n = il_len / sizeof(INTERFACE_INFO);
		size_t i;

		for (i = 0; i < n; i++ ) {
			struct ifaddrs *ifp;

			ifp = malloc(sizeof(*ifp));
			if (ifp == NULL)
				break;

			ZeroMemory(ifp, sizeof(*ifp));

			ifp->ifa_next = NULL;
			ifp->ifa_name = NULL;
			ifp->ifa_flags = il[i].iiFlags;
			ifp->ifa_addr = dupaddr(&il[i].iiAddress);
			ifp->ifa_netmask = dupaddr(&il[i].iiNetmask);
			ifp->ifa_broadaddr = dupaddr(&il[i].iiBroadcastAddress);
			ifp->ifa_data = NULL;

			*ifpp = ifp;
			ifpp = &ifp->ifa_next;
		}

		if (i == n)
			ret = 0;
	}

_exit:

	if (s != INVALID_SOCKET)
	closesocket(s);

	if (il)
	free (il);

	return ret;
}

#endif

#ifndef HAVE_FREEIFADDRS

void freeifaddrs(struct ifaddrs *ifp) {
	struct ifaddrs *p, *q;

	for(p = ifp; p; ) {
		if (p->ifa_name)
			free(p->ifa_name);
		if(p->ifa_addr)
			free(p->ifa_addr);
		if(p->ifa_dstaddr)
			free(p->ifa_dstaddr);
		if(p->ifa_netmask)
			free(p->ifa_netmask);
		if(p->ifa_data)
			free(p->ifa_data);
		q = p;
		p = p->ifa_next;
		free(q);
	}
}

#endif

/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

 /** ASCII-case-insensitive substring search.
 *
 * Search for substring ASCII-case-insensitively.
 *
 */

#ifndef HAVE_STRCASESTR

char *strcasestr(const char *haystack, const char *needle) {
	unsigned char lcn, ucn;
	size_t i;

	if (haystack == NULL || needle == NULL)
		return NULL;

	lcn = ucn = needle[0];
	if ('A' <= lcn && lcn <= 'Z')
		lcn += 'a' - 'A';
	else if ('a' <= ucn && ucn <= 'z')
		ucn -= 'a' - 'A';

	if (lcn == 0)
		return (char *)haystack;

	while (haystack[0] != 0) {
		if (lcn == haystack[0] || ucn == haystack[0]) {
			for (i = 1; ; i++) {
				char n = needle[i], h = haystack[i];
				if (n == 0)
					return (char *)haystack;
				if (h == 0)
					return NULL;
				if (n == h)
					continue;
				if ((n ^ h) != ('A' ^ 'a'))
					break;
				if ('A' <= n && n <= 'Z')
					n += 'a' - 'A';
				else if ('A' <= h && h <= 'Z')
					h += 'a' - 'A';
				if (n != h)
					break;
			}
		}
		haystack++;
	}

	return NULL;		/* Not found */
}

#endif

/* Emulate flock on platforms that lack it, primarily Windows and MinGW.
   This is derived from sqlite3 sources.
   http://www.sqlite.org/cvstrac/rlog?f=sqlite/src/os_win.c
   http://www.sqlite.org/copyright.html
   Written by Richard W.M. Jones <rjones.at.redhat.com>
   Copyright (C) 2008-2014 Free Software Foundation, Inc.
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Determine the current size of a file.  Because the other braindead
 * APIs we'll call need lower/upper 32 bit pairs, keep the file size
 * like that too.
 */

#ifndef HAVE_FLOCK

static BOOL file_size (HANDLE h, DWORD * lower, DWORD * upper) {
	*lower = GetFileSize (h, upper);
	return 1;
}

/* LOCKFILE_FAIL_IMMEDIATELY is undefined on some Windows systems. */
# ifndef LOCKFILE_FAIL_IMMEDIATELY
#  define LOCKFILE_FAIL_IMMEDIATELY 1
# endif

/* Acquire a lock. */
static BOOL do_lock (HANDLE h, int non_blocking, int exclusive) {
	BOOL res;
	DWORD size_lower, size_upper;
	OVERLAPPED ovlp;
	int flags = 0;

	/* We're going to lock the whole file, so get the file size. */
	res = file_size (h, &size_lower, &size_upper);
	if (!res)
		return 0;

	/* Start offset is 0, and also zero the remaining members of this struct. */
	memset (&ovlp, 0, sizeof ovlp);

	if (non_blocking)
		flags |= LOCKFILE_FAIL_IMMEDIATELY;
	if (exclusive)
		flags |= LOCKFILE_EXCLUSIVE_LOCK;

	return LockFileEx (h, flags, 0, size_lower, size_upper, &ovlp);
}

/* Unlock reader or exclusive lock. */
static BOOL do_unlock (HANDLE h) {
	int res;
	DWORD size_lower, size_upper;

	res = file_size (h, &size_lower, &size_upper);
	if (!res)
		return 0;

	return UnlockFile (h, 0, 0, size_lower, size_upper);
}

/* Now our BSD-like flock operation. */
int flock (int fd, int operation) {
	HANDLE h = (HANDLE) _get_osfhandle (fd);
	DWORD res;
	int non_blocking;

	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	non_blocking = operation & LOCK_NB;
	operation &= ~LOCK_NB;

	switch (operation) {
	case LOCK_SH:
		res = do_lock (h, non_blocking, 0);
		break;
	case LOCK_EX:
		res = do_lock (h, non_blocking, 1);
		break;
	case LOCK_UN:
		res = do_unlock (h);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	/* Map Windows errors into Unix errnos.  As usual MSDN fails to
	 * document the permissible error codes.
	 */
	if (!res) {
		DWORD err = GetLastError ();
		switch (err) {
		/* This means someone else is holding a lock. */
		case ERROR_LOCK_VIOLATION:
			errno = EAGAIN;
			break;

		/* Out of memory. */
		case ERROR_NOT_ENOUGH_MEMORY:
			errno = ENOMEM;
			break;

		case ERROR_BAD_COMMAND:
			errno = EINVAL;
			break;

		/* Unlikely to be other errors, but at least don't lose the
		 * error code.
		 */
		default:
			errno = err;
		}

		return -1;
	}

	return 0;
}

#endif

#ifndef HAVE_RELPATH
char *realpath(const char *restrict path, char *restrict resolved_path) {
	return _fullpath(resolved_path, path, PATH_MAX);
}
#endif