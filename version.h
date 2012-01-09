/*
 * Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ADSUCK_VERSION_H
#define ADSUCK_VERSION_H

#define ADSUCK_STR(x)		#x
#define ADSUCK_STRINGIZE(x)	ADSUCK_STR(x)

#define ADSUCK_MAJOR		2
#define ADSUCK_MINOR		4
#define ADSUCK_PATCH		0
#define ADSUCK_VERSION		ADSUCK_STRINGIZE(ADSUCK_MAJOR) "." \
				ADSUCK_STRINGIZE(ADSUCK_MINOR) "." \
				ADSUCK_STRINGIZE(ADSUCK_PATCH)

#endif /* ADSUCK_VERSION_H */

