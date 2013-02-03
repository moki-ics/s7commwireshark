/* s7comm_helper.c
 * Wireshark dissector for S7-Communication
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <string.h>
#include <time.h>

/*******************************************************************************************************
 * Weekday names in DATE_AND_TIME
 *******************************************************************************************************/
static const value_string weekdaynames[] = {
	{ 0,								"Undefined" },
	{ 1,								"Sunday" },
	{ 2,								"Monday" },
	{ 3,								"Tuesday" },
	{ 4,								"Wednesday" },
	{ 5,								"Thursday" },
	{ 6,								"Friday" },
	{ 7,								"Saturday" },
	{ 0,							 	NULL }
};

/*******************************************************************************************************
 *
 * Helper functions to append info text 
 *
 *******************************************************************************************************/
void
s7comm_info_append_uint32(packet_info *pinfo, const char *abbrev, guint32 val)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", abbrev, val);
}

void
s7comm_info_append_uint16(packet_info *pinfo, const char *abbrev, guint16 val)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", abbrev, val);
}

void
s7comm_info_append_str(packet_info *pinfo, const char *abbrev, const char *val)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s:[%s]", abbrev, val);
}

void
s7comm_info_append_uint16hex(packet_info *pinfo, const char *abbrev, guint16 val)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s=0x%04x", abbrev, val);
}

/*******************************************************************************************************
 *
 * Converts a siemens special timestamp to a string of 24+1 bytes length (e.g. "15.04.2009 12:49:30.520").
 * The timestamp is 6 bytes long, one word is the number of days since 1.1.1984, and 4 bytes millisecods of the day
 *
 *******************************************************************************************************/
void 
get_timestring_from_s7time(tvbuff_t *tvb, guint offset, char *str, gint max)
{
	guint16 days;
	guint32 day_msec;
	struct tm *mt;
	time_t t;

	day_msec = tvb_get_ntohl(tvb, offset);
	days = tvb_get_ntohs(tvb, offset + 4);

	t = 441763200L; /* 1.1.1984 00:00:00 */
	t += days * (24*60*60);
	t += day_msec / 1000;
	mt = gmtime(&t);
	g_snprintf(str, max, "%02d.%02d.%04d %02d:%02d:%02d.%03d", 	mt->tm_mday, 
																mt->tm_mon + 1,
																mt->tm_year + 1900,
																mt->tm_hour,
																mt->tm_min,
																mt->tm_sec,
																day_msec % 1000);
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Get int from bcd
 *
 *******************************************************************************************************/
guint8
s7comm_guint8_from_bcd(guint8 i)
{
	return 10 * (i /16) + (i % 16);
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Add a BCD coded timestamp (10 Bytes length) to tree
 *
 *******************************************************************************************************/
guint32
s7comm_add_timestamp_to_tree(tvbuff_t *tvb,
							 proto_tree *tree,
							 guint32 offset,
							 gboolean append_text)
{
	guint8 time[10];
	guint8 i;
	guint8 weekday;
	guint8 tmp;
	
	/* The low nibble of byte 10 is weekday, the high nibble the LSD of msec */
	tmp = tvb_get_guint8(tvb, offset + 9) & 0x0f;
	weekday = s7comm_guint8_from_bcd( tmp );

	for (i = 0;i < 9; i++) {
		time[i] = s7comm_guint8_from_bcd(tvb_get_guint8(tvb, offset + i));						
	}
	tmp = tvb_get_guint8(tvb, offset + 9) >> 4;
	time[9] = s7comm_guint8_from_bcd( tmp );

	proto_tree_add_text(tree, tvb, offset + 0, 1, "Reserved: %d", time[0]);				
	proto_tree_add_text(tree, tvb, offset + 1, 2, "Year    : %02d%02d", time[1], time[2]);
	proto_tree_add_text(tree, tvb, offset + 3, 1, "Month   : %d", time[3]);
	proto_tree_add_text(tree, tvb, offset + 4, 1, "Day     : %d", time[4]);
	proto_tree_add_text(tree, tvb, offset + 5, 1, "Hour    : %d", time[5]);
	proto_tree_add_text(tree, tvb, offset + 6, 1, "Minute  : %d", time[6]);
	proto_tree_add_text(tree, tvb, offset + 7, 1, "Second  : %d", time[7]);

	proto_tree_add_text(tree, tvb, offset + 8, 2, "Msec    : %02d%d", time[8],time[9]);
	proto_tree_add_text(tree, tvb, offset + 9, 1, "Weekday : %s (%d)",  
		val_to_str(weekday, weekdaynames, "Unknown weekday:%d"), weekday);
	offset += 10;
	if (append_text == TRUE) {
		/* mm/dd/yyyy hh:mm:ss.SSSS */
		proto_item_append_text(tree, "(Timestamp: %02d/%02d/%02d%02d %02d:%02d:%02d.%02d%d)", time[3], time[4], time[1], time[2],
										time[5],time[6], time[7], time[8], time[9]);
	}
	return offset;
}

