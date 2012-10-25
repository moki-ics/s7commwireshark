/* s7comm_helper.h
*
* Author:		Thomas Wiens, 2011 (th.wiens@gmx.de)
* Version:		0.0.2
* Description:	Wireshark dissector for S7-Communication
*
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

void s7comm_info_append_uint32(packet_info *pinfo, const char *abbrev, guint32 val);
void s7comm_info_append_uint16(packet_info *pinfo, const char *abbrev, guint16 val);
void s7comm_info_append_uint16hex(packet_info *pinfo, const char *abbrev, guint16 val);
void s7comm_info_append_str(packet_info *pinfo, const char *abbrev, const char *val);

void get_timestring_from_s7time(tvbuff_t *tvb, guint offset, char *str, gint max);
guint8 s7comm_guint8_from_bcd(guint8 i);
guint32 s7comm_add_timestamp_to_tree(tvbuff_t *tvb, proto_tree *tree, guint32 offset, gboolean append_text);