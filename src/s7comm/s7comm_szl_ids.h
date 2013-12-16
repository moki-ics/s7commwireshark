/* s7comm_szl_ids.h
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

guint32 s7comm_decode_ud_szl_subfunc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *data_tree, guint8 type, guint8 subfunc, guint8 ret_val, guint8 tsize, guint16 len, guint16 dlength, guint32 offset);

const gchar* s7comm_get_szl_id_index_description_text(guint16 id, guint16 index);

/* Known SZL IDs and indexes */
guint32 s7comm_decode_szl_id_0013_idx_0000(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);

guint32 s7comm_decode_szl_id_0111_idx_0001(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);

guint32 s7comm_decode_szl_id_0131_idx_0001(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0131_idx_0002(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0131_idx_0003(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0131_idx_0004(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0131_idx_0006(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0131_idx_0010(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);

guint32 s7comm_decode_szl_id_0132_idx_0001(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0132_idx_0002(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0132_idx_0004(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0132_idx_0005(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);
guint32 s7comm_decode_szl_id_0132_idx_0006(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);

guint32 s7comm_decode_szl_id_0424_idx_0000(tvbuff_t *tvb, proto_tree *tree, guint16 szl_partlist_len, guint16 szl_partlist_count, guint32 offset);

void s7comm_register_szl_types(int proto);


void s7comm_szl_0013_0000_register(int proto);

void s7comm_szl_xy11_0001_register(int proto);

void s7comm_szl_0131_0001_register(int proto);
void s7comm_szl_0131_0002_register(int proto);
void s7comm_szl_0131_0003_register(int proto);
void s7comm_szl_0131_0004_register(int proto);
void s7comm_szl_0131_0006_register(int proto);
void s7comm_szl_0131_0010_register(int proto);

void s7comm_szl_0132_0001_register(int proto);
void s7comm_szl_0132_0002_register(int proto);
void s7comm_szl_0132_0004_register(int proto);
void s7comm_szl_0132_0005_register(int proto);
void s7comm_szl_0132_0006_register(int proto);

void s7comm_szl_0424_0000_register(int proto);

