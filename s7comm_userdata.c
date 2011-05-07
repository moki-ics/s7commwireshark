/* s7comm_userdata.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <string.h>
#include <time.h>

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * PDU Type: User Data
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static guint32
s7comm_decode_ud(tvbuff_t *tvb, 
					   packet_info *pinfo, 
					   proto_tree *tree, 
					   guint16 plength, 
					   guint16 dlength, 
					   guint32 offset )
{
	proto_item *item = NULL;
	proto_tree *param_tree = NULL;
	proto_tree *data_tree = NULL;

	guint8 ret_val;
	guint8 tsize;
	guint16 len;
	guint32 offset_temp;
	gboolean know_data = FALSE;

	guint8 type;
	guint8 funcgroup;
	guint8 subfunc;

	/* Add parameter tree */
	item = proto_tree_add_item( tree, hf_s7comm_param, tvb, offset, plength, FALSE );
	param_tree = proto_item_add_subtree( item, ett_s7comm_param);	

	/* Try do decode some functions... 
	* Some functions may use data that does't fit one telegram
	*/
	offset_temp = offset;	/* Save offset */
	/* 3 bytes constant head */
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_head, tvb, offset_temp, 3, FALSE);
	offset_temp += 3;
	/* 1 byte length of following parameter (8 or 12 bytes) */
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_len, tvb, offset_temp, 1, FALSE);
	offset_temp += 1;
	/* 1 byte unknown, maybe indicating request/response */
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_reqres2, tvb, offset_temp, 1, FALSE);
	offset_temp += 1;
	/* High nibble (following/request/response) */
	type = (tvb_get_guint8(tvb, offset_temp) & 0xf0) >> 4;
	funcgroup = (tvb_get_guint8(tvb, offset_temp) & 0x0f);
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_type, tvb, offset_temp, 1, FALSE);

	s7comm_info_append_str(pinfo, "Function", 
		val_to_str(type, userdata_type_names, "Unknown type:0x%02x"));
	s7comm_info_append_str(pinfo, "->", 
		val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function:0x%02x"));

	proto_item_append_text(param_tree, ": (%s)", val_to_str(type, userdata_type_names, "Unknown type:0x%02x"));
	proto_item_append_text(param_tree, " ->(%s)", val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function:0x%02x"));

	/* Low nibble function group  */
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_funcgroup, tvb, offset_temp, 1, FALSE);
	offset_temp += 1;
	/* 1 Byte subfunction  */
	subfunc = tvb_get_guint8(tvb, offset_temp);
	switch (funcgroup){
		case S7COMM_UD_FUNCGROUP_PROG:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		case S7COMM_UD_FUNCGROUP_CYCLIC:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		case S7COMM_UD_FUNCGROUP_BLOCK:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		case S7COMM_UD_FUNCGROUP_SZL:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_szl_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_szl_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_szl_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		case S7COMM_UD_FUNCGROUP_SEC:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		case S7COMM_UD_FUNCGROUP_TIME:
			proto_tree_add_text(param_tree, tvb, offset_temp, 1, "Subfunction: %s (%d)", 
				val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"), subfunc);

			s7comm_info_append_str(pinfo, "->", 
				val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
			proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
			break;
		default:
			proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc, tvb, offset_temp, 1, subfunc);
			break;
	}	
	offset_temp += 1;
	/* 1 Byte sequence number  */
	proto_tree_add_item(param_tree, hf_s7comm_userdata_param_seq_num, tvb, offset_temp, 1, FALSE);
	offset_temp += 1;
	if (plength >= 12) {
		/* 2 bytes reserved */
		proto_tree_add_item(param_tree, hf_s7comm_userdata_param_reserved, tvb, offset_temp, 2, FALSE);
		offset_temp += 2;
		proto_tree_add_text(param_tree, tvb, offset_temp, 2, "Error code: 0x%04x", tvb_get_ntohs(tvb, offset_temp));
		offset_temp += 2;
	}	

	/**********************************
	 * Add data tree 
	 */
	offset += plength;	/* set offset to the beginning of the data part */
	item = proto_tree_add_item( tree, hf_s7comm_data, tvb, offset, dlength, FALSE );
	data_tree = proto_item_add_subtree( item, ett_s7comm_data);	


	/* the first 4 bytes of the  data part of a userdata telegram are the same for all types */
	if (dlength >= 4) {
		ret_val = tvb_get_guint8( tvb, offset );

		proto_tree_add_uint(data_tree, hf_s7comm_userdata_data_return_value, tvb, offset, 1, ret_val);
		offset += 1;
		/* Not definitely known part, kind of "transport size"? constant 0x09, 1 byte 
		 * The position is the same as in a data response/write telegram,
		*/
		tsize = tvb_get_guint8( tvb, offset );
		proto_tree_add_uint(data_tree, hf_s7comm_data_transport_size, tvb, offset, 1, tsize);
		offset += 1;
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(data_tree, hf_s7comm_userdata_data_length, tvb, offset, 2, len);
		offset += 2;

		/* Call function to decode the rest of the data part 
		 *  decode only when there is a data part lenght greater 4 bytes
		 */
		if (dlength > 4) {
			switch (funcgroup){
				case S7COMM_UD_FUNCGROUP_PROG:
					offset = s7comm_decode_ud_prog_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;
				case S7COMM_UD_FUNCGROUP_CYCLIC:
					offset = s7comm_decode_ud_cyclic_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;
				case S7COMM_UD_FUNCGROUP_BLOCK:
					offset = s7comm_decode_ud_block_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;
				case S7COMM_UD_FUNCGROUP_SZL:
					offset = s7comm_decode_ud_szl_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;
				case S7COMM_UD_FUNCGROUP_SEC:
					offset = s7comm_decode_ud_security_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;				
				case S7COMM_UD_FUNCGROUP_TIME:
					offset = s7comm_decode_ud_time_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
					break;
				default:
					break;
			}
		}
	}
	
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	gboolean know_data = FALSE;

	guint8 data_type;
	guint16 byte_count;
	guint16 item_count;
	guint16 i;

	switch(subfunc)
	{
		case S7COMM_UD_SUBF_PROG_VARTAB1:
			/* online status in variable table */		
			data_type = tvb_get_guint8(tvb, offset+ 1);			/* 1 Byte const 0 + 1 Byte type: 0x14 = Request, 0x04 = Response */
			proto_tree_add_text(data_tree, tvb, offset, 2, "Type of data: %s (0x%02x)", 
						val_to_str(data_type, userdata_prog_vartab_type_names, "Unknown Type of data:0x%02x"), data_type);
			offset += 2;
			
			byte_count = tvb_get_ntohs(tvb, offset);			/* 2 Bytes: Number of bytes of item-data including item-count */
			proto_tree_add_text(data_tree, tvb, offset, 2, "Byte count: %d", byte_count);
			offset += 2;
			
			switch (data_type)
			{
				case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ:
					/*** Request of data areas ***/

					/* 20 Bytes unknown part */
					proto_tree_add_text(data_tree, tvb, offset, 20,   "Unknown: 20 Bytes" );
					offset += 20;

					item_count = tvb_get_ntohs(tvb, offset);	/* 2 Bytes header: number of items following */
					proto_tree_add_text(data_tree, tvb, offset, 2, "Item count: %d", item_count);
					offset += 2;
	
					/* parse item data */				
					for (i = 0; i < item_count; i++) {
						offset = s7comm_decode_ud_prog_vartab_req_item(tvb, offset, pinfo, data_tree, i);
					}
					know_data = TRUE;
					break;

				case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES:
					/*** Response of PLC to requested data-areas ***/

					/* 4 Bytes unknown part */
					proto_tree_add_text(data_tree, tvb, offset, 4,   "Unknown: 4 Bytes" );
					offset += 4;

					item_count = tvb_get_ntohs(tvb, offset);	/* 2 Bytes: number of items following */
					proto_tree_add_text(data_tree, tvb, offset, 2, "Item count: %d", item_count);
					offset += 2;

					/* parse item data */				
					for (i = 0; i < item_count; i++) {
						offset = s7comm_decode_ud_prog_vartab_res_item(tvb, offset, pinfo, data_tree, i);
					}
					know_data = TRUE;
					break;
			}
	}

	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Variable table -> request
 *
 *******************************************************************************************************/

static guint32
s7comm_decode_ud_prog_vartab_req_item(tvbuff_t *tvb, 
						  guint32 offset, 
						  packet_info *pinfo, 
						  proto_tree *sub_tree, 
						  guint16 item_no)
{
	guint32 address = 0;
	guint32 bytepos = 0;
	guint16 len = 0;
	guint16 db = 0;
	guint8 area = 0;
	proto_item *item = NULL;

	/* Insert a new tree with 6 bytes for every item */
	item = proto_tree_add_item( sub_tree, hf_s7comm_param_item, tvb, offset, 6, FALSE );

	sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);

	proto_item_append_text(item, " [%d]:", item_no + 1);

	/* Area, 1 byte */
	area = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(item, tvb, offset, 1, "Memory area: %s (0x%02x)", 
						val_to_str(area, userdata_prog_vartab_area_names, "Unknown area: 0x%02x"), area);
	offset += 1;

	/* Length (repetition factor), 1 byte */
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(item, tvb, offset, 1, "Repetition factor: %d", len);
	offset += 1;

	/* DB number, 2 bytes */
	db = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(item, tvb, offset, 2, "DB number: %d", db);	
	offset += 2;

	/* byte offset, 2 bytes */
	bytepos = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(item, tvb, offset, 2, "Startaddress: %d", bytepos);	
	offset += 2;

	/* build a full adress to show item data directly beside the item */
	switch (area) {
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB):
			proto_item_append_text(item, " (M%d.0 BYTE %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW):
			proto_item_append_text(item, " (M%d.0 WORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD):
			proto_item_append_text(item, " (M%d.0 DWORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB):
			proto_item_append_text(item, " (I%d.0 BYTE %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW):
			proto_item_append_text(item, " (I%d.0 WORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED):
			proto_item_append_text(item, " (I%d.0 DWORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB):
			proto_item_append_text(item, " (Q%d.0 BYTE %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW):
			proto_item_append_text(item, " (Q%d.0 WORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD):
			proto_item_append_text(item, " (Q%d.0 DWORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB):
			proto_item_append_text(item, " (PI%d.0 BYTE %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW):
			proto_item_append_text(item, " (PI%d.0 WORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED):
			proto_item_append_text(item, " (PI%d.0 DWORD %d)", bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB):
			proto_item_append_text(item, " (DB%d.DX%d.0 BYTE %d)", db, bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW):
			proto_item_append_text(item, " (DB%d.DX%d.0 WORD %d)", db, bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD):
			proto_item_append_text(item, " (DB%d.DX%d.0 DWORD %d)", db, bytepos, len);
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_T):
			proto_item_append_text(item, " (T %d", bytepos);
			if (len >1) 
				proto_item_append_text(item, "..%d)", bytepos + len -1);	/* it's possible to read multiple timers */
			else
				proto_item_append_text(item, ")");
			break;
		case (S7COMM_UD_SUBF_PROG_VARTAB_AREA_C):
			proto_item_append_text(item, " (C %d", bytepos);
			if (len >1) 
				proto_item_append_text(item, "..%d)", bytepos + len -1);	/* it's possible to read multiple counters */
			else
				proto_item_append_text(item, ")");
			break;

	}
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Variable table -> response
 *
 *******************************************************************************************************/

static guint32
s7comm_decode_ud_prog_vartab_res_item(tvbuff_t *tvb, 
						  guint32 offset, 
						  packet_info *pinfo, 
						  proto_tree *sub_tree, 
						  guint16 item_no)
{
	guint32 address = 0;
	guint32 bytepos = 0;
	guint16 len = 0, len2;
	guint16 db = 0;
	guint8 area = 0;
	guint8 ret_val, tsize;
	guint8 head_len = 4;

	proto_item *item = NULL;


	ret_val = tvb_get_guint8( tvb, offset );
	if (ret_val == S7COMM_ITEM_RETVAL_RESERVED || 
		ret_val == S7COMM_ITEM_RETVAL_DATA_OK || 
		ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
		) {
		tsize = tvb_get_guint8( tvb, offset + 1 );
		len = tvb_get_ntohs(tvb, offset + 2);

		if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BIT || tsize == S7COMM_DATA_TRANSPORT_SIZE_BIT2) {
			len /= 8;
		}
		/* the PLC places extra bytes at the end if length is not a multiple of 2 */
		if (len % 2) {
			len2 = len + 1;
		}else {
			len2 = len;
		}
	}
	/* Insert a new tree for every item */
	item = proto_tree_add_item( sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, FALSE );
	sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

	proto_item_append_text(item, " [%d]: (%s)", item_no + 1, val_to_str(ret_val, item_return_valuenames, "Unknown code:0x%02x"));
	proto_tree_add_uint(sub_tree, hf_s7comm_item_return_value, tvb, offset, 1, ret_val);

	proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);	


	proto_tree_add_text(sub_tree, tvb, offset + 2, 2 , "Data length: %d Bytes", len);
	offset += head_len;
	if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {		
		proto_tree_add_bytes(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len,
				tvb_get_ptr (tvb, offset, len));
		offset += len;
		if (len != len2) {
			proto_tree_add_text(sub_tree, tvb, offset, 1 , "Fill byte: 0x%02x", tvb_get_guint8( tvb, offset ));
			offset += 1;
		}
	}
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 2 -> cyclic data
 * userdata_cyclic_subfunc_names
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_cyclic_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	gboolean know_data = FALSE;
	guint8 item_count;
	guint8 i;

	switch (subfunc)
	{
		case S7COMM_UD_SUBF_CYCLIC_MEM:				
			item_count = tvb_get_guint8( tvb, offset + 1 );	/* first byte reserved??? */	
			proto_tree_add_uint(data_tree, hf_s7comm_param_itemcount, tvb, offset, 2, item_count);
			offset += 1;
			offset += 1;
			if (type == S7COMM_UD_TYPE_REQ) {		/* Request to PLC to send cyclic data */
				proto_tree_add_text(data_tree, tvb, offset, 1, "Interval timebase: %d", tvb_get_guint8(tvb, offset));
				offset += 1;
				proto_tree_add_text(data_tree, tvb, offset, 1, "Interval time    : %d", tvb_get_guint8(tvb, offset));
				offset += 1;
				/* parse item data */				
				for (i = 0; i < item_count; i++) {
					offset = s7comm_decode_param_item(tvb, offset, pinfo, data_tree, i);
				}
				
			} else if (type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_FOLLOW) {	/* Response from PLC with the requested data */
				/* parse item data 
				 */
				offset = s7comm_decode_response_read_data( tvb, pinfo, data_tree, dlength, item_count, offset);
			}
			know_data = TRUE;
			break;
	}

	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 3 -> block functions
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_block_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	guint16 count;
	guint16 i;
	guint8 *blocknumber;
	gboolean know_data = FALSE;
	char str_timestamp[25];

	switch (subfunc) {
		/*************************************************
		 * List blocks 
		 */
		case S7COMM_UD_SUBF_BLOCK_LIST:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/
				

			} else if (type == S7COMM_UD_TYPE_RES) {			/*** Response ***/						
				count = len / 4;
				for(i = 0; i < count; i++) {		
					proto_tree_add_text(data_tree, tvb, offset, 2, "Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset, 2, "Count: %d", tvb_get_ntohs(tvb, offset));
					offset += 2;
				}
				know_data = TRUE;
			}
			break;
		/*************************************************
		 * List blocks of type
		 */
		case S7COMM_UD_SUBF_BLOCK_LISTTYPE:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/
				if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
					proto_tree_add_text(data_tree, tvb, offset, 2, "Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					proto_item_append_text(data_tree, ": (%s)", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					offset += 2;
				}
				know_data = TRUE;

			}else if (type == S7COMM_UD_TYPE_RES) {				/*** Response ***/	
				if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
					count = len / 4;
	
					for(i = 0; i < count; i++) {
						proto_tree_add_text(data_tree, tvb, offset, 2, "Block number   : %d", tvb_get_ntohs(tvb, offset));
						offset += 2;					

						/* The first Byte is unknown, but the second byte is the block language */
						
						proto_tree_add_text(data_tree, tvb, offset, 1, "Unknown        : 0x%02x", tvb_get_guint8(tvb, offset));
						offset += 1;
						proto_tree_add_text(data_tree, tvb, offset, 1, "Block language : %s", 
							val_to_str(tvb_get_guint8(tvb, offset), blocklanguage_names, "Unknown Block language: 0x%02x"));					
						offset += 1;
					}
				}
				know_data = TRUE;
			}
			break;
		/*************************************************
		 * Get block infos
		 */
		case S7COMM_UD_SUBF_BLOCK_BLOCKINFO:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/
				if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
					/* 8 Bytes of Data follow, 1./ 2. type, 3-7 blocknumber as ascii number, 8. 'A' or 'B' unknown */		
					proto_tree_add_text(data_tree, tvb, offset, 2, "Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));										
					proto_item_append_text(data_tree, ": (Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					/* Add block type and number to info column */
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type:0x%02x"));
					offset += 2;					
					blocknumber = tvb_get_ephemeral_string(tvb, offset, 5);
					proto_tree_add_text(data_tree, tvb, offset , 5, "Block number: %s", blocknumber);
					s7comm_info_append_str(pinfo, "No.", blocknumber);
					proto_item_append_text(data_tree, ", Number: %s)", blocknumber);
					offset += 5;
					proto_tree_add_text(data_tree, tvb, offset , 1, "Unknown const: '%c'", tvb_get_guint8(tvb, offset));
					offset += 1;
				}
				know_data = TRUE;

			}else if (type == S7COMM_UD_TYPE_RES) {				/*** Response ***/
				/* 78 Bytes */
				if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Const.          : 0x%02x", tvb_get_guint8(tvb, offset));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 1,	  "Block type      : %s", 
						val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type:0x%02x"));

					proto_item_append_text(data_tree, ": (Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type:0x%02x"));

					/* Add block type and number to info column */
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type:0x%02x"));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Const.          : 0x%04x", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Const.          : 0x%04x", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Const.'pp'      : 0x%04x", tvb_get_ntohs(tvb, offset));
					offset += 2;

					proto_tree_add_text(data_tree, tvb, offset , 1,   "Unknown         : 0x%02x", tvb_get_guint8(tvb, offset));
					offset += 1;

					/* Configuration flags? Bits?
					 * Bits: 0 0 0 0   0 0 0 0   0 0 0 0   0 0 0 0
					 * Pos : 31 ..                             ..0   
					 * 
					 * Bit : 0 -> DB Linked = true
					 * Bit : 5 -> DB Non Retain = true
					 * Standard FC/FC/DB -> 0x0101        0x0100 -> dieses Bit (8) bei FBs für Multiinstanzfähigkeit?
					 * SFC:  0x0009  SFB: 0x0109 or 0x010d (e.g. SFB8, 414)
					 */

				
					proto_tree_add_item(data_tree, hf_s7comm_userdata_blockinfo_flags, tvb, offset, 1, FALSE);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_blockinfo_linked, tvb, offset, 1, FALSE);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_blockinfo_standard_block, tvb, offset, 1, FALSE);					
					proto_tree_add_item(data_tree, hf_s7comm_userdata_blockinfo_nonretain, tvb, offset, 1, FALSE);
					offset += 1;

					proto_tree_add_text(data_tree, tvb, offset , 1,   "Block language  : %s",
						val_to_str(tvb_get_guint8(tvb, offset), blocklanguage_names, "Unknown Block language:0x%02x"));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Subblk type     : %s",
						val_to_str(tvb_get_guint8(tvb, offset), subblktype_names, "Unknown Bubblk type:0x%02x"));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Block number    : %d", tvb_get_ntohs(tvb, offset));
					s7comm_info_append_uint16(pinfo, "No.", tvb_get_ntohs(tvb, offset));
					proto_item_append_text(data_tree, ", Number: %d)", tvb_get_ntohs(tvb, offset));
					offset += 2;
					/* "Length Load mem" -> the length in Step7 Manager seems to be this length +6 bytes */
					proto_tree_add_text(data_tree, tvb, offset , 4,	  "Length load mem.: %d bytes", tvb_get_ntohl(tvb, offset));
					offset += 4;
					proto_tree_add_text(data_tree, tvb, offset , 4,   "Block Security  : %s",
						val_to_str(tvb_get_ntohl(tvb, offset), blocksecurity_names, "Unknown block security:%ld"));
					offset += 4;
					get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
					proto_tree_add_text(data_tree, tvb, offset , 6,   "Code timestamp  : %s", str_timestamp);
					offset += 6;
					get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
					proto_tree_add_text(data_tree, tvb, offset , 6,   "Inteface timest.: %s", str_timestamp);
					offset += 6;
					proto_tree_add_text(data_tree, tvb, offset , 2,	  "SSB length      : %d", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 2,	  "ADD length      : %d", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 2,	  "Length localdata: %d bytes", tvb_get_ntohs(tvb, offset));
					offset += 2;					
					proto_tree_add_text(data_tree, tvb, offset , 2,	  "Length MC7 code : %d bytes", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 8,   "Author          : %s", tvb_get_ephemeral_string(tvb, offset, 8));
					offset += 8;
					proto_tree_add_text(data_tree, tvb, offset , 8,   "Family          : %s", tvb_get_ephemeral_string(tvb, offset, 8));					
					offset += 8;
					proto_tree_add_text(data_tree, tvb, offset , 8,   "Name (Header)   : %s", tvb_get_ephemeral_string(tvb, offset, 8));
					offset += 8;
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Version (Header): %d.%d", 
						((tvb_get_guint8(tvb, offset) & 0xf0) >> 4), tvb_get_guint8(tvb, offset) & 0x0f);
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Unknown         : 0x%02x", tvb_get_guint8(tvb, offset));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Block checksum  : 0x%04x", tvb_get_ntohs(tvb, offset));
					offset += 2;
					proto_tree_add_text(data_tree, tvb, offset , 4,   "Reserved1       : %ld", tvb_get_ntohl(tvb, offset));
					offset += 4;
					proto_tree_add_text(data_tree, tvb, offset , 4,   "Reserved2       : %ld", tvb_get_ntohl(tvb, offset));
					offset += 4;
				}
				know_data = TRUE;
				
			}
			break;
		default:
			break;
	}
	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}
/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_szl_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	guint16 id;
	guint16 index;
	guint16 list_len;
	guint16 list_count;
	guint16 i;
	guint16 tbytes;

	gboolean know_data = FALSE;

	switch (subfunc) {
		/*************************************************
		 * Read SZL
		 */
		case S7COMM_UD_SUBF_SZL_READ:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/				
				id = tvb_get_ntohs(tvb, offset);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id, tvb, offset, 2, FALSE);
				offset += 2;	
				index = tvb_get_ntohs(tvb, offset);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_index, tvb, offset, 2, FALSE);
				offset += 2;
				proto_item_append_text(data_tree, " (SZL-ID: 0x%04x, Index: 0x%04x)", id, index);		
				s7comm_info_append_uint16hex(pinfo, "ID", id);
				s7comm_info_append_uint16hex(pinfo, "Index", index);
				know_data = TRUE;

			} else if (type == S7COMM_UD_TYPE_RES) {			/*** Response ***/						
				/* When response OK, data follows */
				if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK ) {
					id = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id, tvb, offset, 2, FALSE);
					offset += 2;
					index = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_index, tvb, offset, 2, FALSE);
					offset += 2;					
					proto_item_append_text(data_tree, " (SZL-ID: 0x%04x, Index: 0x%04x)", id, index);					
					s7comm_info_append_uint16hex(pinfo, "ID", id);
					s7comm_info_append_uint16hex(pinfo, "Index", index);					
					/* SZL-Data, 4 Bytes header, 4 bytes id/index = 8 bytes */
					list_len = tvb_get_ntohs(tvb, offset); /* Length of an list set in bytes */
					proto_tree_add_text(data_tree, tvb, offset, 2, "SZL partial list length: %d bytes", list_len);
					offset += 2;
					list_count = tvb_get_ntohs(tvb, offset); /* count of partlists */
					proto_tree_add_text(data_tree, tvb, offset, 2, "SZL partial list count: %d", list_count);
					/* Some SZL responses got more lists than fit one PDU (e.g. Diagnosepuffer) and must be read
					 * out in several telegrams, so we have to check here if the list_count is above limits
					 * of the lenght of data part. The remainding bytes will be print as raw bytes, because
					 * it's not possible to decode this and following telegrams without knowing the previous requests.
					 */
					tbytes = 0;
					if ((list_count * list_len) > (len - 8)) {
						list_count = (len - 8) / list_len;
						/* remind the number of trailing bytes */
						if (list_count > 0) {
							tbytes = (len - 8) % list_count;
						}
					}
					/*proto_item_append_text(data_tree, " (len: %d, tbytes: %d, list_count: %d)",len, tbytes, list_count); */

					offset += 2;		
					/* Add a Data element for each partlist */
					if (len > 8) {	/* minimum length of a correct szl data part is 8 bytes */

						/* lets try to decode some known szl-id and indexes */
						if (id == 0x0131 && index == 0x0001) {
							offset += s7comm_decode_ud_szl_id_0131_idx_0001(tvb, data_tree, list_len, list_count, offset);
						} else if (id == 0x0131 && index == 0x0002) {
							offset += s7comm_decode_ud_szl_id_0131_idx_0002(tvb, data_tree, list_len, list_count, offset);
						
						} else {

							for (i = 1; i <= list_count; i++) {
								proto_tree_add_bytes(data_tree, hf_s7comm_userdata_szl_partial_list, tvb, offset, list_len,
									tvb_get_ptr (tvb, offset, list_len));
								offset += list_len;
							}
							/* add raw bytes of data part when SZL response doesn't fit one PDU */
							if (tbytes > 0) {							
								proto_tree_add_bytes(data_tree, hf_s7comm_userdata_szl_partial_list, tvb, offset, tbytes,
									tvb_get_ptr (tvb, offset, tbytes));
								offset += tbytes;
							}
						}
					}
				} else {
					s7comm_info_append_str(pinfo, "Return value", 
						val_to_str(ret_val, item_return_valuenames, "Unknown return value:0x%02x"));
				}
				know_data = TRUE;
			}
			break;
		default:
			break;
	}
	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}



/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 5 -> Security functions?
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_security_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	gboolean know_data = FALSE;
	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}


/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 7 -> time functions
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_time_subfunc(tvbuff_t *tvb, 
									packet_info *pinfo,
									proto_tree *data_tree, 
									guint8 type,				/* Type of data (request/response) */
									guint8 subfunc,				/* Subfunction */
									guint8 ret_val,				/* Return value in data part */
									guint8 tsize,				/* transport size in data part */
									guint16 len,				/* length given in data part */
									guint16 dlength,			/* length of data part given in header */
									guint32 offset )			/* Offset on data part +4 */
{
	gboolean know_data = FALSE;

	switch (subfunc) {
		/*************************************************
		 * Read SZL
		 */
		case S7COMM_UD_SUBF_TIME_READ:
		case S7COMM_UD_SUBF_TIME_READF:
			if (type == S7COMM_UD_TYPE_RES) {			/*** Response ***/
				if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK ) {
					proto_item_append_text(data_tree, ": ");
					offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE);
				}
				know_data = TRUE;				
			}
			break;
		case S7COMM_UD_SUBF_TIME_SET:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/	
				if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK ) {
					proto_item_append_text(data_tree, ": ");
					offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE);
				}
				know_data = TRUE;
			} 
			break;
		default:
			break;
	}

	if (know_data == FALSE && dlength > 4) {
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}