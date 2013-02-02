/* s7comm_szl_ids.c
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

#include "s7comm_szl_ids.h"
#include "s7comm_helper.h"


/* TODO:
 * Redefines from main-file, has to be corrected! 
 */


/**************************************************************************
 * Names of userdata subfunctions in group 4 (SZL functions)
 */
#define S7COMM_UD_SUBF_SZL_READ			0x01
#define S7COMM_UD_SUBF_SZL_ASMESS		0x02

const value_string userdata_szl_subfunc_names[] = {
	{ S7COMM_UD_SUBF_SZL_READ,			"Read SZL" },
	{ S7COMM_UD_SUBF_SZL_ASMESS,		"System-state" },	/* Header constant is also different here */
	{ 0,								NULL }
};
/**************************************************************************
 * Names of types in userdata parameter part
 */
#define S7COMM_UD_TYPE_FOLLOW			0x0			
#define S7COMM_UD_TYPE_REQ				0x4
#define S7COMM_UD_TYPE_RES				0x8

static const value_string userdata_type_names[] = {
	{ S7COMM_UD_TYPE_FOLLOW,			"Follow  " },	/* this type comes when 2 telegrams follow aftes another from the same partner, or initiated from PLC */
	{ S7COMM_UD_TYPE_REQ,				"Request " },
	{ S7COMM_UD_TYPE_RES,				"Response" },
	{ 0,								NULL }
};
/**************************************************************************
 * Returnvalues of an item response
 */
#define S7COMM_ITEM_RETVAL_RESERVED				0x00
#define S7COMM_ITEM_RETVAL_DATA_OK				0xff
#define S7COMM_ITEM_RETVAL_DATA_ERR				0x0a	/* the desired item is not available in the PLC, e.g. when trying to read a non existing DB*/
#define S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE		0x05	/* the desired address is beyond limit for this PLC */
#define S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH	0x07	/* Write data size error */

static const value_string item_return_valuenames[] = {
	{ S7COMM_ITEM_RETVAL_RESERVED,				"Reserved" },
	{ S7COMM_ITEM_RETVAL_DATA_OK,				"Item OK" },
	{ S7COMM_ITEM_RETVAL_DATA_ERR,				"Item not available" },
	{ S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE,		"Adress out of range" },
	{ S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH,		"Write data size error" },
	{ 0,								NULL }
};

static gint ett_s7comm_szl = -1;

static gint hf_s7comm_userdata_szl_partial_list = -1;		/* Partial list in szl response */
static gint hf_s7comm_userdata_szl_id = -1;					/* SZL id */

static const value_string szl_module_type_names[] = {
	{ 0x0000,	"CPU" },	/* Binary: 0000 */
	{ 0x0100,	"IM" },		/* Binary: 0100 */
	{ 0xC000,	"CP" },		/* Binary: 1100 */
	{ 0x8000,	"FM" },		/* Binary: 1000 */
	{ 0,	NULL }
};
static gint hf_s7comm_userdata_szl_id_type = -1;

static gint hf_s7comm_userdata_szl_id_partlist_ex = -1;

static const value_string szl_partial_list_names[] = {
	{ 0x0000,	"List of all the SZL-IDs of a module" },
	{ 0x0011,	"Module identification" },
	{ 0x0012,	"CPU characteristics" },
	{ 0x0013,	"User memory areas" },
	{ 0x0014,	"System areas" },
	{ 0x0015,	"Block types" },
	{ 0x0016,	"Priority classes" },
	{ 0x0017,	"List of the permitted SDBs with a number < 1000" },
	{ 0x0018,	"Maximum S7-300 I/O configuration" },
	{ 0x0019,	"Status of the module LEDs" },
	{ 0x001c,	"Component Identification" },
	{ 0x0021,	"Interrupt / error assignment" },
	{ 0x0022,	"Interrupt status" },
	{ 0x0023,	"Priority classes" },
	{ 0x0024,	"Modes" },
	{ 0x0025,	"Assignment between process image partitions and OBs" },
	{ 0x0031,	"Communication capability parameters" },
	{ 0x0032,	"Communication status data" },
	{ 0x0033,	"Diagnostics: device logon list" },
	{ 0x0037,	"Ethernet - Details of a Module" },
	{ 0x0071,	"H CPU group information" },
	{ 0x0074,	"Status of the module LEDs" },
	{ 0x0075,	"Switched DP slaves in the H-system" },
	{ 0x0081,	"Start information list" },
	{ 0x0082,	"Start event list" },
	{ 0x0091,	"Module status information" },
	{ 0x0092,	"Rack / station status information" },
	{ 0x0094,	"Rack / station status information" },
	{ 0x0095,	"Extended DP master system information" },
	{ 0x0096,	"Module status information, PROFINET IO and PROFIBUS DP" },
	{ 0x00a0,	"Diagnostic buffer of the CPU" },
	{ 0x00b1,	"Module diagnostic information (data record 0)" },
	{ 0x00b2,	"Module diagnostic information (data record 1), geographical address" },
	{ 0x00b3,	"Module diagnostic information (data record 1), logical address" },
	{ 0x00b4,	"Diagnostic data of a DP slave" },
	{ 0,	NULL }
};
static gint hf_s7comm_userdata_szl_id_partlist_num = -1;

static gint hf_s7comm_userdata_szl_index = -1;				/* SZL index */
static gint hf_s7comm_userdata_szl_tree = -1;				/* SZL item tree */
static gint hf_s7comm_userdata_szl_data = -1;				/* SZL raw data */

/* Header fields of the SZL */

static gint hf_s7comm_szl_0013_0000_index = -1;
static const value_string szl_memory_area_names[] = {
	{ 0x0001,	"work memory" },
	{ 0x0002,	"load memory integrated" },
	{ 0x0003,	"load memory plugged in" },
	{ 0x0004,	"maximum plug-in load memory" },
	{ 0x0005,	"size of the backup memory" },
	{ 0x0005,	"size of the memory reserved by the system for CFBs" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0013_0000_code = -1;
static const value_string szl_memory_type_names[] = {
	{ 0x0001,	"volatile memory (RAM)" },
	{ 0x0002,	"non-volatile memory (FEPROM)" },
	{ 0x0003,	"mixed memory (RAM + FEPROM)" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0013_0000_size = -1;
static gint hf_s7comm_szl_0013_0000_mode = -1;
static gint hf_s7comm_szl_0013_0000_mode_0 = -1;
static gint hf_s7comm_szl_0013_0000_mode_1 = -1;
static gint hf_s7comm_szl_0013_0000_mode_2 = -1;
static gint hf_s7comm_szl_0013_0000_mode_3 = -1;
static gint hf_s7comm_szl_0013_0000_mode_4 = -1;
static gint hf_s7comm_szl_0013_0000_granu = -1;
static gint hf_s7comm_szl_0013_0000_ber1 = -1;
static gint hf_s7comm_szl_0013_0000_belegt1 = -1;
static gint hf_s7comm_szl_0013_0000_block1 = -1;
static gint hf_s7comm_szl_0013_0000_ber2 = -1;
static gint hf_s7comm_szl_0013_0000_belegt2 = -1;
static gint hf_s7comm_szl_0013_0000_block2 = -1;


static gint hf_s7comm_szl_0111_0001_index = -1;
static gint hf_s7comm_szl_0111_0001_mlfb = -1;
static gint hf_s7comm_szl_0111_0001_bgtyp = -1;
static gint hf_s7comm_szl_0111_0001_ausbg = -1;
static gint hf_s7comm_szl_0111_0001_ausbe = -1;

static gint hf_s7comm_szl_0131_0001_index = -1;
static gint hf_s7comm_szl_0131_0001_pdu = -1;
static gint hf_s7comm_szl_0131_0001_anz= -1;
static gint hf_s7comm_szl_0131_0001_mpi_bps = -1;
static gint hf_s7comm_szl_0131_0001_kbus_bps = -1;
static gint hf_s7comm_szl_0131_0001_res = -1;

static gint hf_s7comm_szl_0131_0002_index = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0002_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0002_aseg = -1;
static gint hf_s7comm_szl_0131_0002_eseg = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_3 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_4 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_5 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_6 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_0_7 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_0 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_1 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_3 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_4 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_5 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_6 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_1_7 = -1;
static gint hf_s7comm_szl_0131_0002_trgereig_2 = -1;
static gint hf_s7comm_szl_0131_0002_trgbed = -1;
static gint hf_s7comm_szl_0131_0002_pfad = -1;
static gint hf_s7comm_szl_0131_0002_tiefe = -1;
static gint hf_s7comm_szl_0131_0002_systrig = -1;
static gint hf_s7comm_szl_0131_0002_erg_par = -1;
static gint hf_s7comm_szl_0131_0002_erg_pat_1 = -1;
static gint hf_s7comm_szl_0131_0002_erg_pat_2 = -1;
static gint hf_s7comm_szl_0131_0002_force = -1;
static gint hf_s7comm_szl_0131_0002_time = -1;
static gint hf_s7comm_szl_0131_0002_res = -1;

static gint hf_s7comm_szl_0131_0003_index = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_0 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_1 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_2 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_3 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_4 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_5 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_6 = -1;
static gint hf_s7comm_szl_0131_0003_funkt_3_7 = -1;
static gint hf_s7comm_szl_0131_0003_data = -1;
static gint hf_s7comm_szl_0131_0003_anz = -1;
static gint hf_s7comm_szl_0131_0003_per_min = -1;
static gint hf_s7comm_szl_0131_0003_per_max = -1;
static gint hf_s7comm_szl_0131_0003_res = -1;

static gint hf_s7comm_szl_0131_0004_index = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_0_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_1_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_2_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_3_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_0 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_1 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_2 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_3 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_4 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_4_7 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_5 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_6 = -1;
static gint hf_s7comm_szl_0131_0004_funkt_7 = -1;
static gint hf_s7comm_szl_0131_0004_kop = -1;
static gint hf_s7comm_szl_0131_0004_del = -1;
static gint hf_s7comm_szl_0131_0004_kett = -1;
static gint hf_s7comm_szl_0131_0004_hoch = -1;
static gint hf_s7comm_szl_0131_0004_ver = -1;
static gint hf_s7comm_szl_0131_0004_res = -1;


static gint hf_s7comm_szl_0132_0001_index = -1;
static gint hf_s7comm_szl_0132_0001_res_pg = -1;
static gint hf_s7comm_szl_0132_0001_res_os = -1;
static gint hf_s7comm_szl_0132_0001_u_pg = -1;
static gint hf_s7comm_szl_0132_0001_u_os = -1;
static gint hf_s7comm_szl_0132_0001_proj = -1;
static gint hf_s7comm_szl_0132_0001_auf = -1;
static gint hf_s7comm_szl_0132_0001_free = -1;
static gint hf_s7comm_szl_0132_0001_used = -1;
static gint hf_s7comm_szl_0132_0001_last = -1;
static gint hf_s7comm_szl_0132_0001_res = -1;

static gint hf_s7comm_szl_0132_0002_index = -1;
static gint hf_s7comm_szl_0132_0002_anz = -1;
static gint hf_s7comm_szl_0132_0002_res = -1;

static gint hf_s7comm_szl_0132_0004_index = -1;
static gint hf_s7comm_szl_0132_0004_key = -1;
static gint hf_s7comm_szl_0132_0004_param = -1;
static gint hf_s7comm_szl_0132_0004_real = -1;
static gint hf_s7comm_szl_0132_0004_bart_sch = -1;

static const value_string szl_bart_sch_names[] = {
	{ 0,	"undefined or cannot be ascertained" },
	{ 1,	"RUN" },
	{ 2,	"RUN_P" },
	{ 3,	"STOP" },
	{ 4,	"MRES" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0132_0004_crst_wrst = -1;
static const value_string szl_crst_wrst_names[] = {
	{ 0,	"undefined, does not exist or cannot be be ascertained" },
	{ 1,	"CRST" },
	{ 2,	"WRST" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0132_0004_res = -1;



static gint hf_s7comm_szl_0424_0000_ereig = -1;
static gint hf_s7comm_szl_0424_0000_ae = -1;
static gint hf_s7comm_szl_0424_0000_bzu_id = -1;
static const value_string szl_0424_0000_bzu_id_names[] = {
	{ 0x1,	"STOP (update)" },
	{ 0x2,	"STOP (memory reset)" },
	{ 0x3,	"STOP (self initialization)" },
	{ 0x4,	"STOP (internal)" },
	{ 0x5,	"Startup (complete restart)" },
	{ 0x7,	"Restart" },
	{ 0x8,	"RUN" },
	{ 0xa,	"HOLD" },
	{ 0xd,	"DEFECT" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0424_0000_res = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo1 = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo2 = -1;
static const value_string szl_0424_0000_anlinfo2_names[] = {
	{ 0x01,	"Complete restart in multicomputing" },
	{ 0x03,	"Complete restart set at mode selector" },
	{ 0x04,	"Complete restart command via MPI" },
	{ 0x0a,	"Restart in multicomputing" },
	{ 0x0b,	"Restart set at mode selector" },
	{ 0x0c,	"Restart command via MPI" },
	{ 0x10,	"Automatic complete restart after battery-backed power on" },
	{ 0x13,	"Complete restart set at mode selector; last power on battery backed" },
	{ 0x14,	"Complete restart command via MPI; last power on battery backed" },
	{ 0x20,	"Automatic complete restart after non battery backed power on (with memory reset by system)" },
	{ 0x23,	"Complete restart set at mode selector; last power on unbattery backed" },
	{ 0x24,	"Complete restart command via MPI; last power on unbattery backed" },
	{ 0xa0,	"Automatic restart after battery backed power on according to parameter assignment" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0424_0000_anlinfo3 = -1;
static gint hf_s7comm_szl_0424_0000_anlinfo4 = -1;
static const value_string szl_0424_0000_anlinfo4_names[] = {
	{ 0x00,	"No startup type" },
	{ 0x01,	"Complete restart in multicomputing" },
	{ 0x03,	"Complete restart due to switch setting" },
	{ 0x04,	"Complete restart command via MPI" },
	{ 0x0a,	"Restart in multicomputing" },
	{ 0x0b,	"Restart set at mode selector" },
	{ 0x0c,	"Restart command via MPI" },
	{ 0x10,	"Automatic complete restart after battery-backed power on" },
	{ 0x13,	"Complete restart set at mode selector; last power on battery backed" },
	{ 0x14,	"Complete restart command via MPI; last power on battery backed" },
	{ 0x20,	"Automatic complete restart after non battery backed power on (with memory reset by system)" },
	{ 0x23,	"Complete restart set at mode selector; last power on unbattery backed" },
	{ 0x24,	"Complete restart command via MPI; last power on unbattery backed" },
	{ 0xa0,	"Automatic restart after battery backed power on according to parameter assignment" },
	{ 0,	NULL }
};
static gint hf_s7comm_szl_0424_0000_time = -1;


/*******************************************************************************************************
 *
 * Register SZL header fields
 * 
 *******************************************************************************************************/
void
s7comm_register_szl_types(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_userdata_szl_partial_list,
		{ "SZL partial list data",			"s7comm.param.userdata.szl_part_list", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "SZL partial list data", HFILL }},
		  /* SZL ID */
		{ &hf_s7comm_userdata_szl_id,
		{ "SZL-ID",			"s7comm.data.userdata.szl_id", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "SZL-ID (System Status List) Bits 15-12: Diagnostic type, Bits 11-8: Number of the partial list extract, Bits 7-0: Number of the partial list", HFILL }},

		{ &hf_s7comm_userdata_szl_id_type,
		{ "Diagnostic type",	"s7comm.data.userdata.szl_id.diag_type", FT_UINT16, BASE_HEX, VALS(szl_module_type_names), 0xf000,
      	  "Diagnostic type", HFILL }},
		{ &hf_s7comm_userdata_szl_id_partlist_ex,
		{ "Number of the partial list extract",	"s7comm.data.userdata.szl_id.partlist_ex", FT_UINT16, BASE_HEX, NULL, 0x0f00,
      	  "Number of the partial list extract", HFILL }},
		{ &hf_s7comm_userdata_szl_id_partlist_num,
		{ "Number of the partial list",	"s7comm.data.userdata.szl_id.partlist_num", FT_UINT16, BASE_HEX, VALS(szl_partial_list_names), 0x00ff,
      	  "Number of the partial list", HFILL }},


		  /* SZL index */
		{ &hf_s7comm_userdata_szl_index,
		{ "SZL-Index",		"s7comm.data.userdata.szl_index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "SZL-Index (System Status List)", HFILL }},
		{ &hf_s7comm_userdata_szl_tree,
		{ "SZL data tree",		"s7comm.data.userdata.szl_data_tree", FT_NONE,	BASE_NONE, NULL, 0x0,
      	  "SZL data tree", HFILL }},
		/* Raw and unknown data */
		{ &hf_s7comm_userdata_szl_data,
		{ "SZL data",		"s7comm.param.userdata.szl_data", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "SZL data", HFILL }},
	};

	/* Register Subtrees */
	static gint *ett[] = {
		&ett_s7comm_szl,
	};
	proto_register_subtree_array(ett, array_length (ett));

	proto_register_field_array(proto, hf, array_length(hf));

	/* Register the SZL fields */
	s7comm_szl_0013_0000_register(proto);

	s7comm_szl_0111_0001_register(proto);

	s7comm_szl_0131_0001_register(proto);
	s7comm_szl_0131_0002_register(proto);
	s7comm_szl_0131_0003_register(proto);
	s7comm_szl_0131_0004_register(proto);
	
	s7comm_szl_0132_0001_register(proto);
	s7comm_szl_0132_0002_register(proto);
	s7comm_szl_0132_0004_register(proto);

	s7comm_szl_0424_0000_register(proto);	
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions
 * 
 *******************************************************************************************************/
guint32
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
	proto_item *szl_item = NULL;	
	proto_tree *szl_item_tree = NULL;

	gboolean know_data = FALSE;
	gboolean szl_decoded = FALSE;

	switch (subfunc) {
		/*************************************************
		 * Read SZL
		 */
		case S7COMM_UD_SUBF_SZL_READ:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/				
				id = tvb_get_ntohs(tvb, offset);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id, tvb, offset, 2, FALSE);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_type, tvb, offset, 2, FALSE);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_partlist_ex, tvb, offset, 2, FALSE);
				proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_partlist_num, tvb, offset, 2, FALSE);
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
					proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_partlist_ex, tvb, offset, 2, FALSE);
					proto_tree_add_item(data_tree, hf_s7comm_userdata_szl_id_partlist_num, tvb, offset, 2, FALSE);
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
					 * of the length of data part. The remainding bytes will be print as raw bytes, because
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

					offset += 2;		
					/* Add a Data element for each partlist */
					if (len > 8) {	/* minimum length of a correct szl data part is 8 bytes */
						for (i = 1; i <= list_count; i++) {
							/* Add a separate tree for the SZL data */
							szl_item = proto_tree_add_item( data_tree, hf_s7comm_userdata_szl_tree, tvb, offset, list_len, FALSE );
							szl_item_tree = proto_item_add_subtree(szl_item, ett_s7comm_szl);
							proto_item_append_text(szl_item, " (list count no. %d)", i);
							
							szl_decoded = FALSE;
							/* lets try to decode some known szl-id and indexes */
							switch (id) {
								case 0x0013:
									if (index == 0x0000) {
										offset = s7comm_decode_szl_id_0013_idx_0000(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									}
									break;
								case 0x0111:
									if (index == 0x0001) {
										offset = s7comm_decode_szl_id_0111_idx_0001(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									}
									break;
								case 0x0131:
									if (index == 0x0001) {
										offset = s7comm_decode_szl_id_0131_idx_0001(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									} else if (index == 0x0002) {
										offset = s7comm_decode_szl_id_0131_idx_0002(tvb, szl_item_tree, list_len, list_count, offset);	
										szl_decoded = TRUE;
									} else if (index == 0x0003) {
										offset = s7comm_decode_szl_id_0131_idx_0003(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									} else if (index == 0x0004) {
										offset = s7comm_decode_szl_id_0131_idx_0004(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									}
									break;
								case 0x0132:
									if (index == 0x0001) {
										offset = s7comm_decode_szl_id_0132_idx_0001(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									} else if (index == 0x0002) {
										offset = s7comm_decode_szl_id_0132_idx_0002(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									} else if (index == 0x0004) {
										offset = s7comm_decode_szl_id_0132_idx_0004(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									}
									break;
								case 0x0424:
									if (index == 0x0000) {
										offset = s7comm_decode_szl_id_0424_idx_0000(tvb, szl_item_tree, list_len, list_count, offset);
										szl_decoded = TRUE;
									} 
									break;
								default:
									szl_decoded = FALSE;
									break;
							}

							if (szl_decoded == FALSE) {
								proto_tree_add_bytes(szl_item_tree, hf_s7comm_userdata_szl_partial_list, tvb, offset, list_len,
										tvb_get_ptr (tvb, offset, list_len));
								offset += list_len;
							}
							/* add raw bytes of data part when SZL response doesn't fit one PDU */
							if (tbytes > 0) {							
								proto_tree_add_bytes(szl_item_tree, hf_s7comm_userdata_szl_partial_list, tvb, offset, tbytes,
									tvb_get_ptr (tvb, offset, tbytes));
								offset += tbytes;
							}
						} // for
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
		proto_tree_add_bytes(data_tree, hf_s7comm_userdata_szl_data, tvb, offset, dlength - 4,
			tvb_get_ptr (tvb, offset, dlength - 4));
		offset += dlength;
	}
	return offset;
}
/*******************************************************************************************************
 *******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 4 -> SZL functions -> All known SZD-ID and Indices
 * 
 *******************************************************************************************************
 *******************************************************************************************************/

 /*******************************************************************************************************
 *
 * SZL-ID:	0x0013
 * Index:	0x0000
 * Content:
 *	If you read the partial list with SZL-ID W#16#xy13, you obtain information
 *	about the memory areas of the module.
 *
 *  The SZL-ID of the partial list extract
 *		W#16#0013: data records of all memory areas
 *		W#16#0113: data record for one memory area, You specify the memory area with the INDEX parameter.
 *		W#16#0F13: only partial list header information
 * 
 *******************************************************************************************************/
 /*----------------------------------------------------------------------------------------------------*/
void
s7comm_szl_0013_0000_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0013_0000_index,
		{ "Index",			"s7comm.szl.0013.0000.index", FT_UINT16, BASE_HEX, VALS(szl_memory_area_names), 0x0,
		  "Index of an identification data record", HFILL }},

		{ &hf_s7comm_szl_0013_0000_code,
		{ "Code (Memory type)",			"s7comm.szl.0013.0000.code", FT_UINT16, BASE_HEX, VALS(szl_memory_type_names), 0x0,
		  "Code (Memory type)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_size,
		{ "Size (Total size of the selected memory, total of area 1 and area 2)",			"s7comm.szl.0013.0000.size", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Size (Total size of the selected memory, total of area 1 and area 2)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode,
		{ "Mode (Logical mode of the memory)",			"s7comm.szl.0013.0000.mode", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Mode (Logical mode of the memory)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode_0,
		{ "Volatile memory area",			"s7comm.szl.0013.0000.mode", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Volatile memory area", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode_1,
		{ "Non-volatile memory area",			"s7comm.szl.0013.0000.mode", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Non-volatile memory area", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode_2,
		{ "Mixed memory area",		"s7comm.szl.0013.0000.mode", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Mixed memory area", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode_3,
		{ "Code and data separate (for work memory)",			"s7comm.szl.0013.0000.mode", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Code and data separate (for work memory)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_mode_4,
		{ "Code and data together (for work memory)",			"s7comm.szl.0013.0000.mode", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Code and data together (for work memory)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_granu,
		{ "Granu",			"s7comm.szl.0013.0000.granu", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Granu (Always has the value 0)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_ber1,
		{ "ber1 (Size of the volatile memory area in bytes)",			"s7comm.szl.0013.0000.ber1", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "ber1 (Size of the volatile memory area in bytes)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_belegt1,
		{ "belegt1 (Size of the volatile memory area being used)",			"s7comm.szl.0013.0000.belegt1", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "belegt1 (Size of the volatile memory area being used)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_block1,
		{ "block1 (Largest free block in the volatile memory area)",			"s7comm.szl.0013.0000.block1", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "block1 (Largest free block in the volatile memory area)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_ber2,
		{ "ber2 (Size of the non-volatile memory area in bytes)",			"s7comm.szl.0013.0000.ber2", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "ber2 (Size of the non-volatile memory area in bytes)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_belegt2,
		{ "belegt2 (Size of the non-volatile memory area being used)",			"s7comm.szl.0013.0000.belegt2", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "belegt2 (Size of the non-volatile memory area being used)", HFILL }},

		{ &hf_s7comm_szl_0013_0000_block2,
		{ "block2 (Largest free block in the non-volatile memory area)",			"s7comm.szl.0013.0000.block2", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "block2 (Largest free block in the non-volatile memory area)", HFILL }},

	};
	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0013_idx_0000(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_code, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_size, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_mode, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_granu, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_ber1, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_belegt1, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_block1, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_ber2, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_belegt2, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0013_0000_block2, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}


 /*******************************************************************************************************
 *
 * SZL-ID:	0x0111
 * Index:	0x0001
 * Content:
 *	If you read the system status list with SZL-ID W#16#xy11, you obtain the
 *	module identification of the module.
 * 
 *******************************************************************************************************/
void
s7comm_szl_0111_0001_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0111_0001_index,
		{ "Index",			"s7comm.szl.0111.0001.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Index of an identification data record", HFILL }},

		{ &hf_s7comm_szl_0111_0001_mlfb,
		{ "MlfB (Order number of the module)",			"s7comm.szl.0111.0001.anz", FT_STRING, BASE_NONE, NULL, 0x0,
		  "MlfB (Order number of the module)", HFILL }},

		{ &hf_s7comm_szl_0111_0001_bgtyp,
		{ "BGTyp (Module type ID)",			"s7comm.szl.0111.0001.bgtyp", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "BGTyp (Module type ID)", HFILL }},

		{ &hf_s7comm_szl_0111_0001_ausbg,
		{ "Ausbg (Version of the module or release of the operating system)",			"s7comm.szl.0111.0001.ausbg", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Ausbg (Version of the module or release of the operating system)", HFILL }},

		{ &hf_s7comm_szl_0111_0001_ausbe,
		{ "Ausbe (Release of the PG description file)",			"s7comm.szl.0111.0001.ausbe", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Ausbe (Release of the PG description file)", HFILL }},
	};
	proto_register_field_array(proto, hf, array_length(hf));
}
 /*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0111_idx_0001(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0111_0001_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0111_0001_mlfb, tvb, offset, 20, FALSE);
	offset += 20;
	proto_tree_add_item(tree, hf_s7comm_szl_0111_0001_bgtyp, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0111_0001_ausbg, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0111_0001_ausbe, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}
 /*******************************************************************************************************
 *
 * SZL-ID:	0x0131
 * Index:	0x0001
 * Content:
 *	The partial list extract with SZL-ID W#16#0131 and the index W#16#0001
 *	contains general data about the communication of a communication unit.
 * 
 *******************************************************************************************************/
void
s7comm_szl_0131_0001_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0131_0001_index,
		{ "Index",					"s7comm.szl.0131.0001.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0001: Index for general communication data", HFILL }},
		{ &hf_s7comm_szl_0131_0001_pdu,
		{ "pdu (Maximum PDU size in bytes)",			"s7comm.szl.0131.0001.pdu", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Maximum PDU size in bytes", HFILL }},
		{ &hf_s7comm_szl_0131_0001_anz,
		{ "anz (Maximum number of communication connections)",			"s7comm.szl.0131.0001.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Maximum number of communication connections", HFILL }},
		{ &hf_s7comm_szl_0131_0001_mpi_bps,
		{ "mpi_bps (Maximum data rate of the MPI in hexadecimal format)  ",			"s7comm.szl.0131.0001.mpi_bps", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Maximum data rate of the MPI in hexadecimal format, Example: 0x2DC6C corresponds to 187500 bps", HFILL }},
		{ &hf_s7comm_szl_0131_0001_kbus_bps,
		{ "mkbus_bps (Maximum data rate of the communication bus)",		"s7comm.szl.0131.0001.kbus_bps", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Maximum data rate of the communication bus", HFILL }},
		{ &hf_s7comm_szl_0131_0001_res,
		{ "res (Reserved)",			"s7comm.szl.0131.0001.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Reserved", HFILL }}
	};

	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0131_idx_0001(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_pdu, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_anz, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_mpi_bps, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_kbus_bps, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0001_res, tvb, offset, 26, FALSE);
	offset += 26;	
	return offset;
}
 /*******************************************************************************************************
 *
 * SZL-ID:	0x0131
 * Index:	0x0002
 * Content:
 *	The partial list extract with SZL-ID W#16#0131 and the index W#16#0002
 *	contains information about the test and installation constants of the module.
 * 
 *******************************************************************************************************/

void
s7comm_szl_0131_0002_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0131_0002_index,
		{ "Index     ",			"s7comm.szl.0131.0002.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0002: test and installation", HFILL }},

		/* funkt_0 */
		{ &hf_s7comm_szl_0131_0002_funkt_0,
		{ "funkt_0   ",			"s7comm.szl.0131.0002.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_0,
		{ "Reserved",			"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_1,
		{ "Block status",			"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Block status", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_2,
		{ "Variable status",		"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Variable status", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_3,
		{ "Output ISTACK",			"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Output ISTACK", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_4,
		{ "Output BSTACK",			"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Output BSTACK", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_5,
		{ "Output LSTACK",			"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Output LSTACK", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_6,
		{ "Time measurement from ... to ...",		"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Time measurement from ... to ...", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_0_7,
		{ "Force selection",		"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Force selection", HFILL }},

		/* funkt_1 */
		{ &hf_s7comm_szl_0131_0002_funkt_1,
		{ "funkt_1   ",			"s7comm.szl.0131.0002.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_0,
		{ "Modify variable",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Modify variable", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_1,
		{ "Force",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Force", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_2,
		{ "Breakpoint",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Breakpoint", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_3,
		{ "Exit HOLD",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: OExit HOLD", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_4,
		{ "Memory reset",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Memory reset", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_5,
		{ "Disable job",			"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Disable job", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_6,
		{ "Enable job",		"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Enable job", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_1_7,
		{ "Delete job",		"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Delete job", HFILL }},

		/* funkt_2 */		
		{ &hf_s7comm_szl_0131_0002_funkt_2,
		{ "funkt_2   ",			"s7comm.szl.0131.0002.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_0,
		{ "Read job list",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Read job list", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_1,
		{ "Read job",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Read job", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_2,
		{ "Replace job",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Replace job", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_3,
		{ "Reserved",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_4,
		{ "Reserved",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_5,
		{ "Reserved",			"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_6,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_funkt_2_7,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Reserved", HFILL }},

		/* funkt_3 */
		{ &hf_s7comm_szl_0131_0002_funkt_3,
		{ "funkt_3 (Reserved)",			"s7comm.szl.0131.0002.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
		/* funkt_4 */
		{ &hf_s7comm_szl_0131_0002_funkt_4,
		{ "funkt_4 (Reserved)",			"s7comm.szl.0131.0002.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},
		/* funkt_5 */
		{ &hf_s7comm_szl_0131_0002_funkt_5,
		{ "funkt_5 (Reserved)",			"s7comm.szl.0131.0002.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Permitted TIS (Test and Installation) functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_aseg,
		{ "aseg",			"s7comm.szl.0131.0002.aseg", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "aseg (Non-relevant system data)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_eseg,
		{ "eseg",			"s7comm.szl.0131.0002.eseg", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "eseg (Non-relevant system data)", HFILL }},

		/* trgereig_0 */
		{ &hf_s7comm_szl_0131_0002_trgereig_0,
		{ "trgereig_0 (Permitted trigger events)",			"s7comm.szl.0131.0002.trgereig_0", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "trgereig_0 (Permitted trigger events)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_0,
		{ "Immediately",			"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: immediately", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_1,
		{ "System trigger",			"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: System trigger", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_2,
		{ "System checkpoint main cycle start",	"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: System checkpoint main cycle start", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_3,
		{ "System checkpoint main cycle end",	"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: System checkpoint main cycle end", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_4,
		{ "Mode transition RUN-STOP",			"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Mode transition RUN-STOP", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_5,
		{ "After code address",			"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: After code address", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_6,
		{ "Code address area",		"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Code address area", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_0_7,
		{ "Data address",		"s7comm.szl.0131.0002.trgereig_0", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Data Address", HFILL }},

		/* trgereig_1 */
		{ &hf_s7comm_szl_0131_0002_trgereig_1,
		{ "trgereig_1 (Permitted trigger events)",			"s7comm.szl.0131.0002.trgereig_1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "trgereig_1 (Permitted trigger events)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_0,
		{ "Data address area",			"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Data address area", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_1,
		{ "Local data address",			"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Local data address", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_2,
		{ "Local data address area",	"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Local data address area", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_3,
		{ "Range trigger",	"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Range trigger", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_4,
		{ "Before code address",			"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Before code address", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_5,
		{ "Reserved",			"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_6,
		{ "Reserved",		"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgereig_1_7,
		{ "Reserved",		"s7comm.szl.0131.0002.trgereig_1", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Reserved", HFILL }},
		/* trgereig_2 */
		{ &hf_s7comm_szl_0131_0002_trgereig_2,
		{ "trgereig_2 (Permitted trigger events, reserved)",			"s7comm.szl.0131.0002.trgereig_2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "trgereig_2 (Permitted trigger events, reserved)", HFILL }},

		{ &hf_s7comm_szl_0131_0002_trgbed,
		{ "trgbed (System data with no relevance)",			"s7comm.szl.0131.0002.trgbed", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "trgbed (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_pfad,
		{ "pfad (System data with no relevance)",			"s7comm.szl.0131.0002.pfad", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "pfad (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_tiefe,
		{ "tiefe (System data with no relevance)",			"s7comm.szl.0131.0002.tiefe", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "tiefe (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_systrig,
		{ "systrig (System data with no relevance)",			"s7comm.szl.0131.0002.systrig", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "systrig (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_erg_par,
		{ "erg par (System data with no relevance)",			"s7comm.szl.0131.0002.erg_par", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "erg par (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_erg_pat_1,
		{ "erg pat 1 (System data with no relevance)",			"s7comm.szl.0131.0002.erg_pat_1", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "erg pat 1 (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_erg_pat_2,
		{ "erg pat 2 (System data with no relevance)",			"s7comm.szl.0131.0002.erg_pat_2", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "erg pat 2 (System data with no relevance)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_force,
		{ "force (Number of modifiable Variables)",			"s7comm.szl.0131.0002.force", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "force (Number of modifiable Variables)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_time,
		{ "time",			"s7comm.szl.0131.0002.time", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "time (Upper time limit run-time meas, Format: bits 0 to 11 contain the time value (0 to 4K-1); bits 12 to 15 contain the time base: 0H= 10^-10s, 1H = 10^-9s,...,AH = 100s, ... FH = 105s)", HFILL }},
		{ &hf_s7comm_szl_0131_0002_res,
		{ "res (Reserved)",			"s7comm.szl.0131.0002.res", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "res (Reserved)", HFILL }},

	};

	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0131_idx_0002(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_0_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_1_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_2_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_3, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_4, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_funkt_5, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_aseg, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_eseg, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_0_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_1_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgereig_2, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_trgbed, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_pfad, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_tiefe, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_systrig, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_par, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_pat_1, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_erg_pat_2, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_force, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_time, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0002_res, tvb, offset, 4, FALSE);
	offset += 4;
	
	return offset;
}
 /*******************************************************************************************************
 *
 * SZL-ID:	0x0131
 * Index:	0x0003
 * Content:
 *	The partial list extract with SZL-ID W#16#0131 and the index W#16#0003
 *	contains information about the communication parameters of the module for
 *	connection to a unit for operator interface functions.
 * 
 *******************************************************************************************************/

void
s7comm_szl_0131_0003_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0131_0003_index,
		{ "Index     ",			"s7comm.szl.0131.0003.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0003: Index for operator interface functions", HFILL }},

		/* funkt_0 */
		{ &hf_s7comm_szl_0131_0003_funkt_0,
		{ "funkt_0   ",			"s7comm.szl.0131.0003.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bits indicating the available functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_0,
		{ "Read once",			"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Read once", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_1,
		{ "Write once",			"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Write once", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_2,
		{ "Initialize cyclic reading (start implicitly)",		"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Initialize cyclic reading (start implicitly)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_3,
		{ "Initialize cyclic reading (start explicitly)",			"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Initialize cyclic reading (start explicitly)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_4,
		{ "Start cyclic reading",			"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Start cyclic reading", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_5,
		{ "Stop cyclic reading",			"s7comm.szl.0131.0003.funkt_0", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Stop cyclic reading", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_6,
		{ "Clear cyclic reading",		"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Clear cyclic reading", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_0_7,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_0", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Reserved", HFILL }},

		/* funkt_1 */
		{ &hf_s7comm_szl_0131_0003_funkt_1,
		{ "funkt_1   ",			"s7comm.szl.0131.0003.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bits indicating the available functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_0,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_1,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_2,
		{ "Reserved",		"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_3,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_4,
		{ "Peripheral I/Os",			"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Peripheral I/Os", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_5,
		{ "Inputs",			"s7comm.szl.0131.0003.funkt_1", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Inputs", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_6,
		{ "Outputs",		"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Outputs", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_1_7,
		{ "Bit memory",		"s7comm.szl.0131.0002.funkt_1", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Bit memory", HFILL }},

		/* funkt_2 */
		{ &hf_s7comm_szl_0131_0003_funkt_2,
		{ "funkt_2   ",			"s7comm.szl.0131.0003.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bits indicating the available functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_0,
		{ "User DB",			"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: User DB", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_1,
		{ "Data record",			"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Data record", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_2,
		{ "Reserved",		"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_3,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_4,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_5,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_2", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_6,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_2_7,
		{ "S7 counter",		"s7comm.szl.0131.0002.funkt_2", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: S7 counter", HFILL }},

		/* funkt_3 */
		{ &hf_s7comm_szl_0131_0003_funkt_3,
		{ "funkt_3   ",			"s7comm.szl.0131.0003.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bits indicating the available functions (bit = 1: function exists)", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_0,
		{ "S7 timer",			"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: S7 timer", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_1,
		{ "IEC counter",			"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: IEC counter", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_2,
		{ "IEC timer",		"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: IEC timer", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_3,
		{ "High speed counter",			"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: High speed counter", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_4,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_5,
		{ "Reserved",			"s7comm.szl.0131.0003.funkt_3", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_6,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_3", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_funkt_3_7,
		{ "Reserved",		"s7comm.szl.0131.0002.funkt_3", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0003_data,
		{ "data (Maximum size of consistently readable data)",			"s7comm.szl.0131.0003.data", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "data (Maximum size of consistently readable data)", HFILL }},
		{ &hf_s7comm_szl_0131_0003_anz,
		{ "anz (Maximum number of cyclic read jobs)",			"s7comm.szl.0131.0003.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "anz (Maximum number of cyclic read jobs)", HFILL }},
		{ &hf_s7comm_szl_0131_0003_per_min,
		{ "per min (Minimum period for cyclic read jobs (n x 100 ms)",			"s7comm.szl.0131.0003.per_min", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "per min (Minimum period for cyclic read jobs (n x 100 ms)", HFILL }},
		{ &hf_s7comm_szl_0131_0003_per_max,
		{ "per man (Maximum period for cyclic read jobs (n x 100 ms)",			"s7comm.szl.0131.0003.per_max", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "per man (Maximum period for cyclic read jobs (n x 100 ms)", HFILL }},
		{ &hf_s7comm_szl_0131_0003_res,
		{ "res (Reserved)",			"s7comm.szl.0131.0003.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},
	};

	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0131_idx_0003(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_0_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_1_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_2_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_funkt_3_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_data, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_anz, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_per_min, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_per_max, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0003_res, tvb, offset, 26, FALSE);
	offset += 26;
	
	return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:	0x0131
 * Index:	0x0004
 * Content:
 *	The partial list extract with SZL-ID W#16#0131 and the index W#16#0004
 *	contains information about the object management system (OMS) of the
 *	module.
 * 
 *******************************************************************************************************/

void
s7comm_szl_0131_0004_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0131_0004_index,
		{ "Index     ",			"s7comm.szl.0131.0004.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0004 Index for OMS", HFILL }},

		/* funkt_0 */
		{ &hf_s7comm_szl_0131_0004_funkt_0,
		{ "funkt_0   ",			"s7comm.szl.0131.0004.funkt_0", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_0,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_1,
		{ "Directory (hierarchy 1)",			"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Directory (hierarchy 1)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_2,
		{ "Directory (hierarchy 2)",		"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Directory (hierarchy 2)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_3,
		{ "Directory (hierarchy 3)",			"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Directory (hierarchy 3)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_4,
		{ "Copy",			"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Copy", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_5,
		{ "Chain (list)",			"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Chain (list)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_6,
		{ "Chain (all copied)",		"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Chain (all copied)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_0_7,
		{ "Delete (list)",		"s7comm.szl.0131.0004.funkt_0", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Delete (list)", HFILL }},

		/* funkt_1 */
		{ &hf_s7comm_szl_0131_0004_funkt_1,
		{ "funkt_1   ",			"s7comm.szl.0131.0004.funkt_1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_0,
		{ "Upload on PG",			"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Upload on PG", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_1,
		{ "Assign parameters when chaining",			"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Assign parameters when chaining", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_2,
		{ "LOAD function when exchanging data with CFBs",		"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: LOAD function when exchanging data with CFBs", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_3,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_4,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_5,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_6,
		{ "Reserved",		"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_1_7,
		{ "Delete *.*",		"s7comm.szl.0131.0004.funkt_1", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Delete *.*", HFILL }},

		/* funkt_2 */
		{ &hf_s7comm_szl_0131_0004_funkt_2,
		{ "funkt_2   ",			"s7comm.szl.0131.0004.funkt_2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_0,
		{ "Load user program (RAM)",			"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Load user program (RAM)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_1,
		{ "Load user program (EPROM)",			"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Load user program (EPROM)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_2,
		{ "Save user program (RAM)",		"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Save user program (RAM)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_3,
		{ "Save user program (EPROM)",			"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Save user program (EPROM)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_4,
		{ "Save user program (all)",			"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Save user program (all)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_5,
		{ "Compress (external)",			"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Compress (external)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_6,
		{ "Firmware update (using communication)",		"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Firmware update (using communication)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_2_7,
		{ "Set RAM memory mode",		"s7comm.szl.0131.0004.funkt_2", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Set RAM memory mode", HFILL }},

		/* funkt_3 */
		{ &hf_s7comm_szl_0131_0004_funkt_3,
		{ "funkt_3   ",			"s7comm.szl.0131.0004.funkt_3", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_0,
		{ "Set EPROM memory mode",			"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Set EPROM memory mode", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_1,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_2,
		{ "Reserved",		"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_3,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_4,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_5,
		{ "Reserved",			"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_6,
		{ "Assign parameters to newly plugged in modules",		"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Assign parameters to newly plugged in modules", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_3_7,
		{ "Assign parameters when evaluating memory card",		"s7comm.szl.0131.0004.funkt_3", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Assign parameters when evaluating memory card", HFILL }},

		/* funkt_4 */
		{ &hf_s7comm_szl_0131_0004_funkt_4,
		{ "funkt_4   ",			"s7comm.szl.0131.0004.funkt_4", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_0,
		{ "Assign parameters when loading user program",			"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x01,
		  "Bit 0: Assign parameters when loading user program", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_1,
		{ "Assign parameters in complete restart",			"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x02,
		  "Bit 1: Assign parameters in complete restart", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_2,
		{ "Assign parameters in restart",		"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x04,
		  "Bit 2: Assign parameters in restart", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_3,
		{ "Compress (SFC25 COMPRESS)",			"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x08,
		  "Bit 3: Compress (SFC25 COMPRESS)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_4,
		{ "Evaluate memory card after switch setting",			"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x10,
		  "Bit 4: Evaluate memory card after switch setting", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_5,
		{ "Firmware update using memory card",			"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x20,
		  "Bit 5: Firmware update using memory card", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_6,
		{ "Reserved",		"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x40,
		  "Bit 6: Reserved", HFILL }},

		{ &hf_s7comm_szl_0131_0004_funkt_4_7,
		{ "Reserved",		"s7comm.szl.0131.0004.funkt_4", FT_BOOLEAN, 8, NULL, 0x80,
		  "Bit 7: Reserved", HFILL }},

		/* funkt_5 */
		{ &hf_s7comm_szl_0131_0004_funkt_5,
		{ "funkt_5 (Reserved)",			"s7comm.szl.0131.0004.funkt_5", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
		/* funkt_6 */
		{ &hf_s7comm_szl_0131_0004_funkt_6,
		{ "funkt_6 (Reserved)",			"s7comm.szl.0131.0004.funkt_6", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},
		/* funkt_7 */
		{ &hf_s7comm_szl_0131_0004_funkt_7,
		{ "funkt_7 (Reserved)",			"s7comm.szl.0131.0004.funkt_7", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Available object management system functions: (Bit = 1: functions available on the CPU)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_kop,
		{ "kop (Maximum number of copied blocks)",			"s7comm.szl.0131.0004.kop", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "kop (Maximum number of copied blocks)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_del,
		{ "del (Maximum number of uninterruptable, deletable blocks)",			"s7comm.szl.0131.0004.del", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "del (Maximum number of uninterruptable, deletable blocks)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_kett,
		{ "kett (Maximum number of blocks chained in one job)",			"s7comm.szl.0131.0004.kett", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "kett (Maximum number of blocks chained in one job)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_hoch,
		{ "hoch (Maximum number of simultaneous upload procedures)",			"s7comm.szl.0131.0004.hoch", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "hoch (Maximum number of simultaneous upload procedures)", HFILL }},

		{ &hf_s7comm_szl_0131_0004_ver,
		{ "ver (Maximum size (in bytes) of shiftable blocks in RUN)",			"s7comm.szl.0131.0004.hoch", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "ver (Maximum size (in bytes) of shiftable blocks in RUN) With an S7-300, this size refers to the entire block,with the S7-400, it refers to the part of the block relevant to running the program.", HFILL }},

		{ &hf_s7comm_szl_0131_0004_res,
		{ "res (Reserved)",			"s7comm.szl.0131.0004.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},
	};
	proto_register_field_array(proto, hf, array_length(hf));
}

/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0131_idx_0004(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_0_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_1_7, tvb, offset, 1, FALSE);
	offset += 1;	
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_2_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_3_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_0, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_1, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_2, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_3, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_4, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_5, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_6, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_4_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_5, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_6, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_funkt_7, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_kop, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_del, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_kett, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_hoch, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_ver, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0131_0004_res, tvb, offset, 25, FALSE);
	offset += 25;
	
	return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:	0x0132
 * Index:	0x0001
 * Content:
 *	The partial list extract with SZL-ID W#16#0132 and index W#16#0001
 *  contains general communication status data.
 * 
 *******************************************************************************************************/
void
s7comm_szl_0132_0001_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0132_0001_index,
		{ "Index",			"s7comm.szl.0132.0001.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0001: General status data for communication", HFILL }},

		{ &hf_s7comm_szl_0132_0001_res_pg,
		{ "res pg (Guaranteed number of PG connections)",		"s7comm.szl.0132.0001.res_pg", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "res pg (Guaranteed number of PG connections)", HFILL }},

		{ &hf_s7comm_szl_0132_0001_res_os,
		{ "res os (Guaranteed number of OS connections)",		"s7comm.szl.0132.0001.res_os", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "res os (Guaranteed number of OS connections)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_u_pg,
		{ "u pg (Current number of PG connections)",			"s7comm.szl.0132.0001.u_pg", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "u pg (Current number of PG connections)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_u_os,
		{ "u os (Current number of OS connections)",			"s7comm.szl.0132.0001.u_os", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "u os (Current number of OS connections)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_proj,
		{ "proj (Current number of configured connections)",	"s7comm.szl.0132.0001.proj", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "proj (Current number of configured connections)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_auf,
		{ "auf (Current number of connections established by proj)",	"s7comm.szl.0132.0001.auf", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "auf (Current number of connections established by proj)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_free,
		{ "free (Number of free connections)",	"s7comm.szl.0132.0001.free", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "free (Number of free connections)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_used,
		{ "used (Number of free connections used)",	"s7comm.szl.0132.0001.used", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "used (Number of free connections used)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_last,
		{ "last (Maximum selected communication load of the CPU in %)",	"s7comm.szl.0132.0001.last", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "last (Maximum selected communication load of the CPU in %)", HFILL }},
		  
		{ &hf_s7comm_szl_0132_0001_res,
		{ "res (Reserved)",	"s7comm.szl.0132.0001.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},
	};
	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0132_idx_0001(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res_pg, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res_os, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_u_pg, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_u_os, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_proj, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_auf, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_free, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_used, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_last, tvb, offset, 2, FALSE);
	offset += 2;	
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0001_res, tvb, offset, 10, FALSE);
	offset += 10;

	return offset;
}
/*******************************************************************************************************
 *
 * SZL-ID:	0x0132
 * Index:	0x0002
 * Content:
 *	The partial list extract with SZL-ID W#16#0132 and the index W#16#0002
 *	contains information about the test and installation function status of the module.
 * 
 *******************************************************************************************************/
void
s7comm_szl_0132_0002_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0132_0002_index,
		{ "Index",			"s7comm.szl.0132.0002.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0002: Test and installation status", HFILL }},

		{ &hf_s7comm_szl_0132_0002_anz,
		{ "anz (Number of initialized test and installation jobs)",			"s7comm.szl.0132.0002.anz", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "anz (Number of initialized test and installation jobs)", HFILL }},

		{ &hf_s7comm_szl_0132_0002_res,
		{ "res (Reserved)",			"s7comm.szl.0132.0002.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},
	};
	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0132_idx_0002(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_anz, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0002_res, tvb, offset, 36, FALSE);
	offset += 36;

	return offset;
}
/*******************************************************************************************************
 *
 * SZL-ID:	0x0132
 * Index:	0x0004
 * Content:
 *	The partial list extract with SZL-ID W#16#0132 and the index W#16#0004
 *	contains information about the protection level of the module.
 * 
 *******************************************************************************************************/

void
s7comm_szl_0132_0004_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0132_0004_index,
		{ "Index",			"s7comm.szl.0132.0004.index", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "W#16#0004 Protection status data", HFILL }},

		{ &hf_s7comm_szl_0132_0004_key,
		{ "key (Protection level for the key switch, possible values: 1,2 or 3)",			"s7comm.szl.0132.0004.key", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "key (Protection level for the key switch, possible values: 1,2 or 3)", HFILL }},

		{ &hf_s7comm_szl_0132_0004_param,
		{ "param (Assigned protection level (possible values: 0, 1, 2 or 3)",			"s7comm.szl.0132.0004.param", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "param (Assigned protection level (possible values: 0, 1, 2 or 3;0 means: no password assigned, assigned protection level is not valid)", HFILL }},

		{ &hf_s7comm_szl_0132_0004_real,
		{ "real (Valid protection level of the CPU, possible values: 1, 2 or 3)",			"s7comm.szl.0132.0004.real", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "real (Valid protection level of the CPU, possible values: 1, 2 or 3)", HFILL }},

		{ &hf_s7comm_szl_0132_0004_bart_sch,
		{ "bart_sch (Position of the mode switch)",			"s7comm.szl.0132.0004.bart_sch", FT_UINT16, BASE_DEC, VALS(szl_bart_sch_names), 0x0,
		  "bart_sch (Position of the mode switch)", HFILL }},

		{ &hf_s7comm_szl_0132_0004_crst_wrst,
		{ "crst_wrst (Setting of the CRST/WRST switch)",			"s7comm.szl.0132.0004.crst_wrst", FT_UINT16, BASE_DEC, VALS(szl_crst_wrst_names), 0x0,
		  "crst_wrst (Setting of the CRST/WRST switch)", HFILL }},

		{ &hf_s7comm_szl_0132_0004_res,
		{ "res (Reserved)",			"s7comm.szl.0132.0004.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},
	};
	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0132_idx_0004(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_index, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_key, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_param, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_real, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_bart_sch, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_crst_wrst, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0132_0004_res, tvb, offset, 28, FALSE);
	offset += 28;

	return offset;
}

/*******************************************************************************************************
 *
 * SZL-ID:	0x0424
 * Index:	0x0000
 * Content:
 *	If you read the system status list with SZL-ID W#16#xy24, you obtain
 *  information about the modes of the module.
 * 
 *******************************************************************************************************/
void
s7comm_szl_0424_0000_register(int proto)
{
	static hf_register_info hf[] = {
		/*** SZL functions ***/
		{ &hf_s7comm_szl_0424_0000_ereig,
		{ "ereig",			"s7comm.szl.0424.0000.ereig", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Event ID", HFILL }},

		{ &hf_s7comm_szl_0424_0000_ae,
		{ "ae",			"s7comm.szl.0424.0000.ereig", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "ae (B#16#FF)", HFILL }},

		{ &hf_s7comm_szl_0424_0000_bzu_id,
		{ "bzu-id",			"s7comm.szl.0424.0000.bzu_id", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "bzu-id (ID of the mode change divided into 4 bits, Bit 0 to 3: Requested mode, Bit 4 to 7: Previous mode", HFILL }},

		{ &hf_s7comm_szl_0424_0000_res,
		{ "res (Reserved)",			"s7comm.szl.0424.0000.res", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "res (Reserved)", HFILL }},

		{ &hf_s7comm_szl_0424_0000_anlinfo1,
		{ "anlinfo1",			"s7comm.szl.0424.0000.anlinfo1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "anlinfo1", HFILL }},

		{ &hf_s7comm_szl_0424_0000_anlinfo2,
		{ "anlinfo2",			"s7comm.szl.0424.0000.anlinfo2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "anlinfo2", HFILL }},

		{ &hf_s7comm_szl_0424_0000_anlinfo3,
		{ "anlinfo3",			"s7comm.szl.0424.0000.anlinfo3", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "anlinfo3", HFILL }},

		{ &hf_s7comm_szl_0424_0000_anlinfo4,
		{ "anlinfo4",			"s7comm.szl.0424.0000.anlinfo4", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "anlinfo4", HFILL }},

		{ &hf_s7comm_szl_0424_0000_time,
		{ "time",			"s7comm.szl.0424.0000.time", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "time (Time stamp)", HFILL }},

	};
	proto_register_field_array(proto, hf, array_length(hf));
}
/*----------------------------------------------------------------------------------------------------*/
guint32
s7comm_decode_szl_id_0424_idx_0000(tvbuff_t *tvb,
									proto_tree *tree, 
									guint16 szl_partlist_len,
									guint16 szl_partlist_count,									
									guint32 offset )
{
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_ereig, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_ae, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_bzu_id, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_res, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo1, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo2, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo3, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_anlinfo4, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_s7comm_szl_0424_0000_time, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}
