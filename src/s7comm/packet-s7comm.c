/* packet-s7comm.c
 *
 * Author:		Thomas Wiens, 2011 (th.wiens@gmx.de)
 * Version:		0.0.3
 * Description:	Wireshark dissector for S7-Communication
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

#include "packet-s7comm.h"

#include "s7comm_szl_ids.h"
#include "s7comm_helper.h"

#define PROTO_TAG_S7COMM				"S7COMM"

/* Min. telegram length for heuristic check */
#define S7COMM_MIN_TELEGRAM_LENGTH		10

/* Protocol identifier */
#define S7COMM_PROT_ID					0x32

/* Wireshark ID of the S7COMM protocol */
static int proto_s7comm = -1;

/* Forward declaration */
static gboolean dissect_s7comm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

/**************************************************************************
 * Function tree of the dissect process

dissect_s7comm()
    +
    +-------s7comm_decode_req_resp()
    +        +        +
    +     response	request
    +        +        +
    +        +        +------ s7comm_decode_param_item()
    +        +        +       s7comm_decode_response_read_data()
    +        +        +
    +        +        +------ s7comm_decode_pdu_setup_communication()
    +        +        +------ s7comm_decode_plc_controls_param_hex1x()
    +        +        +------ s7comm_decode_plc_controls_param_hex28()
    +        +        +------ s7comm_decode_plc_controls_param_hex29()
    +        +
    +        +------ s7comm_decode_response_read_data()
    +        +------ s7comm_decode_response_write_data()
    +        +------ s7comm_decode_pdu_setup_communication()
    +
    +
    +-------s7comm_decode_ud()
             +
             +------	s7comm_decode_ud_prog_subfunc()
             +                  +
             +                  +------- s7comm_decode_ud_prog_vartab_req_item()
             +                  +------- s7comm_decode_ud_prog_vartab_res_item()
			 +                  +------- s7comm_decode_ud_prog_reqdiagdata()
             +
             +------	s7comm_decode_ud_cyclic_subfunc()
             +------	s7comm_decode_ud_block_subfunc()
             +------	s7comm_decode_ud_szl_subfunc()
             +------	s7comm_decode_ud_security_subfunc()
             +------	s7comm_decode_ud_time_subfunc()

 **************************************************************************/



/**************************************************************************
 * PDU types 
 */
#define S7COMM_ROSCTR_JOB			0x01
#define S7COMM_ROSCTR_ACK			0x02
#define S7COMM_ROSCTR_ACK_DATA		0x03
#define S7COMM_ROSCTR_USERDATA		0x07

static const value_string rosctr_names[] = {
	{ S7COMM_ROSCTR_JOB,				"Job" },	/* Request: job with acknowledgement */
	{ S7COMM_ROSCTR_ACK,				"Ack" },	/* acknowledgement without additional field */ 
	{ S7COMM_ROSCTR_ACK_DATA,			"Ack_Data" }, /* Response: acknowledgement with additional field */
	{ S7COMM_ROSCTR_USERDATA,			"Userdata" },
	{ 0,							 	NULL }
};
/**************************************************************************
 * Error classes in header
 */
#define S7COMM_ERRCLS_NONE				0x00
#define S7COMM_ERRCLS_APPREL			0x81
#define S7COMM_ERRCLS_OBJDEF			0x82
#define S7COMM_ERRCLS_RESSOURCE			0x83
#define S7COMM_ERRCLS_SERVICE			0x84
#define S7COMM_ERRCLS_SUPPLIES			0x85
#define S7COMM_ERRCLS_ACCESS			0x87

static const value_string errcls_names[] = {
	{ S7COMM_ERRCLS_NONE,				"No error" },
	{ S7COMM_ERRCLS_APPREL	,			"Application relationship" },
	{ S7COMM_ERRCLS_OBJDEF,				"Object definition" },
	{ S7COMM_ERRCLS_RESSOURCE,			"No ressources available" },
	{ S7COMM_ERRCLS_SERVICE,			"Error on service processing" },
	{ S7COMM_ERRCLS_SUPPLIES,			"Error on supplies" },
	{ S7COMM_ERRCLS_ACCESS,				"Access error" },
	{ 0,							 	NULL }
};
/**************************************************************************
 * Function codes in parameter part
 */
#define S7COMM_SERV_CPU					0x00
#define S7COMM_SERV_SETUPCOMM			0xF0
#define S7COMM_SERV_READVAR				0x04
#define S7COMM_SERV_WRITEVAR			0x05

#define S7COMM_FUNCREQUESTDOWNLOAD		0x1A
#define S7COMM_FUNCDOWNLOADBLOCK		0x1B
#define S7COMM_FUNCDOWNLOADENDED		0x1C
#define S7COMM_FUNCSTARTUPLOAD			0x1D
#define S7COMM_FUNCUPLOAD				0x1E
#define S7COMM_FUNCENDUPLOAD			0x1F
#define S7COMM_FUNC_PLC_CONTROL			0x28
#define S7COMM_FUNC_PLC_STOP			0x29

static const value_string param_functionnames[] = {
	{ S7COMM_SERV_CPU,					"CPU services" },
	{ S7COMM_SERV_SETUPCOMM,			"Setup communication" },
	{ S7COMM_SERV_READVAR,				"Read Var" },
	{ S7COMM_SERV_WRITEVAR,				"Write Var" },
	/* Block management services */
	{ S7COMM_FUNCREQUESTDOWNLOAD,		"Request download" },
	{ S7COMM_FUNCDOWNLOADBLOCK,			"Download block" },
	{ S7COMM_FUNCDOWNLOADENDED,			"Download ended" },
	{ S7COMM_FUNCSTARTUPLOAD,			"Start upload" },
	{ S7COMM_FUNCUPLOAD,				"Upload" },
	{ S7COMM_FUNCENDUPLOAD,				"End upload" },
	{ S7COMM_FUNC_PLC_CONTROL,			"PLC Control" },
	{ S7COMM_FUNC_PLC_STOP,				"PLC Stop" },
	{ 0,								NULL }
};
/**************************************************************************
 * Area names
 */
#define S7COMM_AREA_SYSINFO				0x3		/* System info of 200 family */
#define S7COMM_AREA_SYSFLAGS			0x5		/* System flags of 200 family */
#define S7COMM_AREA_ANAIN				0x6		/* analog inputs of 200 family */
#define S7COMM_AREA_ANAOUT				0x7		/* analog outputs of 200 family */
#define S7COMM_AREA_P					0x80	/* direct peripheral access */
#define S7COMM_AREA_INPUTS				0x81    
#define S7COMM_AREA_OUTPUTS				0x82    
#define S7COMM_AREA_FLAGS				0x83
#define S7COMM_AREA_DB					0x84	/* data blocks */
#define S7COMM_AREA_DI					0x85	/* instance data blocks */
#define S7COMM_AREA_LOCAL				0x86 	/* local data (should not be accessible over network) */
#define S7COMM_AREA_V					0x87	/* previous (Vorgaenger) local data (should not be accessible over network)  */
#define S7COMM_AREA_COUNTER				28		/* S7 counters */
#define S7COMM_AREA_TIMER				29		/* S7 timers */
#define S7COMM_AREA_COUNTER200			30		/* IEC counters (200 family) */
#define S7COMM_AREA_TIMER200			31		/* IEC timers (200 family) */

static const value_string item_areanames[] = {
	{ S7COMM_AREA_SYSINFO,				"System info of 200 family" },
	{ S7COMM_AREA_SYSFLAGS,				"System flags of 200 family" },
	{ S7COMM_AREA_ANAIN,				"Analog inputs of 200 family" },
	{ S7COMM_AREA_ANAOUT,				"Analog outputs of 200 family" },
	{ S7COMM_AREA_P,					"Direct peripheral access (P)" },
	{ S7COMM_AREA_INPUTS,				"Inputs (I)" },
	{ S7COMM_AREA_OUTPUTS,				"Outputs (Q)" },
	{ S7COMM_AREA_FLAGS,				"Flags (M)" },
	{ S7COMM_AREA_DB,					"Data blocks (DB)" },
	{ S7COMM_AREA_DI,					"Instance data blocks (DI)" },
	{ S7COMM_AREA_LOCAL,				"Local data (L)" },
	{ S7COMM_AREA_V,					"Unknown yet (V)" },
	{ S7COMM_AREA_COUNTER,				"S7 counters (C)" },
	{ S7COMM_AREA_TIMER,				"S7 timers (T)" },
	{ S7COMM_AREA_COUNTER200,			"IEC counters (200 family)" },
	{ S7COMM_AREA_TIMER200,				"IEC timers (200 family)" },
	{ 0,								NULL }
};
/**************************************************************************
 * Transport sizes in item data
 */
	/* types of 1 byte length */
#define S7COMM_TRANSPORT_SIZE_BIT  		1
#define S7COMM_TRANSPORT_SIZE_BYTE 		2
#define S7COMM_TRANSPORT_SIZE_CHAR  	3
	/* types of 2 bytes length */
#define S7COMM_TRANSPORT_SIZE_WORD 		4
#define S7COMM_TRANSPORT_SIZE_INT  		5
	/* types of 4 bytes length */
#define S7COMM_TRANSPORT_SIZE_DWORD		6
#define S7COMM_TRANSPORT_SIZE_DINT		7
#define S7COMM_TRANSPORT_SIZE_REAL  	8
	/* Special types */
#define S7COMM_TRANSPORT_SIZE_DATE	 	9
#define S7COMM_TRANSPORT_SIZE_TOD	 	10
#define S7COMM_TRANSPORT_SIZE_TIME	 	11
#define S7COMM_TRANSPORT_SIZE_S5TIME 	12
#define S7COMM_TRANSPORT_SIZE_DT		15
	/* Timer or counter */
#define S7COMM_TRANSPORT_SIZE_COUNTER 	28
#define S7COMM_TRANSPORT_SIZE_TIMER  	29
#define S7COMM_TRANSPORT_SIZE_IEC_COUNTER	30
#define S7COMM_TRANSPORT_SIZE_IEC_TIMER		31
#define S7COMM_TRANSPORT_SIZE_HS_COUNTER	32
static const value_string item_transportsizenames[] = {
	{ S7COMM_TRANSPORT_SIZE_BIT,		"BIT" },
	{ S7COMM_TRANSPORT_SIZE_BYTE,		"BYTE" },
	{ S7COMM_TRANSPORT_SIZE_CHAR,		"CHAR" },
	{ S7COMM_TRANSPORT_SIZE_WORD,		"WORD" },
	{ S7COMM_TRANSPORT_SIZE_INT,		"INT" },
	{ S7COMM_TRANSPORT_SIZE_DWORD,		"DWORD" },
	{ S7COMM_TRANSPORT_SIZE_DINT,		"DINT" },
	{ S7COMM_TRANSPORT_SIZE_REAL,		"REAL" },
	{ S7COMM_TRANSPORT_SIZE_TOD,		"TOD" },
	{ S7COMM_TRANSPORT_SIZE_TIME,		"TIME" },
	{ S7COMM_TRANSPORT_SIZE_S5TIME,		"S5TIME" },
	{ S7COMM_TRANSPORT_SIZE_DT,			"DATE_AND_TIME" },
	{ S7COMM_TRANSPORT_SIZE_COUNTER,	"COUNTER" },	
	{ S7COMM_TRANSPORT_SIZE_TIMER,		"TIMER" },
	{ S7COMM_TRANSPORT_SIZE_IEC_COUNTER,"IEC TIMER" },	
	{ S7COMM_TRANSPORT_SIZE_IEC_TIMER,	"IEC COUNTER" },	
	{ S7COMM_TRANSPORT_SIZE_HS_COUNTER,	"HS COUNTER" },	
	{ 0,								NULL }
};

/**************************************************************************
 * Syntax Ids of variable specification
 */
#define S7COMM_SYNTAXID_S7ANY  			0x10		/* Adress data S7-Any pointer-like DB1.DBX10.2 */
#define S7COMM_SYNTAXID_DRIVEESANY 		0xa2		/* seen on Drive ES Starter with routing over S7 */
#define S7COMM_SYNTAXID_1200SYM  		0xb2		/* Symbolic address mode of S7-1200 */
#define S7COMM_SYNTAXID_DBREAD  		0xb0		/* Kind of DB block read, seen only at an S7-400 */

static const value_string item_syntaxid_names[] = {
	{ S7COMM_SYNTAXID_S7ANY,			"S7ANY" },
	{ S7COMM_SYNTAXID_DRIVEESANY,		"DRIVEESANY" },
	{ S7COMM_SYNTAXID_1200SYM,			"1200SYM" },
	{ S7COMM_SYNTAXID_DBREAD,			"DBREAD" },
	{ 0,								NULL }
};

/**************************************************************************
 * Transport sizes in data
 */
#define S7COMM_DATA_TRANSPORT_SIZE_NULL		0
#define S7COMM_DATA_TRANSPORT_SIZE_BBIT		3		/* bit access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BBYTE	4		/* byte/word/dword acces, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BINT		5		/* integer access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BREAL	7		/* real access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BSTR		9		/* octet string, len is in bytes */

static const value_string data_transportsizenames[] = {
	{ S7COMM_DATA_TRANSPORT_SIZE_NULL,	"NULL" },
	{ S7COMM_DATA_TRANSPORT_SIZE_BBIT,	"BIT" },
	{ S7COMM_DATA_TRANSPORT_SIZE_BBYTE,	"BYTE/WORD/DWORD" },
	{ S7COMM_DATA_TRANSPORT_SIZE_BINT,	"INTEGER" },
	{ S7COMM_DATA_TRANSPORT_SIZE_BREAL,	"REAL" },
	{ S7COMM_DATA_TRANSPORT_SIZE_BSTR,	"OCTET STRING" },
	{ 0,								NULL }
};
/**************************************************************************
 * Returnvalues of an item response
 */
#define S7COMM_ITEM_RETVAL_RESERVED				0x00
#define S7COMM_ITEM_RETVAL_DATA_HW_FAULT		0x01
#define S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT	0x03
#define S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE		0x05	/* the desired address is beyond limit for this PLC */
#define S7COMM_ITEM_RETVAL_DATA_NOT_SUP			0x06	/* Type is not supported */
#define S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH	0x07	/* Data type inconsistent */
#define S7COMM_ITEM_RETVAL_DATA_ERR				0x0a	/* the desired item is not available in the PLC, e.g. when trying to read a non existing DB*/
#define S7COMM_ITEM_RETVAL_DATA_OK				0xff
static const value_string item_return_valuenames[] = {
	{ S7COMM_ITEM_RETVAL_RESERVED,				"Reserved" },
	{ S7COMM_ITEM_RETVAL_DATA_HW_FAULT,			"Hardware error" },
	{ S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT,		"Accessing the object not allowed" },
	{ S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE,		"Invalid address" },
	{ S7COMM_ITEM_RETVAL_DATA_NOT_SUP,			"Data type not supported" },
	{ S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH,		"Data type inconsistent" },
	{ S7COMM_ITEM_RETVAL_DATA_ERR,				"Object does not exist" },		
	{ S7COMM_ITEM_RETVAL_DATA_OK,				"Success" },
	{ 0,										NULL }
};
/**************************************************************************
 * Block Types
 */
#define S7COMM_BLOCKTYPE_OB				'8'
#define S7COMM_BLOCKTYPE_DB				'A'
#define S7COMM_BLOCKTYPE_SDB			'B'
#define S7COMM_BLOCKTYPE_FC				'C'
#define S7COMM_BLOCKTYPE_SFC			'D'
#define S7COMM_BLOCKTYPE_FB				'E'
#define S7COMM_BLOCKTYPE_SFB			'F'

static const value_string blocktype_names[] = {
	{ S7COMM_BLOCKTYPE_OB,				"OB" },
	{ S7COMM_BLOCKTYPE_DB,				"DB" },
	{ S7COMM_BLOCKTYPE_SDB,				"SDB" },
	{ S7COMM_BLOCKTYPE_FC,				"FC" },
	{ S7COMM_BLOCKTYPE_SFC,				"SFC" },
	{ S7COMM_BLOCKTYPE_FB,				"FB" },
	{ S7COMM_BLOCKTYPE_SFB,				"SFB" },
	{ 0,								NULL }
};

/**************************************************************************
 * Subblk types
 */
#define S7COMM_SUBBLKTYPE_OB			0x08
#define S7COMM_SUBBLKTYPE_DB			0x0a
#define S7COMM_SUBBLKTYPE_SDB			0x0b
#define S7COMM_SUBBLKTYPE_FC			0x0c
#define S7COMM_SUBBLKTYPE_SFC			0x0d
#define S7COMM_SUBBLKTYPE_FB			0x0e
#define S7COMM_SUBBLKTYPE_SFB			0x0f

static const value_string subblktype_names[] = {
	{ S7COMM_SUBBLKTYPE_OB,				"OB" },
	{ S7COMM_SUBBLKTYPE_DB,				"DB" },
	{ S7COMM_SUBBLKTYPE_SDB,			"SDB" },
	{ S7COMM_SUBBLKTYPE_FC,				"FC" },
	{ S7COMM_SUBBLKTYPE_SFC,			"SFC" },
	{ S7COMM_SUBBLKTYPE_FB,				"FB" },
	{ S7COMM_SUBBLKTYPE_SFB,			"SFB" },
	{ 0,								NULL }
};

/**************************************************************************
 * Block security
 */
#define S7COMM_BLOCKSECURITY_OFF			0
#define S7COMM_BLOCKSECURITY_KNOWHOWPROTECT	3

static const value_string blocksecurity_names[] = {
	{ S7COMM_BLOCKSECURITY_OFF,				"None" },
	{ S7COMM_BLOCKSECURITY_KNOWHOWPROTECT,	"Kow How Protect" },
	{ 0,									NULL }
};
/**************************************************************************
 * Block Languages
 */
static const value_string blocklanguage_names[] = {
	{ 0x00,								"Not defined" },
	{ 0x01,								"AWL" },
	{ 0x02,								"KOP" },
	{ 0x03,								"FUP" },
	{ 0x04,								"SCL" },
	{ 0x05,								"DB" },
	{ 0x06,								"GRAPH" },
	{ 0x07,								"SDB" },
	{ 0x08,								"CPU-DB" },							/* DB was created from Plc programm (CREAT_DB) */
	{ 0x11, 							"SDB (after overall reset)" },		/* another SDB, don't know what it means, in SDB 1 and SDB 2, uncertain*/
	{ 0x12,								"SDB (Routing)" },					/* another SDB, in SDB 999 and SDB 1000 (routing information), uncertain */
	{ 0,								NULL }
};

/**************************************************************************
 * Names of types in userdata parameter part
 */
#define S7COMM_UD_TYPE_FOLLOW			0x0			
#define S7COMM_UD_TYPE_REQ				0x4
#define S7COMM_UD_TYPE_RES				0x8

static const value_string userdata_type_names[] = {
	{ S7COMM_UD_TYPE_FOLLOW,			"Follow" },			/* this type occurs when 2 telegrams follow after another from the same partner, or initiated from PLC */
	{ S7COMM_UD_TYPE_REQ,				"Request" },
	{ S7COMM_UD_TYPE_RES,				"Response" },
	{ 0,								NULL }
};

/**************************************************************************
 * Userdata Parameter, last data unit 
 */
#define S7COMM_UD_LASTDATAUNIT_YES		0x00
#define S7COMM_UD_LASTDATAUNIT_NO		0x01

static const value_string userdata_lastdataunit_names[] = {
	{ S7COMM_UD_LASTDATAUNIT_YES,		"Yes" },
	{ S7COMM_UD_LASTDATAUNIT_NO,		"No" },
	{ 0,								NULL }
};

/**************************************************************************
 * Names of Function groups in userdata parameter part
 */
#define S7COMM_UD_FUNCGROUP_PROG		0x1
#define S7COMM_UD_FUNCGROUP_CYCLIC		0x2
#define S7COMM_UD_FUNCGROUP_BLOCK		0x3
#define S7COMM_UD_FUNCGROUP_SZL			0x4
#define S7COMM_UD_FUNCGROUP_SEC			0x5				/* Security funnctions?? e.g. plc password */
#define S7COMM_UD_FUNCGROUP_TIME		0x7

static const value_string userdata_functiongroup_names[] = {
	{ S7COMM_UD_FUNCGROUP_PROG,			"Programmer commands" },
	{ S7COMM_UD_FUNCGROUP_CYCLIC,		"Cyclic data" },			/* to read data from plc without a request */
	{ S7COMM_UD_FUNCGROUP_BLOCK,		"Block functions" },
	{ S7COMM_UD_FUNCGROUP_SZL,			"SZL functions" },
	{ S7COMM_UD_FUNCGROUP_SEC,			"Security" },
	{ S7COMM_UD_FUNCGROUP_TIME,			"Time functions" },
	{ 0,								NULL }
};

/**************************************************************************
 * Vartab: Typ of data in data part, first two bytes
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ	0x14
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES	0x04

static const value_string userdata_prog_vartab_type_names[] = {
	{ S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ,		"Request" },		/* Request of data areas */
	{ S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES,		"Response" },		/* Response from plc with data */
	{ 0,								NULL }
};

/**************************************************************************
 * Vartab: area of data request
 *
 * Low       Hi
 * 0=M       1=BYTE
 * 1=E       2=WORD
 * 2=A       3=DWORD
 * 3=PEx
 * 7=DB	
 * 54=TIMER	
 * 64=COUNTER	
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB	0x01
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW	0x02
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD	0x03
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB	0x11
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW	0x12
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED	0x13
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB	0x21
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW	0x22
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD	0x23
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB	0x31
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW	0x32
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED	0x33
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB	0x71
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW	0x72
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD	0x73
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_T	0x54
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_C	0x64


static const value_string userdata_prog_vartab_area_names[] = {
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB,		"MB" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW,		"MW" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD,		"MD" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB,		"IB" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW,		"IW" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED,		"ID" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB,		"QB" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW,		"QW" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD,		"QD" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB,		"PIB" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW,		"PIW" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED,		"PID" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB,		"DBB" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW,		"DBW" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD,		"DBD" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_T,		"TIMER" },
	{ S7COMM_UD_SUBF_PROG_VARTAB_AREA_C,		"COUNTER" },
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 1 (Programmer commands)
 */
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA1	0x01
#define S7COMM_UD_SUBF_PROG_VARTAB1			0x02
#define S7COMM_UD_SUBF_PROG_ERASE			0x0c
#define S7COMM_UD_SUBF_PROG_READDIAGDATA	0x0e
#define S7COMM_UD_SUBF_PROG_REMOVEDIAGDATA	0x0f
#define S7COMM_UD_SUBF_PROG_FORCE			0x10
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA2	0x13

static const value_string userdata_prog_subfunc_names[] = {
	{ S7COMM_UD_SUBF_PROG_REQDIAGDATA1,		"Request diag data (Type 1)" },		/* Start online block view */
	{ S7COMM_UD_SUBF_PROG_VARTAB1,			"VarTab" },							/* Variable table */
	{ S7COMM_UD_SUBF_PROG_READDIAGDATA,		"Read diag data" },					/* online block view */
	{ S7COMM_UD_SUBF_PROG_REMOVEDIAGDATA,	"Remove diag data" },				/* Stop online block view */
	{ S7COMM_UD_SUBF_PROG_ERASE,			"Erase" },
	{ S7COMM_UD_SUBF_PROG_FORCE,			"Forces" },
	{ S7COMM_UD_SUBF_PROG_REQDIAGDATA2,		"Request diag data (Type2)" },		/* Start online block view */
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 2 (cyclic data)
 */
#define S7COMM_UD_SUBF_CYCLIC_MEM			0x01
#define S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE	0x04

static const value_string userdata_cyclic_subfunc_names[] = {
	{ S7COMM_UD_SUBF_CYCLIC_MEM,		"Memory" },			/* read data from memory (DB/M/etc.) */
	{ S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE,"Unsubscribe" },	/* Unsubcribe (diable) cyclic data */
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 3 (Block functions)
 */
#define S7COMM_UD_SUBF_BLOCK_LIST		0x01
#define S7COMM_UD_SUBF_BLOCK_LISTTYPE	0x02
#define S7COMM_UD_SUBF_BLOCK_BLOCKINFO	0x03

static const value_string userdata_block_subfunc_names[] = {
	{ S7COMM_UD_SUBF_BLOCK_LIST,		"List blocks" },
	{ S7COMM_UD_SUBF_BLOCK_LISTTYPE,	"List blocks of type" },
	{ S7COMM_UD_SUBF_BLOCK_BLOCKINFO,	"Get block info" },
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 4 (SZL functions)
 */
#define S7COMM_UD_SUBF_SZL_READ			0x01
#define S7COMM_UD_SUBF_SZL_ASMESS		0x02

static const value_string userdata_szl_subfunc_names[] = {
	{ S7COMM_UD_SUBF_SZL_READ,			"Read SZL" },
	{ S7COMM_UD_SUBF_SZL_ASMESS,		"System-state" },	/* Header constant is also different here */
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 5 (Security?)
 */
#define S7COMM_UD_SUBF_SEC_PASSWD		0x01

static const value_string userdata_sec_subfunc_names[] = {
	{ S7COMM_UD_SUBF_SEC_PASSWD,		"PLC password" },
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 7 (Time functions)
 */
#define S7COMM_UD_SUBF_TIME_READ		0x01
#define S7COMM_UD_SUBF_TIME_READF		0x03
#define S7COMM_UD_SUBF_TIME_SET			0x04

static const value_string userdata_time_subfunc_names[] = {
	{ S7COMM_UD_SUBF_TIME_READ,			"Read clock" },
	{ S7COMM_UD_SUBF_TIME_READF,		"Read clock (following)" },
	{ S7COMM_UD_SUBF_TIME_SET,			"Set clock" },
	{ 0,								NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 7 (Time functions)
 */
static const true_false_string fragment_descriptions = {
	"Yes",
	"No"
};

/**************************************************************************
 **************************************************************************/
 
/**************************************************************************
 * Flags for LID access
 */
#define S7COMM_TIA1200_VAR_ENCAPS_LID		0x2
#define S7COMM_TIA1200_VAR_ENCAPS_IDX		0x3
#define S7COMM_TIA1200_VAR_OBTAIN_LID		0x4
#define S7COMM_TIA1200_VAR_OBTAIN_IDX		0x5
#define S7COMM_TIA1200_VAR_PART_START		0x6
#define S7COMM_TIA1200_VAR_PART_LEN			0x7

static const value_string tia1200_var_lid_flag_names[] = {
	{ S7COMM_TIA1200_VAR_ENCAPS_LID,		"Encapsulated LID" },
	{ S7COMM_TIA1200_VAR_ENCAPS_IDX,		"Encapsulated Index" },
	{ S7COMM_TIA1200_VAR_OBTAIN_LID,		"Obtain by LID" },
	{ S7COMM_TIA1200_VAR_OBTAIN_IDX,		"Obtain by Index" },
	{ S7COMM_TIA1200_VAR_PART_START,		"Part Start Address" },
	{ S7COMM_TIA1200_VAR_PART_LEN,			"Part Length" },
	{ 0,									NULL }
};

/**************************************************************************
 * TIA 1200 Area Names for variable access
 */
#define S7COMM_TIA1200_VAR_ITEM_AREA_I		0x50
#define S7COMM_TIA1200_VAR_ITEM_AREA_O		0x51
#define S7COMM_TIA1200_VAR_ITEM_AREA_M		0x52
#define S7COMM_TIA1200_VAR_ITEM_AREA_C		0x53
#define S7COMM_TIA1200_VAR_ITEM_AREA_T		0x54

static const value_string tia1200_var_item_area_names[] = {
	{ S7COMM_TIA1200_VAR_ITEM_AREA_I,		"Inputs (I)" },
	{ S7COMM_TIA1200_VAR_ITEM_AREA_O,		"Outputs (Q)" },
	{ S7COMM_TIA1200_VAR_ITEM_AREA_M,		"Flags (M)" },
	{ S7COMM_TIA1200_VAR_ITEM_AREA_C,		"Counter (C)" },
	{ S7COMM_TIA1200_VAR_ITEM_AREA_T,		"Timer (TM)" },
	{ 0,									NULL }
};

static gint hf_s7comm_tia1200_substructure_item = -1;					/* Substructure */
static gint hf_s7comm_tia1200_var_lid_flags = -1;						/* LID Flags */

/**************************************************************************
 **************************************************************************/




/**************************************************************************
 **************************************************************************/
/* Header Block */
static gint hf_s7comm = -1;
static gint hf_s7comm_header = -1;
static gint hf_s7comm_header_protid = -1;			/* Header Byte  0 */
static gint hf_s7comm_header_rosctr = -1;			/* Header Bytes 1 */
static gint hf_s7comm_header_redid = -1;			/* Header Bytes 2, 3 */
static gint hf_s7comm_header_pduref = -1;			/* Header Bytes 4, 5 */
static gint hf_s7comm_header_parlg = -1;			/* Header Bytes 6, 7 */
static gint hf_s7comm_header_datlg = -1;			/* Header Bytes 8, 9 */
static gint hf_s7comm_header_errcls = -1;			/* Header Byte 10, only available at type 2 or 3 */
static gint hf_s7comm_header_errcod = -1;			/* Header Byte 11, only available at type 2 or 3 */
/* Parameter Block */
static gint hf_s7comm_param = -1;
static gint hf_s7comm_param_service = -1;			/* Parameter part: service */
static gint hf_s7comm_param_itemcount = -1;			/* Parameter part: item count */
static gint hf_s7comm_param_data = -1;				/* Parameter part: data */
static gint hf_s7comm_param_neg_pdu_length = -1;	/* Parameter part: Negotiate PDU length */


/* Item data */
static gint hf_s7comm_param_item = -1;
static gint hf_s7comm_item_varspec = -1;			/* Variable specification */
static gint hf_s7comm_item_varspec_length = -1;		/* Length of following address specification */
static gint hf_s7comm_item_syntax_id = -1;			/* Syntax Id */
static gint hf_s7comm_item_transport_size = -1; 	/* Transport size, 1 Byte*/
static gint hf_s7comm_item_length = -1;				/* length, 2 Bytes*/
static gint hf_s7comm_item_db = -1;					/* DB/M/E/A, 2 Bytes */
static gint hf_s7comm_item_area = -1;				/* Area code, 1 byte */
static gint hf_s7comm_item_address = -1;			/* Bit adress, 3 Bytes */

static gint hf_s7comm_data = -1;
static gint hf_s7comm_data_transport_size = -1;		/* unknown part, kind of "transport size"? constant 0x09, 1 byte */
static gint hf_s7comm_data_item = -1;

static gint hf_s7comm_readresponse_data = -1;
static gint hf_s7comm_item_return_value = -1;




static gint hf_s7comm_userdata_param = -1;
static gint hf_s7comm_userdata_data = -1;
static gint hf_s7comm_userdata_data_return_value = -1;		/* Return value in userdata header, 1 byte */
static gint hf_s7comm_userdata_data_length = -1;			/* Length of user data, 2 Bytes */

static gint hf_s7comm_userdata_param_head = -1;
static gint hf_s7comm_userdata_param_len = -1;
static gint hf_s7comm_userdata_param_reqres2 = -1;			/* unknown */
static gint hf_s7comm_userdata_param_type = -1;
static gint hf_s7comm_userdata_param_funcgroup = -1;
static gint hf_s7comm_userdata_param_subfunc = -1;
static gint hf_s7comm_userdata_param_seq_num = -1;
static gint hf_s7comm_userdata_param_dataunitref = -1;
static gint hf_s7comm_userdata_param_dataunit = -1;


static gint hf_s7comm_userdata_blockinfo_flags = -1;		/* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_linked = -1;		/* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_standard_block = -1;
static gint hf_s7comm_userdata_blockinfo_nonretain = -1;	/* Some flags in Block info response */

/* Flags for requested registers in diagnostic data telegrams */
static gint hf_s7comm_diagdata_registerflag = -1;			/* Registerflags */
static gint hf_s7comm_diagdata_registerflag_stw = -1;		/* STW = Status word */
static gint hf_s7comm_diagdata_registerflag_accu1 = -1;		/* Accumulator 1 */
static gint hf_s7comm_diagdata_registerflag_accu2 = -1;		/* Accumulator 2 */
static gint hf_s7comm_diagdata_registerflag_ar1 = -1;		/* Addressregister 1 */
static gint hf_s7comm_diagdata_registerflag_ar2 = -1;		/* Addressregister 2 */
static gint hf_s7comm_diagdata_registerflag_db1 = -1;		/* Datablock register 1 */
static gint hf_s7comm_diagdata_registerflag_db2 = -1;		/* Datablock register 1 */


/* These are the ids of the subtrees that we are creating */
static gint ett_s7comm = -1;								/* S7 communication tree, parent of all other subtree */
static gint ett_s7comm_header = -1;							/* Subtree for header block */
static gint ett_s7comm_param = -1;							/* Subtree for parameter block */
static gint ett_s7comm_param_item = -1;						/* Subtree for items in parameter block */
static gint ett_s7comm_data = -1;							/* Subtree for data block */
static gint ett_s7comm_data_item = -1;						/* Subtree for an item in data block */


/* Register this protocol */
void
proto_reg_handoff_s7comm(void)
{
	static gboolean initialized = FALSE;
	if (!initialized) {
		/* register ourself as an heuristic cotp (ISO 8073) payload dissector */
        heur_dissector_add("cotp", dissect_s7comm, proto_s7comm);
		initialized = TRUE;
	}
}

void
proto_register_s7comm (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_s7comm,
		{ "S7 Communication Data",		"s7comm.gendata",		FT_NONE, BASE_NONE, NULL, 0x0,
		  "S7 Communication Data", HFILL }},
		  
		{ &hf_s7comm_header,
		{ "Header",						"s7comm.header",		FT_NONE, BASE_NONE, NULL, 0x0,
		  "This is the header of S7 communication", HFILL }},
		{ &hf_s7comm_header_protid,
		{ "Protocol Id",				"s7comm.header.protid",	FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Protocol Identification, 0x32 for S7", HFILL }},
		{ &hf_s7comm_header_rosctr,
		{ "ROSCTR",						"s7comm.header.rosctr",	FT_UINT8, BASE_DEC, VALS(rosctr_names), 0x0,
		  "Remote Operating Service Control", HFILL }},
		{ &hf_s7comm_header_redid,
		{ "Redundancy Identification (Reserved)",	"s7comm.header.redid", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Redundancy Identification (Reserved), should be always 0x0000", HFILL }},
		{ &hf_s7comm_header_pduref,
		{ "Protocol Data Unit Reference",			"s7comm.header.pduref", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Protocol Data Unit Reference", HFILL }},
		{ &hf_s7comm_header_parlg,
		{ "Parameter length",			"s7comm.header.parlg", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Specifies the entire length of the parameter block in bytes", HFILL }},
		{ &hf_s7comm_header_datlg,
		{ "Data length",				"s7comm.header.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Specifies the entire length of the data block in bytes", HFILL }}, 
		{ &hf_s7comm_header_errcls,
		{ "Error class",				"s7comm.header.errcls", FT_UINT8, BASE_HEX, VALS(errcls_names), 0x0,
		  "Error class", HFILL }},
		{ &hf_s7comm_header_errcod,
		{ "Error code",					"s7comm.header.errcod", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Error code", HFILL }},
		  
		{ &hf_s7comm_param,
		{ "Parameter",					"s7comm.param",			FT_NONE, BASE_NONE, NULL, 0x0,
		  "This is the parameter part of S7 communication", HFILL }},
		{ &hf_s7comm_param_service,
		{ "Function",					"s7comm.param.func",	FT_UINT8, BASE_HEX, VALS(param_functionnames), 0x0,
		  "Indicates the function of parameter/data", HFILL }},
		{ &hf_s7comm_param_neg_pdu_length,
		{ "PDU length",					"s7comm.param.pdu_length",	FT_UINT16, BASE_DEC, NULL, 0x0,
		  "PDU length", HFILL }},
		{ &hf_s7comm_param_itemcount,
		{ "Item count",					"s7comm.param.itemcount",	FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Items in parameter/data part", HFILL }},
		{ &hf_s7comm_param_data,
		{ "Parameter data",				"s7comm.param.data",	FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Parameter data", HFILL }},
		{ &hf_s7comm_param_item,
		{ "Item",						"s7comm.param.item",	FT_NONE, BASE_NONE, NULL, 0x0,
		  "Item", HFILL }},		  
		{ &hf_s7comm_item_varspec,
		{ "Variable specification",		"s7comm.param.item.varspec",	FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Variable specification", HFILL }},
		{ &hf_s7comm_item_varspec_length,
		{ "Length of following address specification",		"s7comm.param.item.varspec_length",	FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Length of following address specification", HFILL }},
		{ &hf_s7comm_item_syntax_id,
		{ "Syntax Id",					"s7comm.param.item.syntaxid",	FT_UINT8, BASE_HEX, VALS(item_syntaxid_names), 0x0,
		  "Syntax Id, format type of following address specification", HFILL }},		  
		{ &hf_s7comm_item_transport_size,
		{ "Transport size",				"s7comm.param.item.transp_size", FT_UINT8, BASE_DEC, VALS(item_transportsizenames), 0x0,
		  "Transport size", HFILL }},
		{ &hf_s7comm_item_length,
		{ "Length",						"s7comm.param.item.length", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length", HFILL }},
		{ &hf_s7comm_item_db,
		{ "DB number",					"s7comm.param.item.db", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "DB number", HFILL }},
		{ &hf_s7comm_item_area,
		{ "Area",						"s7comm.param.item.area", FT_UINT8, BASE_HEX, VALS(item_areanames), 0x0,
		  "Area", HFILL }},
		{ &hf_s7comm_item_address,
		{ "Address",					"s7comm.param.item.address", FT_UINT24, BASE_HEX, NULL, 0x0,
		  "Address", HFILL }},
		{ &hf_s7comm_data,
		{ "Data",						"s7comm.data", FT_NONE, BASE_NONE, NULL, 0x0,
		  "This is the data part of S7 communication", HFILL }},
		{ &hf_s7comm_data_transport_size,
		{ "Transport size",				"s7comm.data.userdata.transportsize", FT_UINT8,	BASE_HEX, VALS(data_transportsizenames), 0x0,
      	  "Data type / Transport size", HFILL }},
		{ &hf_s7comm_data_item,
		{ "Item",						"s7comm.data.item", FT_NONE, BASE_NONE, NULL, 0x0,
		  "Item", HFILL }},
		{ &hf_s7comm_item_return_value,
		{ "Return code",				"s7comm.data.ret_code", FT_UINT8, BASE_HEX, VALS(item_return_valuenames), 0x0,
		  "Return code", HFILL }},
		{ &hf_s7comm_readresponse_data,
		{ "Data",						"s7comm.resp.data", FT_BYTES,	BASE_NONE, NULL, 0x0,
      	  "Data", HFILL }},



		{ &hf_s7comm_userdata_param,
		{ "Userdata parameter",			"s7comm.param.userdata", FT_BYTES,	BASE_NONE, NULL, 0x0,
      	  "Userdata parameter", HFILL }},
		{ &hf_s7comm_userdata_data,
		{ "Data",						"s7comm.data.userdata", FT_BYTES,	BASE_NONE, NULL, 0x0,
      	  "Userdata data", HFILL }},
		{ &hf_s7comm_userdata_data_return_value,
		{ "Return value",				"s7comm.data.userdata.ret_code", FT_UINT8,	BASE_HEX, VALS(item_return_valuenames), 0x0,
      	  "Userdata return value", HFILL }},		
		{ &hf_s7comm_userdata_data_length,
		{ "Length",						"s7comm.data.userdata.length", FT_UINT16,	BASE_DEC, NULL, 0x0,
      	  "Length of userdata", HFILL }},
	/* Userdata parameter 8/12 Bytes len*/
		{ &hf_s7comm_userdata_param_head,
		{ "Parameter head",				"s7comm.param.userdata.head", FT_UINT24, BASE_HEX, NULL, 0x0,
		  "Header before parameter (constant 0x000112)", HFILL }},
		{ &hf_s7comm_userdata_param_len,
		{ "Parameter length",			"s7comm.param.userdata.length", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Length of following parameter data (without head)", HFILL }},
		{ &hf_s7comm_userdata_param_reqres2,
		{ "Unknown (Request/Response)",	"s7comm.param.userdata.reqres1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Unknown part, possible request/response (0x11, 0x12), but not in programmer commands", HFILL }},

		{ &hf_s7comm_userdata_param_type,
		{ "Type",						"s7comm.param.userdata.type", FT_UINT8,	BASE_DEC, VALS(userdata_type_names), 0xf0,
      	  "Type of parameter", HFILL }},

		{ &hf_s7comm_userdata_param_funcgroup,
		{ "Function group",				"s7comm.param.userdata.funcgroup", FT_UINT8, BASE_DEC, VALS(userdata_functiongroup_names), 0x0f,
      	  "Function group", HFILL }},

		{ &hf_s7comm_userdata_param_subfunc,
		{ "Subfunction",				"s7comm.param.userdata.subfunc", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Subfunction", HFILL }},

		{ &hf_s7comm_userdata_param_seq_num,
		{ "Sequence number",			"s7comm.param.userdata.seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Sequence number", HFILL }},

		{ &hf_s7comm_userdata_param_dataunitref,
		{ "Data unit reference number",				"s7comm.param.userdata.dataunitref", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Data unit reference number if PDU is fragmented", HFILL }},
		  
		{ &hf_s7comm_userdata_param_dataunit,
		{ "Last data unit",				"s7comm.param.userdata.lastdataunit", FT_UINT8, BASE_HEX, VALS(userdata_lastdataunit_names), 0x0,
		  "Last data unit", HFILL }},

		  /* Flags in blockinfo response */
		{ &hf_s7comm_userdata_blockinfo_flags,
		{ "Block flags",				"s7comm.param.userdata.blockinfo.flags", FT_UINT8, BASE_HEX, NULL, 0xff,
      	  "Some block configuration flags", HFILL }},
		 /* Bit : 0 -> DB Linked = true */ 
		{ &hf_s7comm_userdata_blockinfo_linked,
		{ "Linked",				"s7comm.param.userdata.blockinfo.linked", FT_BOOLEAN, 8, TFS(&fragment_descriptions), 0x01,
      	  "Linked", HFILL }},
		/* Bit : 1 -> Standard block = true */ 
		{ &hf_s7comm_userdata_blockinfo_standard_block,
		{ "Standard block",				"s7comm.param.userdata.blockinfo.standard_block", FT_BOOLEAN, 8, TFS(&fragment_descriptions), 0x02,
      	  "Standard block", HFILL }},
		/* Bit : 5 -> DB Non Retain = true */
		{ &hf_s7comm_userdata_blockinfo_nonretain,
		{ "Non Retain",					"s7comm.param.userdata.blockinfo.nonretain", FT_BOOLEAN, 8, TFS(&fragment_descriptions), 0x08,
      	  "Non Retain", HFILL }},
		  
		  
		 /* Flags for requested registers in diagnostic data telegrams */
		{ &hf_s7comm_diagdata_registerflag,
		{ "Registers",			"s7comm.diagdata.register", FT_UINT8, BASE_HEX, NULL, 0x00, // 0xff
		  "Requested registers", HFILL }},		  
		{ &hf_s7comm_diagdata_registerflag_stw,
		{ "Status word",		"s7comm.diagdata.register.stw", FT_BOOLEAN, 8, NULL, 0x01,
		  "STW / Status word", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_accu1,
		{ "Accumulator 1",		"s7comm.diagdata.register.accu1", FT_BOOLEAN, 8, NULL, 0x02,
		  "AKKU1 / Accumulator 1", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_accu2,
		{ "Accumulator 2",		"s7comm.diagdata.register.accu2", FT_BOOLEAN, 8, NULL, 0x04,
		  "AKKU2 / Accumulator 2", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_ar1,
		{ "Addressregister 1",		"s7comm.diagdata.register.ar1", FT_BOOLEAN, 8, NULL, 0x08,
		  "AR1 / Addressregister 1", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_ar2,
		{ "Addressregister 2",		"s7comm.diagdata.register.ar2", FT_BOOLEAN, 8, NULL, 0x10,
		  "AR2 / Addressregister 2", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_db1,
		{ "Datablock register 1",		"s7comm.diagdata.register.db1", FT_BOOLEAN, 8, NULL, 0x20,
		  "DB1 (global)/ Datablock register 1", HFILL }},
		{ &hf_s7comm_diagdata_registerflag_db2,
		{ "Datablock register 2",		"s7comm.diagdata.register.db2", FT_BOOLEAN, 8, NULL, 0x40,
		  "DB2 (instance) / Datablock register 2", HFILL }},
		
		/* TIA Portal stuff */
		{ &hf_s7comm_tia1200_var_lid_flags,
		{ "LID flags",					"s7comm.tiap.lid_flags", FT_UINT8,	BASE_DEC, VALS(tia1200_var_lid_flag_names), 0xf0,
      	  "LID flags", HFILL }},
		  
		{ &hf_s7comm_tia1200_substructure_item,
		{ "Substructure",				"s7comm.tiap.substructure",	FT_NONE, BASE_NONE, NULL, 0x0,
		  "Substructure", HFILL }},
	};

	static gint *ett[] = {
		&ett_s7comm,
		&ett_s7comm_header,
		&ett_s7comm_param,
		&ett_s7comm_param_item,
		&ett_s7comm_data,
		&ett_s7comm_data_item,
	};

	proto_s7comm = proto_register_protocol (
			"S7 Communication",			/* name */
			"S7COMM",					/* short name */
			"s7comm"					/* abbrev */
			);

	proto_register_field_array(proto_s7comm, hf, array_length (hf));
	
	s7comm_register_szl_types(proto_s7comm);

	proto_register_subtree_array(ett, array_length (ett));
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * S7-Protocol (main tree)
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static gboolean /*use a gboolean return value for a heuristic dissector, void  otherwise*/
dissect_s7comm(tvbuff_t *tvb, 
				packet_info *pinfo, 
				proto_tree *tree, 
				void *data _U_)
{
	proto_item *s7comm_item = NULL;
	proto_item *s7comm_sub_item = NULL;
	proto_tree *s7comm_tree = NULL;
	proto_tree *s7comm_header_tree = NULL;
	proto_tree *s7comm_param_tree = NULL;
	proto_tree *s7comm_data_tree = NULL;

	guint32 offset = 0;

	guint8 rosctr = 0;
	guint8 hlength = 10; /* Header 10 Bytes, when type 2 or 3 (Response) -> 12 Bytes */
	guint16 plength = 0;
	guint16 dlength = 0;

	/*----------------- Heuristic Checks - Begin */
	/* 1) check for minimum length */
	if(tvb_length(tvb) < S7COMM_MIN_TELEGRAM_LENGTH) 
		return 0;
	/* 2) first byte must be 0x32 */
	if ( tvb_get_guint8(tvb, 0) != S7COMM_PROT_ID )
		return 0;
	/* 3) second byte is a type field and only can contain values between 0x01-0x07 (1/2/3/7) */
	if ( tvb_get_guint8(tvb, 1) < 0x01 || tvb_get_guint8(tvb, 1) > 0x07)
		return 0;	
	/*----------------- Heuristic Checks - End */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM);
	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	rosctr = tvb_get_guint8( tvb, 1 );						/* Get the type byte */
	if (rosctr == 2 || rosctr == 3) hlength = 12;			/* Header 10 Bytes, when type 2 or 3 (response) -> 12 Bytes */

	/* display some infos in info-column of wireshark */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "ROSCTR:[%-8s]",
				val_to_str(rosctr, rosctr_names, "Unknown: 0x%02x")
				);
	}
	
	if (tree) { /* we are being asked for details */
		s7comm_item = proto_tree_add_item(tree, proto_s7comm, tvb, 0, -1, FALSE);
        s7comm_tree = proto_item_add_subtree(s7comm_item, ett_s7comm);
        s7comm_header_tree = proto_item_add_subtree(s7comm_item, ett_s7comm);

		/* insert header tree */
		s7comm_sub_item = proto_tree_add_item( s7comm_tree, hf_s7comm_header, 
                        tvb, offset, hlength, FALSE );

		/* insert sub-items in header tree */
		s7comm_header_tree = proto_item_add_subtree(s7comm_sub_item, ett_s7comm);
		
		/* Protocol Identifier, constant 0x32 */
		proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_protid, tvb, offset, 1, FALSE);		
		offset += 1;
		
		/* ROSCTR (Remote Operating Service Control) - PDU Type */
		proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_rosctr, tvb, offset, 1, rosctr);
		/* Show pdu type beside the header tree */
		proto_item_append_text(s7comm_header_tree, ": (%s)", val_to_str(rosctr, rosctr_names, "Unknown ROSCTR: 0x%02x"));
		offset += 1;
		/* Redundacy ID, reserved */
		proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_redid, tvb, offset, 2, FALSE);
		offset += 2;
		/* Protocol Data Unit Reference */
		proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_pduref, tvb, offset, 2, FALSE);
		offset += 2;
		/* Parameter length */
		plength = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_parlg, tvb, offset, 2, plength);
		offset += 2;
		/* Data length */
		dlength = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_datlg, tvb, offset, 2, dlength);		
		offset += 2;
		/* when type is 2 or 3 there are 2 bytes with errorclass and errorcode */
		if (hlength == 12) {			
			proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcls, tvb, offset, 1, FALSE);
			offset += 1;
			proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcod, tvb, offset, 1, FALSE);
			offset += 1;
		}

		switch (rosctr) {
			case S7COMM_ROSCTR_JOB:
			case S7COMM_ROSCTR_ACK_DATA:
				offset = s7comm_decode_req_resp(tvb, pinfo, s7comm_tree, plength, dlength, offset, rosctr);
				break;
			case S7COMM_ROSCTR_USERDATA:
				offset = s7comm_decode_ud(tvb, pinfo, s7comm_tree, plength, dlength, offset );
				break;
		}
		/*else {  Unknown pdu, maybe passed to another dissector... 

		*/
	}
	return TRUE;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_req_resp(tvbuff_t *tvb, 
					  packet_info *pinfo, 
					  proto_tree *tree, 
					  guint16 plength, 
					  guint16 dlength, 
					  guint32 offset,
					  guint8 rosctr)
{
	proto_item *item = NULL;
	proto_tree *param_tree = NULL;
	proto_tree *data_tree = NULL;
	guint8 function = 0;
	guint8 item_count = 0;
	guint8 i;
	guint32 offset_old;
	guint32 len;

	if (plength > 0) {
		/* Add parameter tree */
		item = proto_tree_add_item( tree, hf_s7comm_param, tvb, offset, plength, FALSE );
		param_tree = proto_item_add_subtree( item, ett_s7comm_param);		
		/* Analyze function */
		function = tvb_get_guint8( tvb, offset );
		/* add param.function to info column */
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s]", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
		}
		proto_tree_add_uint(param_tree, hf_s7comm_param_service, tvb, offset, 1, function);
		/* show param.function code at the tree */
		proto_item_append_text(param_tree, ": (%s)", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
		offset += 1;

		if (rosctr == S7COMM_ROSCTR_JOB) {
			switch (function){
				case S7COMM_SERV_READVAR:
				case S7COMM_SERV_WRITEVAR:
					item_count = tvb_get_guint8( tvb, offset );
					proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
					offset += 1;
					/* parse item data */
					for (i = 0; i < item_count; i++) {
						offset_old = offset;
						offset = s7comm_decode_param_item(tvb, offset, pinfo, param_tree, i);
						/* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
						len = offset - offset_old;
						if ((len % 2) && (i < item_count)) {
							offset += 1;
						}						
					}
					/* in write-function there is a data part */
					if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
						item = proto_tree_add_item( tree, hf_s7comm_data, tvb, offset, dlength, FALSE );
						data_tree = proto_item_add_subtree( item, ett_s7comm_data);
						/* Add returned data to data-tree */
						offset = s7comm_decode_response_read_data( tvb, pinfo, data_tree, dlength, item_count, offset);
					}
					break;
				case S7COMM_SERV_SETUPCOMM:
					offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, plength, offset);
					break;
				/* Special functions */
				case S7COMM_FUNCREQUESTDOWNLOAD:
				case S7COMM_FUNCDOWNLOADBLOCK:
				case S7COMM_FUNCDOWNLOADENDED:
				case S7COMM_FUNCSTARTUPLOAD:
				case S7COMM_FUNCUPLOAD:
				case S7COMM_FUNCENDUPLOAD:
					offset = s7comm_decode_plc_controls_param_hex1x(tvb, pinfo, param_tree, plength, offset -1, rosctr);
					break;
				case S7COMM_FUNC_PLC_CONTROL:
					offset = s7comm_decode_plc_controls_param_hex28(tvb, pinfo, param_tree, plength, offset -1, rosctr);
					break;
				case S7COMM_FUNC_PLC_STOP:
					offset = s7comm_decode_plc_controls_param_hex29(tvb, pinfo, param_tree, plength, offset -1, rosctr);
					break;

				default:
					/* Print unknown part as raw bytes */
					if (plength > 1) {
						proto_tree_add_bytes(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1,
							tvb_get_ptr (tvb, offset, plength - 1));
					}
					offset += plength - 1; /* 1 byte function code */
					if (dlength > 0) {
						/* Add data tree 
						 * First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
						 * seem to indicate something else. But I'm not sure, so leave it as it is.....
						 */
						item = proto_tree_add_item( tree, hf_s7comm_data, tvb, offset, dlength, FALSE );
						data_tree = proto_item_add_subtree( item, ett_s7comm_data);
						proto_tree_add_bytes(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength,
							tvb_get_ptr (tvb, offset, dlength));
						offset += dlength;
					}
					break;
			}
		} else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
			switch (function){
				case S7COMM_SERV_READVAR:
				case S7COMM_SERV_WRITEVAR:
					/* This is a read-response, so the requested data may follow when address in request was ok */
					item_count = tvb_get_guint8( tvb, offset );
					proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
					offset += 1;
					/* Add data tree */
					item = proto_tree_add_item( tree, hf_s7comm_data, tvb, offset, dlength, FALSE );
					data_tree = proto_item_add_subtree( item, ett_s7comm_data);
					/* Add returned data to data-tree */
					if ((function == S7COMM_SERV_READVAR) && (dlength > 0)) {
						offset = s7comm_decode_response_read_data( tvb, pinfo, data_tree, dlength, item_count, offset);
					} else if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
						offset = s7comm_decode_response_write_data( tvb, pinfo, data_tree, dlength, item_count, offset);
					}
					break;
				case S7COMM_SERV_SETUPCOMM:
					offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, plength, offset);
					break;
				default:
					/* Print unknown part as raw bytes */
					if (plength > 1) {
						proto_tree_add_bytes(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1,
							tvb_get_ptr (tvb, offset, plength - 1));
					}
					offset += plength - 1; /* 1 byte function code */
					if (dlength > 0) {
						/* Add data tree
						/* First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
						 * seem to indicate something else. But I'm not sure, so leave it as it is.....
						 */
						item = proto_tree_add_item( tree, hf_s7comm_data, tvb, offset, dlength, FALSE );
						data_tree = proto_item_add_subtree( item, ett_s7comm_data);
						proto_tree_add_bytes(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength,
							tvb_get_ptr (tvb, offset, dlength));
						offset += dlength;
					}
					break;
			}
		}
	}
	return offset;
}

/*******************************************************************************************************
 *
 * Dissect the parameter details of a read/write request (Items)
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_param_item(tvbuff_t *tvb, 
						  guint32 offset, 
						  packet_info *pinfo, 
						  proto_tree *sub_tree, 
						  guint8 item_no)
{
	guint32 address = 0;
	guint32 bytepos = 0;
	guint32 bitpos = 0;
	guint8 t_size = 0;
	guint16 len = 0;
	guint16 db = 0;
	guint16 i;
	guint8 area = 0;
	proto_item *item = NULL;
	
	guint8 var_spec_type = 0;
	guint8 var_spec_length = 0;
	guint8 var_spec_syntax_id = 0;
	proto_item *tia_struct_item = NULL;
	guint16 tia_var_area1 = 0;
	guint16 tia_var_area2 = 0;
	guint8 tia_lid_flags = 0;
	
	/* At first check type and length of variable specification */
	var_spec_type = tvb_get_guint8(tvb, offset);
	var_spec_length = tvb_get_guint8(tvb, offset + 1);
	var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);
	
	/* Classic S7:  type = 0x12, len=10, syntax-id=0x10 for ANY-Pointer
	 * TIA S7-1200: type = 0x12, len=14, syntax-id=0xb2 (symbolic addressing??)
	 * Drive-ES Starter with routing: type = 0x12, len=10, syntax-id=0xa2 for ANY-Pointer
	 */
	 
	/* Insert a new tree for every item */
	item = proto_tree_add_item( sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, FALSE );
	sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);

	proto_item_append_text(item, " [%d]:", item_no + 1);

	/* Item head, constant 3 bytes */
	proto_tree_add_item(item, hf_s7comm_item_varspec, tvb, offset, 1, FALSE);	
	offset += 1;
	proto_tree_add_item(item, hf_s7comm_item_varspec_length, tvb, offset, 1, FALSE);	
	offset += 1;
	proto_tree_add_item(item, hf_s7comm_item_syntax_id, tvb, offset, 1, FALSE);	
	offset += 1;

	/****************************************************************************/
	/************************** Step 7 Classic 300 400 **************************/
	if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY) {		
		/* Transport size, 1 byte */
		t_size = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(item, hf_s7comm_item_transport_size, tvb, offset, 1, t_size);	
		offset += 1;
		/* Length, 2 bytes */
		len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(item, hf_s7comm_item_length, tvb, offset, 2, len);	
		offset += 2;
		/* DB number, 2 bytes */
		db = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(item, hf_s7comm_item_db, tvb, offset, 2, db);	
		offset += 2;
		/* Area, 1 byte */
		area = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(item, hf_s7comm_item_area, tvb, offset, 1, area);	
		offset += 1;
		/* Address, 3 bytes */
		address = tvb_get_ntoh24(tvb, offset);
		proto_tree_add_uint(item, hf_s7comm_item_address, tvb, offset, 3, address);	
		bytepos = address / 8;
		bitpos = address % 8;
		/* build a full adress to show item data directly beside the item */
		switch (area) {
			case (S7COMM_AREA_P):
				proto_item_append_text(item, " (P");
				break;
			case (S7COMM_AREA_INPUTS):
				proto_item_append_text(item, " (I");
				break;
			case (S7COMM_AREA_OUTPUTS):
				proto_item_append_text(item, " (Q");
				break;
			case (S7COMM_AREA_FLAGS):
				proto_item_append_text(item, " (M");
				break;
			case (S7COMM_AREA_DB):
				proto_item_append_text(item, " (DB%d.DBX", db);
				break;
			case (S7COMM_AREA_DI):
				proto_item_append_text(item, " (DI%d.DIX", db);
				break;
			case (S7COMM_AREA_LOCAL):
				proto_item_append_text(item, " (L");
				break;
			case (S7COMM_AREA_COUNTER):
				proto_item_append_text(item, " (C");
				break;
			case (S7COMM_AREA_TIMER):
				proto_item_append_text(item, " (T");
				break;
			default:
				proto_item_append_text(item, " (unknown area");
				break;
		}
		if (area == S7COMM_AREA_TIMER || area == S7COMM_AREA_COUNTER) {
			proto_item_append_text(item, " %d)", address);
		} else {
			proto_item_append_text(item, " %d.%d ", bytepos, bitpos);	
			proto_item_append_text(item, val_to_str(t_size, item_transportsizenames, "Unknown transport size: 0x%02x"));
			proto_item_append_text(item, " %d)", len);
		}	
		offset += 3;
	/****************************************************************************/
	/******************** S7-400 special address mode (kind of cyclic read) *****/
	} else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD) {
		/* don't know what this is, has to be always 0x01 */
		proto_tree_add_text(item, tvb, offset, 2, "Fixed (0x01)   : 0x%02x", tvb_get_guint8( tvb, offset));
		offset += 1;
		len = tvb_get_guint8( tvb, offset);
		proto_tree_add_text(item, tvb, offset, 1, "Number of bytes: %u", len);
		offset += 1;
		/* DB number, 2 bytes */
		db = tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(item, tvb, offset, 1, "DB number      : %u", db);
		offset += 2;
		/* Start address, 2 bytes */
		bytepos = tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(item, tvb, offset, 2, "Start address  : %u", bytepos);
		offset += 2;
		/* Display as pseudo S7-Any Format */
		proto_item_append_text(item, " (DB%d.DBB %d BYTE %d)", db, bytepos, len);
	/****************************************************************************/
	/******************** TIA S7 1200 symbolic address mode *********************/
	} else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM) {
		proto_item_append_text(item, " 1200 symbolic address");
		/* first byte in address seems always be 0xff */
		proto_tree_add_text(item, tvb, offset, 1, "1200 sym Reserved: 0x%02x", tvb_get_guint8( tvb, offset ));
		offset += 1;
		/* When Bytes 2/3 are 0, then Bytes 4/5 defines the area as in classic 300/400 address mode
		 * when Bytes 2/3 = 8a0e then in bytes 4/5 contain the DB number
		 */
		tia_var_area1 = tvb_get_ntohs(tvb, offset);
		tia_var_area2 = tvb_get_ntohs(tvb, offset + 2);
		if (tia_var_area1 == 0) {
			proto_tree_add_text(item, tvb, offset, 4, "1200 sym Root area: %s", val_to_str(tia_var_area2, tia1200_var_item_area_names, "Unknown area: %u"));
			offset += 4;
		} else if (tia_var_area1 == 0x8a0e) {
			proto_tree_add_text(item, tvb, offset, 2, "1200 sym Root area DB: 0x%04x", tia_var_area1);
			offset += 2;
			proto_tree_add_text(item, tvb, offset, 2, "1200 sym Root DB number: %u", tia_var_area2);
			offset += 2;
		} else {
			proto_tree_add_text(item, tvb, offset, 2, "1200 sym Unknown Area 1: 0x%04x", tia_var_area1);
			offset += 2;
			proto_tree_add_text(item, tvb, offset, 2, "1200 sym Unknown Area 2: 0x%04x", tia_var_area2);
			offset += 2;
		}
		proto_tree_add_text(item, tvb, offset, 4, "1200 sym CRC: 0x%08x", tvb_get_ntohl(tvb, offset));
		offset += 4;

		for (i = 0; i < (var_spec_length - 10) / 4; i++) {
			/* Insert a new tree for every sub-struct */
			tia_struct_item = proto_tree_add_item( sub_tree, hf_s7comm_tia1200_substructure_item, tvb, offset, 4, FALSE );
			item = proto_item_add_subtree(tia_struct_item, ett_s7comm_param_item);
			tia_lid_flags = tvb_get_guint8( tvb, offset ) >> 4;
			proto_item_append_text(tia_struct_item, " [%d]: %s, Value: %lu", i + 1,
				val_to_str(tia_lid_flags, tia1200_var_lid_flag_names, "Unknown flags: 0x%02x"),
				(tvb_get_ntohl( tvb, offset ) & 0x0fffffff)				
			);			
			proto_tree_add_item(tia_struct_item, hf_s7comm_tia1200_var_lid_flags, tvb, offset, 1, FALSE);
			proto_tree_add_text(tia_struct_item, tvb, offset, 4, "Value     : %lu", tvb_get_ntohl( tvb, offset ) & 0x0fffffff);	
			
			offset += 4;
		}		
	}
	else {
		proto_tree_add_text(item, tvb, offset, 1, "Unknown variable specification", tvb_get_guint8( tvb, offset ));
		offset += var_spec_length - 1;
		proto_item_append_text(item, " Unknown variable specification");
	}
	return offset;
}

/*******************************************************************************************************
 *
 * Decode parameter part of a PDU for setup communication
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_pdu_setup_communication(tvbuff_t *tvb, 
									 proto_tree *tree, 
									 guint16 plength, 
									 guint32 offset )
{
	proto_tree_add_text(tree, tvb, offset, 1, "Reserved: 0x%02x", tvb_get_guint8( tvb, offset ));
	offset += 1;
	proto_tree_add_text(tree, tvb, offset, 2, "Max AmQ (parallel jobs with ack) calling: %d", tvb_get_ntohs( tvb, offset ));
	offset += 2;
	proto_tree_add_text(tree, tvb, offset, 2, "Max AmQ (parallel jobs with ack) called : %d", tvb_get_ntohs( tvb, offset ));
	offset += 2;

	proto_tree_add_item(tree, hf_s7comm_param_neg_pdu_length, tvb, offset, 2, FALSE);
	offset += 2;
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Write  -> Data part 
 * 
 *******************************************************************************************************/
static guint32
s7comm_decode_response_write_data(tvbuff_t *tvb, 
								 packet_info *pinfo, 
								 proto_tree *tree, 
								 guint16 dlength, 
								 guint8 item_count, 
								 guint32 offset)
{
	guint8 ret_val = 0;
	guint8 i = 0;
	proto_item *item = NULL;	
	proto_tree *item_tree = NULL;

	for (i = 1; i <= item_count; i++) {
		ret_val = tvb_get_guint8( tvb, offset );	
		/* Insert a new tree for every item */
		item = proto_tree_add_item( tree, hf_s7comm_data_item, tvb, offset, 1, FALSE );
		item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
		proto_item_append_text(item, " [%d]: (%s)", i, val_to_str(ret_val, item_return_valuenames, "Unknown code: 0x%02x"));
		proto_tree_add_uint(item_tree, hf_s7comm_item_return_value, tvb, offset, 1, ret_val);
		offset += 1;
	}
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Read  -> Data part 
 *           Request  -> Function Write -> Data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_response_read_data(tvbuff_t *tvb, 
								 packet_info *pinfo, 
								 proto_tree *tree, 
								 guint16 dlength, 
								 guint8 item_count, 
								 guint32 offset)
{
	guint8 ret_val = 0;
	guint8 tsize = 0;
	guint16 len = 0, len2 = 0;
	guint16 head_len = 4;	/* 1 byte res-code, 1 byte transp-size, 2 bytes len */	
	guint8 i = 0;
	proto_item *item = NULL;	
	proto_tree *item_tree = NULL;

	for (i = 1; i <= item_count; i++) {
		ret_val = tvb_get_guint8( tvb, offset );
		if (ret_val == S7COMM_ITEM_RETVAL_RESERVED || 
			ret_val == S7COMM_ITEM_RETVAL_DATA_OK || 
			ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
			) {
			tsize = tvb_get_guint8( tvb, offset + 1 );
			len = tvb_get_ntohs(tvb, offset + 2);
			/* calculate length in bytes */
			if (tsize >= 3 && tsize <= 5) {	/* given length is in number of bits */
				if (len % 8) { /* len is not a multiple of 8, then round up to next number */
					len /= 8;
					len = len + 1;
				} else {
					len /= 8;
				}
			}

			/* the PLC places extra bytes at the end of all but last result, if length is not a multiple of 2 */
			if ((len % 2) && (i < item_count)) {
				len2 = len + 1;
			} else {
				len2 = len;
			}
		}
		/* Insert a new tree for every item */
		item = proto_tree_add_item( tree, hf_s7comm_data_item, tvb, offset, len + head_len, FALSE );
		item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
		proto_item_append_text(item, " [%d]: (%s)", i, val_to_str(ret_val, item_return_valuenames, "Unknown code: 0x%02x"));

		proto_tree_add_uint(item_tree, hf_s7comm_item_return_value, tvb, offset, 1, ret_val);
		proto_tree_add_uint(item_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);	
		proto_tree_add_text(item_tree, tvb, offset + 2, 2 , "Data length: %d Bytes", len);

		offset += head_len;

		if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {		
			proto_tree_add_bytes(item_tree, hf_s7comm_readresponse_data, tvb, offset, len,
					tvb_get_ptr (tvb, offset, len));
			offset += len;			
			if (len != len2) {
					proto_tree_add_text(item_tree, tvb, offset, 1 , "Fill byte: 0x%02x", tvb_get_guint8( tvb, offset ));
					offset += 1;
			}
		}
	} 
	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x28 (PLC control functions)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex28(tvbuff_t *tvb, 
					  packet_info *pinfo, 
					  proto_tree *tree, 
					  guint16 plength,
					  guint32 offset,
					  guint8 rosctr)
{
	guint16 len;
	guint8 count;
	guint8 i;
	guint8 function;

	function = tvb_get_guint8( tvb, offset );
	offset += 1;

	/* First part is unknown */
	proto_tree_add_text(tree, tvb, offset, 7, "Unknown 7 bytes: 0x%02x%02x%02x%02x%02x%02x%02x", 
						tvb_get_guint8(tvb, offset),
						tvb_get_guint8(tvb, offset+1),
						tvb_get_guint8(tvb, offset+2),
						tvb_get_guint8(tvb, offset+3),
						tvb_get_guint8(tvb, offset+4),
						tvb_get_guint8(tvb, offset+5),
						tvb_get_guint8(tvb, offset+6));
	offset += 7;
	/* Part 1 */
	len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Length part 1: %d bytes", len);
	offset += 2;
	/* no block function, cold start e.g. */
	if (len == 2) {
		/* C = cold start */
		proto_tree_add_text(tree, tvb, offset,2, "Argument: %c%c", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset+1));
		offset +=2;
	} else if (len > 2) {
		count = tvb_get_guint8(tvb, offset);			/* number of blocks following */
		proto_tree_add_text(tree, tvb, offset, 1, "Number of blocks: %d", count);
		offset += 1;
		/* Next byte reserved? is 0x00 */
		offset += 1;
		for (i = 0; i < count; i++) {
			/* First byte of block type is every time '0' */
			proto_tree_add_text(tree, tvb, offset, 2, "Block type: %s", 
					val_to_str(tvb_get_guint8(tvb, offset+1), blocktype_names, "Unknown Block type: 0x%02x"));
			s7comm_info_append_str(pinfo, "Type", 
				val_to_str(tvb_get_guint8(tvb, offset+1), blocktype_names, "Unknown Block type: 0x%02x"));
			offset += 2;
			proto_tree_add_text(tree, tvb, offset , 5, "Block number: %s", tvb_get_ephemeral_string(tvb, offset, 5));
			s7comm_info_append_str(pinfo, "No.", tvb_get_ephemeral_string(tvb, offset, 5));
			offset += 5;
			/* 'P', 'B' or 'A' is following 
			 Destination filesystem?
				P = passive filesystem
				A = active filesystem?
			 */
			proto_tree_add_text(tree, tvb, offset,1, "Destination filesystem: %c", tvb_get_guint8(tvb, offset));
			offset += 1;
		}
	}
	/* Part 2 */
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Length part 2: %d bytes", len);
	offset += 1;
	/* Function (PI_SERVICE) as string  (program invocation)
		Known functions:
		_INSE = Activate a module
		_DELE = Delete a passive module
		_PROGRAM = Start/Stop the PLC
		_PLC_MEMORYRESET = Reset the PLC memory
	*/	
	proto_tree_add_text(tree, tvb, offset , len, "PI (program invocation) Service: %s", tvb_get_ephemeral_string(tvb, offset, len));
	offset += len;

	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x29 (PLC control functions -> STOP)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex29(tvbuff_t *tvb, 
					  packet_info *pinfo, 
					  proto_tree *tree, 
					  guint16 plength,
					  guint32 offset,
					  guint8 rosctr)
{
	guint8 len;
	guint8 function;

	function = tvb_get_guint8( tvb, offset );
	offset += 1;
	/* Meaning of first 5 bytes (Part 1) is unknown */
	proto_tree_add_text(tree, tvb, offset, 5, "Unknown 5 bytes: 0x%02x%02x%02x%02x%02x", 
						tvb_get_guint8(tvb, offset),
						tvb_get_guint8(tvb, offset+1),
						tvb_get_guint8(tvb, offset+2),
						tvb_get_guint8(tvb, offset+3),
						tvb_get_guint8(tvb, offset+4));
	offset += 5;
	
	/* Part 2 */
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Length part 2: %d bytes", len);
	offset += 1;
	/* Function as string */
	proto_tree_add_text(tree, tvb, offset , len, "PI (program invocation) Service: %s", tvb_get_ephemeral_string(tvb, offset, len));
	offset += len;

	return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f (block control functions)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex1x(tvbuff_t *tvb, 
					  packet_info *pinfo, 
					  proto_tree *tree, 
					  guint16 plength, 
					  guint32 offset,
					  guint8 rosctr)
{
	guint8 len;
	guint8 function;

	function = tvb_get_guint8( tvb, offset );
	offset += 1;

	/* Meaning of first 5 bytes is unknown */
	proto_tree_add_text(tree, tvb, offset, 7, "Unknown 7 bytes: 0x%02x%02x%02x%02x%02x%02x%02x", 
						tvb_get_guint8(tvb, offset),
						tvb_get_guint8(tvb, offset+1),
						tvb_get_guint8(tvb, offset+2),
						tvb_get_guint8(tvb, offset+3),
						tvb_get_guint8(tvb, offset+4),
						tvb_get_guint8(tvb, offset+5),
						tvb_get_guint8(tvb, offset+6));
	offset += 7;
	if (plength <= 8) {
		/* Upload or End upload functions have no other data */
		return offset;
	}

	/* Part 1: Block information*/
	len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Length part 1: %d bytes", len);
	offset += 1;
	/* Prefix
		File identifier:
		_ Bedeutet: "complete module"
		$ bedeutet: "Module header for up-loading"
	*/
	proto_tree_add_text(tree, tvb, offset, 1, "File identifier: %c", tvb_get_guint8(tvb, offset));
	offset += 1;
	/* First byte of block type is every time '0' */
	proto_tree_add_text(tree, tvb, offset, 2, "Block type: %s", 
		val_to_str(tvb_get_guint8(tvb, offset+1), blocktype_names, "Unknown Block type: 0x%02x"));
	s7comm_info_append_str(pinfo, "Type", 
		val_to_str(tvb_get_guint8(tvb, offset+1), blocktype_names, "Unknown Block type: 0x%02x"));
	offset += 2;

	proto_tree_add_text(tree, tvb, offset , 5, "Block number: %s", tvb_get_ephemeral_string(tvb, offset, 5));
	s7comm_info_append_str(pinfo, "No.", tvb_get_ephemeral_string(tvb, offset, 5));
	offset += 5;
	/* 'P', 'B' or 'A' is following */
	proto_tree_add_text(tree, tvb, offset,1, "Destination filesystem: %c", tvb_get_guint8(tvb, offset));
	offset += 1;
	
	/* Part 2, only available in "request download" */
	if (function == S7COMM_FUNCREQUESTDOWNLOAD && plength > 18) {
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1, "Length part 2: %d bytes", len);
		offset += 1;
		/* first byte unknown '1' */
		proto_tree_add_text(tree, tvb, offset, 1, "Unknown: %c", tvb_get_guint8(tvb, offset));
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 6, "Length load memory: %s bytes", tvb_get_ephemeral_string(tvb, offset, 6));
		offset += 6;
		proto_tree_add_text(tree, tvb, offset, 6, "Length MC7 code   : %s bytes", tvb_get_ephemeral_string(tvb, offset, 6));
		offset += 6;
	}
	return offset;
}

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
		val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"));
	s7comm_info_append_str(pinfo, "->", 
		val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x"));

	proto_item_append_text(param_tree, ": (%s)", val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"));
	proto_item_append_text(param_tree, " ->(%s)", val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x"));

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
		/* 1 Byte data unit reference. If packet is fragmented, all packets with this number belong together */
		proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunitref, tvb, offset_temp, 1, FALSE);
		offset_temp += 1;
		/* 1 Byte fragmented flag, if this is not the last data unit (telegram is fragmented) this is != 0 */
		proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunit, tvb, offset_temp, 1, FALSE);
		offset_temp += 1;
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
		 * decode only when there is a data part lenght greater 4 bytes
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
		case S7COMM_UD_SUBF_PROG_REQDIAGDATA1:
		case S7COMM_UD_SUBF_PROG_REQDIAGDATA2:
			/* start variable table or block online view */
			/* TODO: Can only handle requests/response, not the "following" telegrams because it's neccessary to correlate them
				with the previous request*/
			if (type != S7COMM_UD_TYPE_FOLLOW) {
				offset = s7comm_decode_ud_prog_reqdiagdata(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
				know_data = TRUE;
			}
			break;		
			
		case S7COMM_UD_SUBF_PROG_VARTAB1:
			/* online status in variable table */		
			data_type = tvb_get_guint8(tvb, offset+ 1);			/* 1 Byte const 0 + 1 Byte type: 0x14 = Request, 0x04 = Response */
			proto_tree_add_text(data_tree, tvb, offset, 2, "Type of data: %s (0x%02x)", 
						val_to_str(data_type, userdata_prog_vartab_type_names, "Unknown Type of data: 0x%02x"), data_type);
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
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Request diagnose data (0x13 or 0x01)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_reqdiagdata(tvbuff_t *tvb, 
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
	proto_item *item = NULL;
	proto_tree *item_tree = NULL;
	guint16 line_nr;
	guint16 line_cnt;
	guint16 ask_size;
	guint16 item_size = 4;
	guint8 registerflags;
	gchar str_flags[80];
	
	
	proto_tree_add_text(data_tree, tvb, offset, 2, "Ask header size: %d", tvb_get_ntohs(tvb, offset));
	offset += 2;
	ask_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(data_tree, tvb, offset, 2, "Ask size       : %d", ask_size);
	offset += 2;
	proto_tree_add_text(data_tree, tvb, offset, 6, "Unknown 6 bytes");
	offset += 6;
	proto_tree_add_text(data_tree, tvb, offset, 2, "Answer size    : %d", tvb_get_ntohs(tvb, offset));
	offset += 2;
	proto_tree_add_text(data_tree, tvb, offset, 12, "Unknown 13 bytes");
	offset += 13;	
	proto_tree_add_text(data_tree, tvb, offset, 1, "Block type     : %s", val_to_str(tvb_get_guint8(tvb, offset), subblktype_names, "Unknown Block type: 0x%02x"));
	offset += 1;
	proto_tree_add_text(data_tree, tvb, offset, 2, "Block number   : %d", tvb_get_ntohs(tvb, offset));
	offset += 2;
	proto_tree_add_text(data_tree, tvb, offset, 2, "Start address AWL: %d", tvb_get_ntohs(tvb, offset));
	offset += 2;
	proto_tree_add_text(data_tree, tvb, offset, 2, "Step address counter (SAZ): %d", tvb_get_ntohs(tvb, offset));
	offset += 2;
	proto_tree_add_text(data_tree, tvb, offset, 1, "Unknown byte   : 0x%02x", tvb_get_guint8(tvb, offset));
	offset += 1;
	if (subfunc == 0x13) {
		line_cnt = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(data_tree, tvb, offset, 1, "Number of lines: %d", line_cnt);
		offset += 1;
		proto_tree_add_text(data_tree, tvb, offset, 1, "Unknown byte   : 0x%02x", tvb_get_guint8(tvb, offset));
		offset += 1;
	} else {
		line_cnt = (ask_size - 2) / 2;
	}

	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_stw, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_accu1, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_accu2, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_ar1, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_ar2, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_db1, tvb, offset, 1, FALSE);
	proto_tree_add_item(data_tree, hf_s7comm_diagdata_registerflag_db2, tvb, offset, 1, FALSE);
	offset += 1;	
	
	if (subfunc == 0x13) {
		item_size = 4;
	} else {
		item_size = 2;
	}
	for (line_nr = 0; line_nr < line_cnt; line_nr++) {
	
		item = proto_tree_add_item( data_tree, hf_s7comm_data_item, tvb, offset, item_size, FALSE );
		item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
		if (subfunc == 0x13) {
			proto_tree_add_text(item_tree, tvb, offset, 2, "Address        : %d", tvb_get_ntohs(tvb, offset));
			offset += 2;
		}
		proto_tree_add_text(item_tree, tvb, offset, 1, "Unknown byte: 0x%02x", tvb_get_guint8(tvb, offset));
		offset += 1;

		registerflags = tvb_get_guint8(tvb, offset);
		make_registerflag_string(str_flags, registerflags, sizeof(str_flags));
		proto_item_append_text(item, " [%d]: (%s)", line_nr+1, str_flags);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_stw, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_accu1, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_accu2, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_ar1, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_ar2, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_db1, tvb, offset, 1, FALSE);
		proto_tree_add_item(item_tree, hf_s7comm_diagdata_registerflag_db2, tvb, offset, 1, FALSE);
		offset += 1;
	}
	
	return offset;
}
/* Generate a comma separated string for registerflags */
static void make_registerflag_string(gchar *str, guint8 flags, gint max)
{
	g_strlcpy(str, "", max);
	if (flags & 0x01) g_strlcat(str, "STW, ", max);
	if (flags & 0x02) g_strlcat(str, "ACCU1, ", max);
	if (flags & 0x04) g_strlcat(str, "ACCU2, ", max);
	if (flags & 0x08) g_strlcat(str, "AR1, ", max);
	if (flags & 0x10) g_strlcat(str, "AR2, ", max);
	if (flags & 0x20) g_strlcat(str, "DB1, ", max);
	if (flags & 0x40) g_strlcat(str, "DB2, ", max);
	if (strlen(str) > 2) 
		str[strlen(str) - 2 ] = '\0';
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
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB:
			proto_item_append_text(item, " (M%d.0 BYTE %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW:
			proto_item_append_text(item, " (M%d.0 WORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD:
			proto_item_append_text(item, " (M%d.0 DWORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB:
			proto_item_append_text(item, " (I%d.0 BYTE %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW:
			proto_item_append_text(item, " (I%d.0 WORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED:
			proto_item_append_text(item, " (I%d.0 DWORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB:
			proto_item_append_text(item, " (Q%d.0 BYTE %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW:
			proto_item_append_text(item, " (Q%d.0 WORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD:
			proto_item_append_text(item, " (Q%d.0 DWORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB:
			proto_item_append_text(item, " (PI%d.0 BYTE %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW:
			proto_item_append_text(item, " (PI%d.0 WORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED:
			proto_item_append_text(item, " (PI%d.0 DWORD %d)", bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB:
			proto_item_append_text(item, " (DB%d.DX%d.0 BYTE %d)", db, bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW:
			proto_item_append_text(item, " (DB%d.DX%d.0 WORD %d)", db, bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD:
			proto_item_append_text(item, " (DB%d.DX%d.0 DWORD %d)", db, bytepos, len);
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_T:
			proto_item_append_text(item, " (T %d", bytepos);
			if (len >1) 
				proto_item_append_text(item, "..%d)", bytepos + len -1);	/* it's possible to read multiple timers */
			else
				proto_item_append_text(item, ")");
			break;
		case S7COMM_UD_SUBF_PROG_VARTAB_AREA_C:
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

		if (tsize >= 4 && tsize <= 5) {
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

	proto_item_append_text(item, " [%d]: (%s)", item_no + 1, val_to_str(ret_val, item_return_valuenames, "Unknown code: 0x%02x"));
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
	guint32 offset_old;
	guint32 len_item;
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
					offset_old = offset;
					offset = s7comm_decode_param_item(tvb, offset, pinfo, data_tree, i);					
					/* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
					len_item = offset - offset_old;
					if ((len_item % 2) && (i < item_count)) {
						offset += 1;
					}					
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
	guint8 *pBlocknumber;
	guint16 blocknumber;
	guint8 blocktype;
	gboolean know_data = FALSE;
	proto_item *item = NULL;	
	proto_tree *item_tree = NULL;
	char str_timestamp[25];
	char str_number[10];

	switch (subfunc) {
		/*************************************************
		 * List blocks 
		 */
		case S7COMM_UD_SUBF_BLOCK_LIST:
			if (type == S7COMM_UD_TYPE_REQ) {					/*** Request ***/
				

			} else if (type == S7COMM_UD_TYPE_RES) {			/*** Response ***/						
				count = len / 4;
				for(i = 0; i < count; i++) {
					/* Insert a new tree of 4 byte length for every item */
					item = proto_tree_add_item( data_tree, hf_s7comm_data_item, tvb, offset, 4, FALSE );
					item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
					proto_item_append_text(item, " [%d]: (Block type %s)", i+1, val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));	
					proto_tree_add_text(item_tree, tvb, offset, 2, "Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					offset += 2;
					proto_tree_add_text(item_tree, tvb, offset, 2, "Count: %d", tvb_get_ntohs(tvb, offset));
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
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					proto_item_append_text(data_tree, ": (%s)", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					offset += 2;
				}
				know_data = TRUE;

			}else if (type == S7COMM_UD_TYPE_RES) {				/*** Response ***/	
				if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
					count = len / 4;
	
					for(i = 0; i < count; i++) {
						/* Insert a new tree of 4 byte length for every item */
						item = proto_tree_add_item( data_tree, hf_s7comm_data_item, tvb, offset, 4, FALSE );
						item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
						proto_item_append_text(item, " [%d]: (Block number %d)", i+1, tvb_get_ntohs(tvb, offset));					
						proto_tree_add_text(item_tree, tvb, offset, 2, "Block number   : %d", tvb_get_ntohs(tvb, offset));
						offset += 2;					
						/* The first Byte is unknown */						
						proto_tree_add_text(item_tree, tvb, offset, 1, "Unknown  flags : 0x%02x", tvb_get_guint8(tvb, offset));
						offset += 1;
						proto_tree_add_text(item_tree, tvb, offset, 1, "Block language : %s", 
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
					/* 8 Bytes of Data follow, 1./ 2. type, 3-7 blocknumber as ascii number */		
					proto_tree_add_text(data_tree, tvb, offset, 2, "Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));										
					proto_item_append_text(data_tree, ": (Block type: %s", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					/* Add block type and number to info column */
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(tvb_get_guint8(tvb, offset + 1), blocktype_names, "Unknown Block type: 0x%02x"));
					offset += 2;					
					pBlocknumber = tvb_get_ephemeral_string(tvb, offset, 5);
					proto_tree_add_text(data_tree, tvb, offset , 5, "Block number: %s", pBlocknumber);
					s7comm_info_append_str(pinfo, "No.", pBlocknumber);
					proto_item_append_text(data_tree, ", Number: %s)", pBlocknumber);
					offset += 5;
					proto_tree_add_text(data_tree, tvb, offset , 1, "Filesystem: '%c'", tvb_get_guint8(tvb, offset));
					offset += 1;
				}
				know_data = TRUE;

			}else if (type == S7COMM_UD_TYPE_RES) {				/*** Response ***/
				/* 78 Bytes */
				if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Const.          : 0x%02x", tvb_get_guint8(tvb, offset));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 1,	  "Block type      : %s", 
						val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
					offset += 1;
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Length of Info  : %d Bytes", tvb_get_ntohs(tvb, offset));
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
						val_to_str(tvb_get_guint8(tvb, offset), blocklanguage_names, "Unknown Block language: 0x%02x"));
					offset += 1;
					blocktype = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(data_tree, tvb, offset , 1,   "Subblk type     : %s",
						val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"));
					/* Add block type and number to info column */
					s7comm_info_append_str(pinfo, "Type", 
						val_to_str(blocktype, subblktype_names, "Unknown Block type: 0x%02x"));
					proto_item_append_text(data_tree, ": (Block type: %s", 
						val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"));
					offset += 1;
					blocknumber = tvb_get_ntohs(tvb, offset);
					proto_tree_add_text(data_tree, tvb, offset , 2,   "Block number    : %d", blocknumber);
					sprintf(str_number, "%05d", blocknumber);
					s7comm_info_append_str(pinfo, "No.", str_number);					
					proto_item_append_text(data_tree, ", Number: %05d)", blocknumber);
					offset += 2;
					/* "Length Load mem" -> the length in Step7 Manager seems to be this length +6 bytes */
					proto_tree_add_text(data_tree, tvb, offset , 4,	  "Length load mem.: %d bytes", tvb_get_ntohl(tvb, offset));
					offset += 4;
					proto_tree_add_text(data_tree, tvb, offset , 4,   "Block Security  : %s",
						val_to_str(tvb_get_ntohl(tvb, offset), blocksecurity_names, "Unknown block security: %ld"));
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
			if (type == S7COMM_UD_TYPE_RES) {					/*** Response ***/
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
