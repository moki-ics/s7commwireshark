/* packet-s7comm_plus.c
 *
 * Author:      Thomas Wiens, 2014 <th.wiens@gmx.de>
 * Version:     0.0.1
 * Description: Wireshark dissector for S7 Communication plus
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

/* #include <epan/dissectors/packet-wap.h>  Für variable length */

#include "packet-s7comm_plus.h"

#define PROTO_TAG_S7COMM_PLUS               "S7COMM-PLUS"

/* Min. telegram length for heuristic check */
#define S7COMMP_MIN_TELEGRAM_LENGTH	        4

/* Protocol identifier */
#define S7COMM_PLUS_PROT_ID                 0x72

/* Wireshark ID of the S7COMM_PLUS protocol */
static int proto_s7commp = -1;

/* Forward declaration */
static gboolean dissect_s7commp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

/**************************************************************************
 * PDU types 
 */
#define S7COMMP_PDUTYPE_1                   0x01
#define S7COMMP_PDUTYPE_2                   0x02
#define S7COMMP_PDUTYPE_3                   0x03
#define S7COMMP_PDUTYPE_4                   0x04
#define S7COMMP_PDUTYPE_FF                  0xff

static const value_string pdutype_names[] = {
    { S7COMMP_PDUTYPE_1,                    "Connect" },
    { S7COMMP_PDUTYPE_2,                    "Data" },
    { S7COMMP_PDUTYPE_3,                    "-3-" },
    { S7COMMP_PDUTYPE_4,                    "-4-" },
    { S7COMMP_PDUTYPE_FF,                   "Keep Alive" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Data telegramm Typen
 * Typen die ich schonmal gesehen habe sind nur mit der Nummer angegeben
 */
#define S7COMMP_DATATYPE_x05                0x05
#define S7COMMP_DATATYPE_REQ                0x31
#define S7COMMP_DATATYPE_RES                0x32
#define S7COMMP_DATATYPE_CYC                0x33
#define S7COMMP_DATATYPE_x88                0x88
#define S7COMMP_DATATYPE_xba                0xba

static const value_string datatype_names[] = {
    { S7COMMP_DATATYPE_x05,                 "? 0x05 ?" },
    { S7COMMP_DATATYPE_REQ,                 "Request " },
    { S7COMMP_DATATYPE_RES,                 "Response" },
    { S7COMMP_DATATYPE_CYC,                 "Cyclic  " },
    { S7COMMP_DATATYPE_x88,                 "? 0x88 ?" },
    { S7COMMP_DATATYPE_xba,                 "? 0xba ?" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Data Funktions-Typen für PDU Typ 1 (Connect)
 * 
 */
#define S7COMMP_PDU1_DATAFUNC_STARTSESSION  0x04ca

static const value_string pdu1_datafunc_names[] = {
    { S7COMMP_PDU1_DATAFUNC_STARTSESSION,   "Start session" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Data Funktions-Typen für PDU Typ 2 (Data)
 * 
 */

#define S7COMMP_PDU2_DATAFUNC_BLOCK         0x04ca      /* kommt z.B. bei Block Upload, aber auch sonst für alles */
#define S7COMMP_PDU2_DATAFUNC_ENDSESSION    0x04d4      /* kommt auch wenn zyklische Dienste an-/abgemeldet werden */
#define S7COMMP_PDU2_DATAFUNC_WRITE1        0x0542      /* kommt immer nach PDU1 connect, und wenn Variablen geschrieben werden */
#define S7COMMP_PDU2_DATAFUNC_READ1         0x054c      /* Allgemeines Read, für alles mögliche */

static const value_string pdu2_datafunc_names[] = {
    { S7COMMP_PDU2_DATAFUNC_BLOCK,          "Block1" },
    { S7COMMP_PDU2_DATAFUNC_ENDSESSION,     "End session" },
    { S7COMMP_PDU2_DATAFUNC_WRITE1,         "Write1" },
    { S7COMMP_PDU2_DATAFUNC_READ1,          "Read1" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Wert Datentypen in HMI Antworttelegrammen einer S7-1200
 * 
 */

/*** Binärzahlen **/
#define S7COMMP_ITEM_DATA_TYPE_BOOL         0x01        /* BOOL, Wert in 1 Byte */
/*** Ganzzahlen ohne Vorzeichen ***/
#define S7COMMP_ITEM_DATA_TYPE_USINT        0x02        /* USINT oder CHAR, Wert in 1 Byte */
#define S7COMMP_ITEM_DATA_TYPE_UINT         0x03        /* UINT, oder auch DATE, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_UDINT        0x04        /* UDint, TIME_OF_DAY, Wert in 4 Bytes, bzw. abhängig vom Wert da kann es aber noch ein Byte mehr sein*/
#define S7COMMP_ITEM_DATA_TYPE_ULINT        0x05        /* ULInt, bisher noch nicht gesehen TODO */
/* 0x05 = ULINT? */
/*** Ganzzahlen mit Vorzeichen ***/
#define S7COMMP_ITEM_DATA_TYPE_SINT         0x06        /* SINT, Wert in 1 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_INT          0x07        /* INT, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_DINT         0x08        /* DINT, Wert in 4 Byte, kommt auch bei erster Antwort von der SPS, auch für TIME */
#define S7COMMP_ITEM_DATA_TYPE_LINT         0x09        /* LInt, bisher noch nicht gesehen TODO */
/*** Bitfolgen ***/
#define S7COMMP_ITEM_DATA_TYPE_BYTE         0x0a        /* BYTE, Wert in 1 Byte */
#define S7COMMP_ITEM_DATA_TYPE_WORD         0x0b        /* WORD, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_DWORD        0x0c        /* DWORD, Wert in 4 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_LWORD        0x0d        /* LWORD, bisher noch nicht gesehen TODO */
/*** Gleitpunktzahlen ***/
#define S7COMMP_ITEM_DATA_TYPE_REAL         0x0e        /* REAL, Wert in 4 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_LREAL        0x0f        /* LREAL, Wert in 8 Bytes */


static const value_string item_data_type_names[] = {
    { S7COMMP_ITEM_DATA_TYPE_BOOL,          "Bool" },
    { S7COMMP_ITEM_DATA_TYPE_USINT,         "USInt" },
    { S7COMMP_ITEM_DATA_TYPE_UINT,          "UInt" },
    { S7COMMP_ITEM_DATA_TYPE_UDINT,         "UDInt" },
    { S7COMMP_ITEM_DATA_TYPE_ULINT,         "ULInt" },
    { S7COMMP_ITEM_DATA_TYPE_SINT,          "SInt" },
    { S7COMMP_ITEM_DATA_TYPE_INT,           "Int" },
    { S7COMMP_ITEM_DATA_TYPE_DINT,          "DInt" },
    { S7COMMP_ITEM_DATA_TYPE_LINT,          "LInt" },
    { S7COMMP_ITEM_DATA_TYPE_BYTE,          "Byte" },
    { S7COMMP_ITEM_DATA_TYPE_WORD,          "Word" },
    { S7COMMP_ITEM_DATA_TYPE_DWORD,         "DWord" },
    { S7COMMP_ITEM_DATA_TYPE_LWORD,         "LWORD" },
    { S7COMMP_ITEM_DATA_TYPE_REAL,          "Real" },
    { S7COMMP_ITEM_DATA_TYPE_LREAL,         "LReal" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Datatype IDs in Connect -> Session telegrams
 * 
 */
#define S7COMMP_SESS_TYPEID_ENDBYTE         0x00
#define S7COMMP_SESS_TYPEID_VARUINT32       0x04
#define S7COMMP_SESS_TYPEID_BINARRAY        0x02 // guessed, because this is followed by one byte length
#define S7COMMP_SESS_TYPEID_STRING          0x15
/* Why two dwords, maybe one is integer? */
#define S7COMMP_SESS_TYPEID_DWORD1          0xd3
#define S7COMMP_SESS_TYPEID_DWORD2          0x12

static const value_string sess_typeid_names[] = {
    { S7COMMP_SESS_TYPEID_ENDBYTE,          "Ending Byte" },
    { S7COMMP_SESS_TYPEID_VARUINT32,        "VarUInt32" },
    { S7COMMP_SESS_TYPEID_BINARRAY,         "Byte array with length" },
    { S7COMMP_SESS_TYPEID_STRING,           "String with length header" },
    { S7COMMP_SESS_TYPEID_DWORD1,           "DWORD 1" },
    { S7COMMP_SESS_TYPEID_DWORD2,           "DWORD 2" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Flags for LID access
 * ÄNDERUNGEN ZUM s7comm: Alle Werte um 2 verringert
 */
#define S7COMMP_VAR_ENCAPS_LID       0x0
#define S7COMMP_VAR_ENCAPS_IDX       0x1
#define S7COMMP_VAR_OBTAIN_LID       0x2
#define S7COMMP_VAR_OBTAIN_IDX       0x3
#define S7COMMP_VAR_PART_START       0x4
#define S7COMMP_VAR_PART_LEN         0x5

static const value_string var_lid_flag_names[] = {
    { S7COMMP_VAR_ENCAPS_LID,        "Encapsulated LID" },
    { S7COMMP_VAR_ENCAPS_IDX,        "Encapsulated Index" },
    { S7COMMP_VAR_OBTAIN_LID,        "Obtain by LID" },
    { S7COMMP_VAR_OBTAIN_IDX,        "Obtain by Index" },
    { S7COMMP_VAR_PART_START,        "Part Start Address" },
    { S7COMMP_VAR_PART_LEN,          "Part Length" },
    { 0,                                    NULL }
};

#define S7COMMP_VAR_ITEM_AREA1_DB    0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMMP_VAR_ITEM_AREA1_IQMCT 0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */

static const value_string var_item_area1_names[] = {
    { S7COMMP_VAR_ITEM_AREA1_DB,     "DB" },
    { S7COMMP_VAR_ITEM_AREA1_IQMCT,  "IQMCT" },
    { 0,                                    NULL }
};

#define S7COMMP_VAR_ITEM_AREA2_DB    0x8a0e
#define S7COMMP_VAR_ITEM_AREA2_I     0x50
#define S7COMMP_VAR_ITEM_AREA2_Q     0x51
#define S7COMMP_VAR_ITEM_AREA2_M     0x52
#define S7COMMP_VAR_ITEM_AREA2_C     0x53
#define S7COMMP_VAR_ITEM_AREA2_T     0x54

static const value_string var_item_area2_names[] = {
    { S7COMMP_VAR_ITEM_AREA2_I,      "Inputs (I)" },
    { S7COMMP_VAR_ITEM_AREA2_Q,      "Outputs (Q)" },
    { S7COMMP_VAR_ITEM_AREA2_M,      "Flags (M)" },
    { S7COMMP_VAR_ITEM_AREA2_C,      "Counter (C)" },
    { S7COMMP_VAR_ITEM_AREA2_T,      "Timer (T)" },
    { S7COMMP_VAR_ITEM_AREA2_DB,     "Datablock (DB)" },
    { 0,                                    NULL }
};

static const value_string var_item_area2_names_short[] = {
    { S7COMMP_VAR_ITEM_AREA2_I,      "I" },
    { S7COMMP_VAR_ITEM_AREA2_Q,      "Q" },
    { S7COMMP_VAR_ITEM_AREA2_M,      "M" },
    { S7COMMP_VAR_ITEM_AREA2_C,      "C" },
    { S7COMMP_VAR_ITEM_AREA2_T,      "T" },
    { S7COMMP_VAR_ITEM_AREA2_DB,     "DB" },
    { 0,                                    NULL }
};

#define S7COMMP_VAR_ITEM_BASE_AREA_IQMCT    0x0e98
#define S7COMMP_VAR_ITEM_BASE_AREA_DB       0x09f6
static const value_string var_item_base_area_names[] = {
    { S7COMMP_VAR_ITEM_BASE_AREA_IQMCT, "IQMCT" },
    { S7COMMP_VAR_ITEM_BASE_AREA_DB,    "DB" },
    { 0,                                    NULL }
};
/**************************************************************************
 **************************************************************************/
/* Header Block */
static gint hf_s7commp = -1;
static gint hf_s7commp_header = -1;
static gint hf_s7commp_header_protid = -1;              /* Header Byte  0 */
static gint hf_s7commp_header_pdutype = -1;             /* Header Bytes 1 */
static gint hf_s7commp_header_datlg = -1;               /* Header Bytes 2, 3*/

static gint hf_s7commp_data = -1;
static gint hf_s7commp_data_item_address = -1;
static gint hf_s7commp_data_item_value = -1;
static gint hf_s7commp_data_item_errorvalue = -1;
static gint hf_s7commp_data_data = -1;
static gint hf_s7commp_data_datatype = -1;
static gint hf_s7commp_data_unknown1 = -1;
static gint hf_s7commp_data_pdu1function = -1;
static gint hf_s7commp_data_unknown2 = -1;
static gint hf_s7commp_data_pdu2function = -1;
static gint hf_s7commp_data_requnknown1 = -1;
static gint hf_s7commp_data_sessionid = -1;
static gint hf_s7commp_data_seqnum = -1;

static gint hf_s7commp_data_item_type = -1;

static gint hf_s7commp_trailer = -1;
static gint hf_s7commp_trailer_protid = -1;
static gint hf_s7commp_trailer_pdutype = -1;
static gint hf_s7commp_trailer_datlg = -1;
static gint hf_s7commp_trailer_item = -1;

/* Read Response */
static gint hf_s7commp_data_req_set = -1;
static gint hf_s7commp_data_res_set = -1;

static gint hf_s7commp_data_request_id = -1;


/* These are the ids of the subtrees that we are creating */
static gint ett_s7commp = -1;                           /* S7 communication tree, parent of all other subtree */
static gint ett_s7commp_header = -1;                    /* Subtree for header block */
static gint ett_s7commp_param = -1;                     /* Subtree for parameter block */
static gint ett_s7commp_param_item = -1;                /* Subtree for items in parameter block */
static gint ett_s7commp_data = -1;                      /* Subtree for data block */
static gint ett_s7commp_data_item = -1;                 /* Subtree for an item in data block */
static gint ett_s7commp_trailer = -1;                   /* Subtree for trailer block */
static gint ett_s7commp_trailer_item = -1;              /* Subtree for item in trailer block */

static gint ett_s7commp_data_req_set = -1;              /* Subtree for data request set*/
static gint ett_s7commp_data_res_set = -1;              /* Subtree for data response set*/

static gint hf_s7commp_item_reserved1 = -1;              /* 1 Byte Reserved (always 0xff?) */
static gint hf_s7commp_item_area1 = -1;                  /* 2 Byte2 Root area (DB or IQMCT) */
static gint hf_s7commp_item_area2 = -1;                  /* 2 Bytes detail area (I/Q/M/C/T) */
static gint hf_s7commp_item_dbnumber = -1;               /* 2 Bytes DB number */
static gint hf_s7commp_item_crc = -1;                    /* 4 Bytes CRC */

static gint hf_s7commp_substructure_item = -1;           /* Substructure */
static gint hf_s7commp_var_lid_flags = -1;               /* LID Flags */
static gint hf_s7commp_var_lid_value = -1;

/* Register this protocol */
void
proto_reg_handoff_s7commp(void)
{
    static gboolean initialized = FALSE;
    if (!initialized) {
        heur_dissector_add("cotp", dissect_s7commp, proto_s7commp);
        initialized = TRUE;
    }
}

void
proto_register_s7commp (void)
{
    static hf_register_info hf[] = {
        /*** Header fields ***/
        { &hf_s7commp_header,
        { "Header", "s7comm-plus.header", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the header of S7 communication plus", HFILL }},
        { &hf_s7commp_header_protid,
        { "Protocol Id", "s7comm-plus.header.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Protocol Identification", HFILL }},
        { &hf_s7commp_header_pdutype,
        { "PDU-Type", "s7comm-plus.header.pdutype", FT_UINT8, BASE_HEX, VALS(pdutype_names), 0x0,
          "Type of packet", HFILL }},
        { &hf_s7commp_header_datlg,
        { "Data length", "s7comm-plus.header.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the data block in bytes", HFILL }},         
        
        /*** Fields in data part ***/
        { &hf_s7commp_data,
        { "Data", "s7comm-plus.data", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the data part of S7 communication plus", HFILL }},

        { &hf_s7commp_data_item_address,
        { "Item Address", "s7comm-plus.data.item_address", FT_NONE, BASE_NONE, NULL, 0x0,
          "Address of one Item", HFILL }},
        { &hf_s7commp_data_item_value,
        { "Item Value", "s7comm-plus.data.item_value", FT_NONE, BASE_NONE, NULL, 0x0,
          "Value of one item", HFILL }},
        
        { &hf_s7commp_data_item_errorvalue,
        { "Item Error Value", "s7comm-plus.data.item_errorvalue", FT_NONE, BASE_NONE, NULL, 0x0,
          "Value for error codes of one item", HFILL }},
          
        { &hf_s7commp_data_data,
        { "Data unknown", "s7comm-plus.data.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Data unknown", HFILL }},
          
        { &hf_s7commp_data_datatype,
        { "Type of data", "s7comm-plus.data.datatype", FT_UINT8, BASE_HEX, VALS(datatype_names), 0x0,
          "Type of data packet", HFILL }},
        
        { &hf_s7commp_data_unknown1,
        { "Unknown 1", "s7comm-plus.data.unknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Unknown 1, Reserved? Seems that this is always 0x0000, but not in 'cyclic' telegrams", HFILL }},
        
        { &hf_s7commp_data_pdu1function,
        { "Function? ", "s7comm-plus.data.pdu1function", FT_UINT16, BASE_HEX, VALS(pdu1_datafunc_names), 0x0,
          "Function for PDUs of type 1", HFILL }},
        
        { &hf_s7commp_data_unknown2,
        { "Unknown 2", "s7comm-plus.data.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Unknown 2, Reserved? Seems that this is always 0x0000, but not in 'cyclic' telegrams", HFILL }},
          
        { &hf_s7commp_data_pdu2function,
        { "Function? ", "s7comm-plus.data.pdu2function", FT_UINT16, BASE_HEX, VALS(pdu2_datafunc_names), 0x0,
          "Function for PDUs of type 2", HFILL }},
          
        { &hf_s7commp_data_sessionid,
        { "Session Id", "s7comm-plus.data.sessionid", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Session Id, negotiated on session start", HFILL }},
        
        { &hf_s7commp_data_seqnum,
        { "Sequence number", "s7comm-plus.data.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Sequence number (for reference)", HFILL }},
        
        { &hf_s7commp_data_requnknown1,
        { "Req. Unknown 1", "s7comm-plus.data.requnknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Request Unknown 1, don't know what this is", HFILL }},
         
        /*** Trailer fields ***/
        { &hf_s7commp_trailer,
        { "Trailer", "s7comm-plus.trailer", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the trailer part of S7 communication plus", HFILL }},
        { &hf_s7commp_trailer_item,
        { "Trailer", "s7comm-plus.traileritem", FT_BYTES, BASE_NONE, NULL, 0x0,
          "This is the trailer part of S7 communication plus", HFILL }},
        { &hf_s7commp_trailer_protid,
        { "Protocol Id", "s7comm-plus.trailer.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Protocol Identification", HFILL }},
        { &hf_s7commp_trailer_pdutype,
        { "PDU-Type", "s7comm-plus.trailer.pdutype", FT_UINT8, BASE_HEX, VALS(pdutype_names), 0x0,
          "Type of packet", HFILL }},
        { &hf_s7commp_trailer_datlg,
        { "Data length", "s7comm-plus.trailer.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the data block in bytes", HFILL }},

        /* Data */
        { &hf_s7commp_data_item_type,
        { "Datatype", "s7comm-plus.data.item.type", FT_UINT8, BASE_HEX, VALS(item_data_type_names), 0x0,
          "Type of data following", HFILL }},
          
        
        { &hf_s7commp_data_req_set,
        { "Request Set", "s7comm-plus.data.req_set", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is a set of data in a request telegram", HFILL }}, 
        { &hf_s7commp_data_res_set,
        { "Response Set", "s7comm-plus.data.res_set", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is a set of data in a response telegram", HFILL }},
          
        { &hf_s7commp_data_request_id,
        { "Request ID", "s7comm-plus.data.request_id", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Request ID, Length is variable", HFILL }},
        
        
        /* TIA Portal stuff */
        { &hf_s7commp_item_reserved1,
        { "1200 sym Reserved", "s7comm.tiap.item.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7commp_item_area1,
        { "1200 sym root area 1", "s7comm.tiap.item.area1", FT_UINT16, BASE_HEX, VALS(var_item_area1_names), 0x0,
          "Area from where to read: DB or Inputs, Outputs, etc.", HFILL }},
        { &hf_s7commp_item_area2,
        { "1200 sym root area 2", "s7comm.tiap.item.area2", FT_UINT16, BASE_HEX, VALS(var_item_area2_names), 0x0,
          "Specifies the area from where to read", HFILL }},
        { &hf_s7commp_item_dbnumber,
        { "1200 sym root DB number", "s7comm.tiap.item.dbnumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7commp_item_crc,
        { "1200 sym CRC", "s7comm.tiap.item.crc", FT_UINT32, BASE_HEX, NULL, 0x0,
          "CRC generated out of symbolic name with (x^32+x^31+x^30+x^29+x^28+x^26+x^23+x^21+x^19+x^18+x^15+x^14+x^13+x^12+x^9+x^8+x^4+x+1)", HFILL }},        
        { &hf_s7commp_var_lid_flags,
        { "LID flags", "s7comm.tiap.item.lid_flags", FT_UINT8, BASE_DEC, VALS(var_lid_flag_names), 0x0,
          NULL, HFILL }},          
        { &hf_s7commp_substructure_item,
        { "Substructure", "s7comm.tiap.item.substructure", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7commp_var_lid_value,
        { "LID Value", "s7comm.tiap.item.lid_value", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_s7commp,
        &ett_s7commp_header,
        &ett_s7commp_param,
        &ett_s7commp_param_item,
        &ett_s7commp_data,
        &ett_s7commp_data_item,
        &ett_s7commp_trailer,
        &ett_s7commp_trailer_item,
        &ett_s7commp_data_req_set,
        &ett_s7commp_data_res_set
    };

    proto_s7commp = proto_register_protocol (
            "S7 Communication Plus",            /* name */
            "S7COMM-PLUS",                      /* short name */
            "s7comm-plus"                       /* abbrev */
            );

    proto_register_field_array(proto_s7commp, hf, array_length (hf));
    
    proto_register_subtree_array(ett, array_length (ett));
}
/*******************************************************************************************************
 *
 * Spezial gepacktes Datenformat
 * siehe: http://en.wikipedia.org/wiki/Variable-length_quantity
 *
 * In der Datei packet-wap.c gibt es eine Funktion für unsigned:
 * guint tvb_get_guintvar (tvbuff_t *tvb, guint offset, guint *octetCount)
 * welche aber keine Begrenzung auf eine max-Anzahl hat (5 für int32).
 * Solange das Protokoll noch nicht sicher erkannt wird, ist diese Version hier sicherer.
 *
 *******************************************************************************************************/
guint32
tvb_get_varint32(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint32 val = 0;
    guint8 octet;
    guint8 cont;

    for (counter = 1; counter <= 4+1; counter++) {        /* große Werte benötigen 5 Bytes */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        if ((counter == 1) && (octet & 0x40)) {   /* Vorzeichen prüfen */
            octet &= 0xbf;
            val = 0xffffffc0; /* pre-load with one complement, excluding first 6 bits, TODO: endianess for other processors? */
        } else {
            val <<= 7;
        }
        cont = (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    return val;
}
/*******************************************************************************************************/
guint32
tvb_get_varuint32(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint32 val = 0;
    guint8 octet;
    guint8 cont;
    for (counter = 1; counter <= 4+1; counter++) {        /* große Werte benötigen 5 Bytes */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 7;
        cont= (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    return  val;
}
/*******************************************************************************************************
 *
 * Connect -> Request -> Start session
 * pass auch für response
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_connect_req_startsession(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 offset)
{
    guint32 start_offset;
    guint32 uint32val = 0;
    guint8 str_length = 0;
    guint8 octet_count = 0;
    int item_nr = 1;
    
    guint32 id_number = 0;
    guint8 type_of_id_value = 0;
    gboolean unknown_type_occured = FALSE;
    
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    
    /* 16 Bytes unbekannt */
    proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 16, tvb_get_ptr(tvb, offset, 16));
    offset += 16;
    
    /* Einlesen bis ID 0xa2a200 */
    do {
        start_offset = offset;
        
        data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
        data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
    
        /* 4 Bytes ID?? */
        id_number = tvb_get_ntohl(tvb, offset);
        proto_tree_add_text(data_item_tree, tvb, offset, 4, "ID Number: 0x%08x", id_number);
        offset += 4;
        
        proto_item_append_text(data_item_tree, " [%d]: ID: 0x%08x", item_nr, id_number);
        
        /* 1 Byte Typkennung */
        type_of_id_value = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(data_item_tree, tvb, offset, 1, "Type ID: %s (0x%02x)", 
            val_to_str(type_of_id_value, sess_typeid_names, "Unknown Type ID: 0x%02x"), type_of_id_value);
        offset += 1;

        switch (type_of_id_value) {
            /***************** TEST ****************************/
            case 0x17:
                /* 3 byte Werte? test */
                proto_tree_add_text(data_item_tree, tvb, offset, 3, "Value: 0x%02x%02x%02x", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset+1), tvb_get_guint8(tvb, offset+2));
                proto_item_append_text(data_item_tree, " => 0x%02x%02x%02x", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset+1), tvb_get_guint8(tvb, offset+2));
                offset += 3;
                break;
        
        
        
            case S7COMMP_SESS_TYPEID_ENDBYTE:       /* 0x00 */
                /* Leeres byte als Ende-Kennung? */
                proto_tree_add_text(data_item_tree, tvb, offset, 1, "Value: 0x%02x", tvb_get_guint8(tvb, offset));
                proto_item_append_text(data_item_tree, " => 0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                break;
            case S7COMMP_SESS_TYPEID_VARUINT32:          /* 0x04 */
                /* Es folgt ein var uint */
                uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_text(data_item_tree, tvb, offset, octet_count, "Value: 0x%08x", uint32val);
                proto_item_append_text(data_item_tree, " => 0x%08x", uint32val);
                offset += octet_count;
                break;
            case S7COMMP_SESS_TYPEID_BINARRAY: // 0x02
                /* Es folgt ein String mit vorab einem Byte für die Stringlänge */
                str_length = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(data_item_tree, tvb, offset, 1, "String length: %d", tvb_get_guint8(tvb, offset));
                offset += 1;
                proto_tree_add_text(data_item_tree, tvb, offset, str_length, "Value: %s", tvb_format_text(tvb, offset, str_length));
                proto_item_append_text(data_item_tree, " => %s", tvb_format_text(tvb, offset, str_length));
                offset += str_length;
                break;
            case S7COMMP_SESS_TYPEID_STRING:        /* 0x15 */
                /* Es folgt ein String mit vorab einem Byte für die Stringlänge */
                str_length = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(data_item_tree, tvb, offset, 1, "String length: %d", tvb_get_guint8(tvb, offset));
                offset += 1;
                proto_tree_add_text(data_item_tree, tvb, offset, str_length, "Value: %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, str_length, ENC_ASCII));
                proto_item_append_text(data_item_tree, " => %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, str_length, ENC_ASCII));
                offset += str_length;
                break;
            case S7COMMP_SESS_TYPEID_DWORD1:        /* 0xd3 */
                /* Es folgen vier Bytes */
                proto_tree_add_text(data_item_tree, tvb, offset, 4, "Value: 0x%08x", tvb_get_ntohl(tvb, offset));
                proto_item_append_text(data_item_tree, " => 0x%08x", tvb_get_ntohl(tvb, offset));
                offset += 4;
                break; 
            case S7COMMP_SESS_TYPEID_DWORD2:        /* 0x12 */
                /* Es folgen vier Bytes */
                proto_tree_add_text(data_item_tree, tvb, offset, 4, "Value: 0x%08x", tvb_get_ntohl(tvb, offset));
                proto_item_append_text(data_item_tree, " => 0x%08x", tvb_get_ntohl(tvb, offset));
                offset += 4;
                break;
            default:
                /* Unbekannt Typen, erstmal abbrechen */
                proto_item_append_text(data_item_tree, " => TODO! CANT DECODE THIS, BREAK DISSECTION.");
                unknown_type_occured = TRUE;
                break;
        }
        item_nr++;
        
        proto_item_set_len(data_item_tree, offset - start_offset);
        
    } while ((unknown_type_occured == FALSE) && (id_number != 0xa2a20000) && (id_number != 0x00a20000));
    
    return offset;
}

/*******************************************************************************************************
 *
 * Eine einzelne Variablen-Adresse einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_address(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 *number_of_fields,
                                  guint32 offset)
{
    proto_item *adr_item = NULL;
    proto_tree *adr_item_tree = NULL;
    
    guint8 octet_count = 0;
    guint32 value = 0;
    guint32 crc = 0;
    guint16 tia_var_area1 = 0;
    guint16 tia_var_area2 = 0;
    guint32 tia_lid_nest_depth = 0;
    guint32 tia_lid_cnt = 0;
    guint32 tia_value = 0;
    guint32 offset_at_start = offset;
    
    *number_of_fields = 0;
    
    adr_item = proto_tree_add_item(tree, hf_s7commp_data_item_address, tvb, offset, -1, FALSE);
    adr_item_tree = proto_item_add_subtree(adr_item, ett_s7commp_data_item);
    
    /**************************************************************
     * CRC als varuint
     */
    crc = tvb_get_varuint32(tvb, &octet_count, offset);
    offset += octet_count;
    proto_tree_add_text(adr_item_tree, tvb, offset - octet_count, octet_count, "Symbol CRC: 0x%08x", crc);
    proto_item_append_text(adr_item_tree, ": SYM-CRC=%08x", crc);
        
    *number_of_fields += 1;
    /**************************************************************
     * Area 52=Merker usw.
     * when Bytes 2/3 == 0x8a0e then bytes 4/5 are containing the DB number
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);
    offset += octet_count;
    /* Area ausmaskieren */
    tia_var_area1 = (value >> 16); 
    tia_var_area2 = (value & 0xffff);      
    if (tia_var_area1 == S7COMMP_VAR_ITEM_AREA1_IQMCT) {            
        proto_tree_add_text(adr_item_tree, tvb, offset - octet_count, octet_count, "Accessing Area: %s", val_to_str(tia_var_area2, var_item_area2_names, "Unknown IQMCT Area: 0x%04x"));
        proto_item_append_text(adr_item_tree, ", LID=%s", val_to_str(tia_var_area2, var_item_area2_names_short, "Unknown IQMCT Area: 0x%04x"));
    } else if (tia_var_area1 == S7COMMP_VAR_ITEM_AREA1_DB) {
        proto_tree_add_text(adr_item_tree, tvb, offset - octet_count, octet_count, "Accessing Area: Datablock, DB-Number: %d", tia_var_area2);
        proto_item_append_text(adr_item_tree, ", LID=DB%d", tia_var_area2);
    } else {
        proto_tree_add_text(adr_item_tree, tvb, offset - octet_count, octet_count, "Unknown Area: 0x%04x / 0x%04x", tia_var_area1, tia_var_area2);
        proto_item_append_text(adr_item_tree, " Unknown Area 0x%04x / 0x%04x", tia_var_area1, tia_var_area2);
    }        
    
    *number_of_fields += 1;
    
    /**************************************************************
     * LID Nesting Depth
     *
     * 0x01: Merker                 Folgende LIDs: 1
     * 0x02: DB.VAR                 Folgende LIDs: 1
     * 0x03: DB.STRUCT.VAR          Folgende LIDs: 2
     * 0x03: DB.ARRAY[INDEX]        Folgende LIDs: 2
     * 0x04: DB.STRUCT.STRUCT.VAR   Folgende LIDs: 3
     */
    tia_lid_nest_depth = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_text(adr_item_tree, tvb, offset, octet_count, "LID Nesting depth: %u", tia_lid_nest_depth);     
    offset += octet_count;
    *number_of_fields += 1;
    
    /**************************************************************
     * Nochmal Angabe des Speicherbereichs.
     * Bei Merkern scheint hier 0xe98 zu stehen, bei DBs 0x9f6
     * Es gibt noch weitere Bereiche, deren Bedeutung z.Zt. unbekannt ist (Systemdaten? äquivalent zu bisherigen SZL?)
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);        
    proto_tree_add_text(adr_item_tree, tvb, offset, octet_count, "LID Access Area (Nesting level 1): %s", val_to_str(value, var_item_base_area_names, "Unknown Area: 0x%08x"));
    offset += octet_count;
    
    *number_of_fields += 1;
    
    /**************************************************************
     * LID pro Nest-Level
     * 
     */
    for (tia_lid_cnt = 2; tia_lid_cnt <= tia_lid_nest_depth; tia_lid_cnt++) {        
        value = tvb_get_varuint32(tvb, &octet_count, offset); 
        proto_tree_add_text(adr_item_tree, tvb, offset, octet_count, "LID Value (Nesting Level %d): %u", tia_lid_cnt, value);
        proto_item_append_text(adr_item_tree, ".%u", value);
        offset += octet_count;            
        *number_of_fields += 1;
    }
    proto_item_set_len(adr_item_tree, offset - offset_at_start);    
    return offset;
}
/*******************************************************************************************************
 *
 * Ein einzelner Variablen-Wert einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_value(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    
    guint8 octet_count = 0;
    guint8 item_number;
    guint8 datatype;
    guint8 datatype_flags;
    
    guint32 uint32val = 0;
    guint16 uint16val = 0;
    gint16 int16val = 0;
    gint32 int32val = 0;
    guint8 uint8val = 0;
    gint8 int8val = 0;
    gchar str_val[512];
    
    /* Datatype string */
    guint32 string_completelength = 0;
    guint8 string_maxlength = 0;
    guint8 string_actlength = 0;
        
    guint32 offset_at_start = offset;
    guint32 item_start_offset = 0;
    guint32 length_of_value = 0;
    
    item_start_offset = offset;    
    
    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, item_start_offset, -1, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);

    item_number = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 1, "Item Number: %d", item_number);
    offset += 1;

    datatype_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 1, "Datatype Flags: 0x%02x", datatype_flags);
    offset += 1;

    datatype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_data_item_type, tvb, offset, 1, datatype);
    offset += 1;

    switch (datatype) {
        /************************** Binärzahlen **************************/
        case S7COMMP_ITEM_DATA_TYPE_BOOL:
            /* 0x00 oder 0x01 */
            length_of_value = 1;
            g_snprintf(str_val, sizeof(str_val), "0x%02x", tvb_get_guint8(tvb, offset));
            offset += 1;
            break;
            /************************** Ganzzahlen ohne Vorzeichen **************************/   
        case S7COMMP_ITEM_DATA_TYPE_USINT:
            /* Dieser Typ wird auch zur Übertragung von Strings verwendet. Dann steht in den
             * Flags der Wert 0x10, andernfalls 0x00.
             * Bei Strings folgt:
             * - ein als varuint gepackter Wert, die Gesamtlänge des Satzes plus string-Header
             * - Ein Byte Maximallänge
             * - Ein Byte Aktuallänge
             * Dann die Bytes, Anzahl aus Maximallänge
             */
            if (datatype_flags == 0x10) 
            {
                length_of_value = 0;
                /* Ein als varuint gepackter Wert, die Gesamtlänge des Satzes plus string-Header */
                string_completelength = tvb_get_varuint32(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value += octet_count;
                /* 1 Byte Maximallänge */
                string_maxlength = tvb_get_guint8(tvb, offset);
                offset += 1;
                length_of_value += 1;
                /* 1 Byte Aktuallänge */
                string_actlength =  tvb_get_guint8(tvb, offset);
                offset += 1;
                length_of_value += 1;
                /* Und der eigentliche string */                        
                g_snprintf(str_val, sizeof(str_val), "STRING Complete Length: %u, MaxLen: %d, ActLen: %d, Text: %s", 
                    string_completelength, string_maxlength, string_actlength,
                    tvb_get_string(wmem_packet_scope(), tvb, offset, string_maxlength));
                
                offset += string_maxlength;
                length_of_value += string_maxlength;
                
            } else {
                length_of_value = 1;
                g_snprintf(str_val, sizeof(str_val), "%u", tvb_get_guint8(tvb, offset));
                offset += 1;
            }
            break;
        case S7COMMP_ITEM_DATA_TYPE_UINT:
            length_of_value = 2;
            g_snprintf(str_val, sizeof(str_val), "%u", tvb_get_ntohs(tvb, offset));
            offset += 2;
            break;
        case S7COMMP_ITEM_DATA_TYPE_UDINT:                    
            uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
            offset += octet_count;
            length_of_value = octet_count;
            g_snprintf(str_val, sizeof(str_val), "%u", uint32val);
            break;    
/* TODO ULINT */

        /************************** Ganzzahlen mit Vorzeichen **************************/
        case S7COMMP_ITEM_DATA_TYPE_SINT:
            uint8val = tvb_get_guint8(tvb, offset);
            memcpy(&int8val, &uint8val, sizeof(int8val));
            length_of_value = 1;
            g_snprintf(str_val, sizeof(str_val), "%d", int8val);
            offset += 1;
            break;
        case S7COMMP_ITEM_DATA_TYPE_INT:
            uint16val = tvb_get_ntohs(tvb, offset);
            memcpy(&int16val, &uint16val, sizeof(int16val));
            length_of_value = 2;
            g_snprintf(str_val, sizeof(str_val), "%d", int16val);
            offset += 2;
            break;
        case S7COMMP_ITEM_DATA_TYPE_DINT:
            int32val = tvb_get_varint32(tvb, &octet_count, offset);
            offset += octet_count;
            length_of_value = octet_count;
            g_snprintf(str_val, sizeof(str_val), "%d", int32val);
            break;
/* TODO LINT */
        /************************** Bitfolgen **************************/    
        case S7COMMP_ITEM_DATA_TYPE_BYTE:
            length_of_value = 1;
            g_snprintf(str_val, sizeof(str_val), "0x%02x", tvb_get_guint8(tvb, offset));
            offset += 1;
            break;
        case S7COMMP_ITEM_DATA_TYPE_WORD:
            length_of_value = 2;
            g_snprintf(str_val, sizeof(str_val), "0x%04x", tvb_get_ntohs(tvb, offset));
            offset += 2;
            break;
        case S7COMMP_ITEM_DATA_TYPE_DWORD:
            length_of_value = 4;
            g_snprintf(str_val, sizeof(str_val), "0x%08x", tvb_get_ntohl(tvb, offset));
            offset += 4;
            break;
/* TODO LWORD */
        /************************** Gleitpunktzahlen **************************/
        case S7COMMP_ITEM_DATA_TYPE_REAL:
            length_of_value = 4;
            g_snprintf(str_val, sizeof(str_val), "%f", tvb_get_ntohieee_float(tvb, offset));
            offset += 4;
            break;
        case S7COMMP_ITEM_DATA_TYPE_LREAL:
            length_of_value = 4;
            g_snprintf(str_val, sizeof(str_val), "%f", tvb_get_ntohieee_double(tvb, offset));
            offset += 8;
            break;
        /**************************  ***************************/
        default:
            /* zur Zeit unbekannter Typ, muss abgebrochen werden solange der Aufbau nicht bekannt */
            g_strlcpy(str_val, "Unknown Type", sizeof(str_val));
            break;
    }
    proto_item_set_len(data_item_tree, length_of_value + 3);
    
    proto_tree_add_text(data_item_tree, tvb, item_start_offset + 3, length_of_value, "Value: %s", str_val);    
    proto_item_append_text(data_item_tree, " [%d]: (%s) = %s", item_number, val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), str_val);

    return offset;
}
/*******************************************************************************************************
 *
 * Ein Fehler-Variablenwert einer 1200
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_errorvalue(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    
    guint8 item_number;
    guint8 datatype_flags;
    
    guint32 errorvalue1 = 0;
    guint32 errorvalue2 = 0;
    
    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_errorvalue, tvb, offset, 10, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);

    item_number = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 1, "Item Number: %d", item_number);
    offset += 1;
            
    /* Byte nach Item-Nummer: Ist dieses ein Standard Datentyp ist hier immer 0x00
     * bei Strings steht hier 0x10, und als Datentyp hat ein String 0x02=USint
     * 
     * Steht hier ein 0xc0, dann ist es ein Fehlertelegramm und es folgen
     * Zwei Varuint mit Fehlercode.
     */
    datatype_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 1, "Datatype Flags: 0x%02x", datatype_flags);
    offset += 1;
    ////////////////////////////////////////////////////////////////////////////////////////////
    errorvalue1 = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 4, "Errorvalue 1: 0x%08x dez %d", errorvalue1, errorvalue1);
    offset += 4;

    errorvalue2 = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(data_item_tree, tvb, offset, 4, "Errorvalue 2: 0x%08x dez %d", errorvalue2, errorvalue2);
    offset += 4;
    
    proto_item_append_text(data_item_tree, " [%d]: Error values: 0x%08x/0x%08x", item_number, errorvalue1, errorvalue2);

    return offset;
}
/*******************************************************************************************************
 *
 * Write-Request zu einer Variablen-Anfrage bei einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data_request_write(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint16 dlength,
                                  guint32 offset)
{
    guint8 item_count = 0;
    guint8 number_of_fields_in_complete_set = 0;
    guint8 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    
    /* Wenn die ersten 4 Bytes 0x00, dann ist es ein 'normaler' Schreib-Befehl
     * Es kann sein dass hier die Session-ID steht, dann ist der Aufbau anders
     */
    value = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Unknown: 0x%08x", value);
    offset += 4;
    
    if (value == 0x00) {    
        item_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Item Count: %u", item_count);
        offset += 1;

        number_of_fields_in_complete_set = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Number of Fields in complete Item-Dataset: %u", number_of_fields_in_complete_set);
        offset += 1;

        for (i = 1; i <= item_count; i++) {      
            offset = s7commp_decode_item_address(tvb, tree, &number_of_fields, offset);        
            number_of_fields_in_complete_set -= number_of_fields;
            /* Eigentlicher Wert */
            offset = s7commp_decode_item_value(tvb, tree, offset);
            
        }
        /* 27 byte unbekannt */
        proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 27, tvb_get_ptr(tvb, offset, 27));
        offset += 27;
    
    } else {
        proto_tree_add_text(tree, tvb, offset-4, 4, "Different Write Request with first value !=0 : 0x%08x. TODO", value);
    }
    
    return offset;
}
/*******************************************************************************************************
 *
 * Read-Request zu einer Variablen-Anfrage bei einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data_request_read(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint16 dlength,
                                  guint32 offset)
{    
    guint8 item_count = 0;
    guint8 number_of_fields_in_complete_set = 0;
    guint8 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    
    /* für Variablen-Lesen müssen die ersten 4 Bytes 0 sein 
     * Bei einer Variablentabelle steht dort z.b. 0x00000020
     */
    value = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Unknown: 0x%08x", value);
    offset += 4;
    if (value == 0x0) {        
        item_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Item Count: %u", item_count);
        offset += 1;

        number_of_fields_in_complete_set = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Number of Fields in complete Item-Dataset: %u", number_of_fields_in_complete_set);
        offset += 1;
        
        for (i = 1; i <= item_count; i++) {        
            offset = s7commp_decode_item_address(tvb, tree, &number_of_fields, offset);        
            number_of_fields_in_complete_set -= number_of_fields;
        }
        /* 27 byte unbekannt */
        proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 27, tvb_get_ptr(tvb, offset, 27));
        offset += 27;
    } else {
         proto_tree_add_text(tree, tvb, offset-4, 4, "Different Read Request with first value != 0: 0x%08x. TODO", value);    
    }
    
    return offset;
}
/*******************************************************************************************************
 *
 * Read-Response zu eier Variablen-Anfrage bei einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data_response_read(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint16 dlength,
                                  guint32 offset)
{
    guint8 first_response_byte;
    guint8 item_number;
    guint8 octet_count = 0;
    guint8 in_error_set = 0;
    
    guint32 offset_at_start = offset;
    guint32 uint32val = 0;
    gint32 int32val = 0;
    
    first_response_byte = tvb_get_guint8(tvb, offset);
    /* Wenn kein Fehler bei einem Item, kommt als erstes ein 0x00 und dann die Item-Werte
     *
     * Bei Fehler (Vermutung):
     * Tritt ein Fehler auf, ist das erste Byte 0x90 (oder ungleich 0x00)
     * Dann folgen zwei varint Werte (vermutlich).
     * Dann folgen die Items die mit Erfolg gelesen werden konnten.
     * Dann folgt ein Byte mit 0x00
     * Dann folgt Fehlerdatensatz pro Item:
     *  - Itemnummer
     *  - Dann 9 Bytes (oder eine Anzahl varuint??)
     *  - Dann entweder die nächste Itemnummer, oder wenn 0x00 dann Ende.
     *
     */
    proto_tree_add_text(tree, tvb, offset, 1, "Result (0x00 when all Items OK): 0x%02x", first_response_byte);
    offset += 1;
    if (first_response_byte != 0x00) {
        /******* Erste zwei Werte bei Fehler ******/
        //uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 1: 0x%08x : %d", int32val, int32val);
        offset += octet_count;
        
        //uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 2: 0x%08x : %d", int32val, int32val);
        offset += octet_count;
    }
        
    /********** Items die OK sind ********/
    item_number = tvb_get_guint8(tvb, offset);
    /* Den einzelnen Items folgen auf jeden Fall immer noch 6 Null-Bytes 
     * Bzw. nur 5 Null-Bytes, wenn vorher ein 0x00 als Trenner zum Fehlerdatensatz eingefügt wurde.
     * Evtl. lässt sich dieses vereinheitlichen.
     */
    do {
        item_number = tvb_get_guint8(tvb, offset);
        
        /* Dieses ist die nächste Item Nummer
         * ACHTUNG!
         * Gibt es einen Fehlerdatensatz, so wird mit den Items begonnen, dann folgt
         * als Trennung ein Byte 0x00 und dann die Items mit den Fehlerdaten
         */
        if ((item_number == 0x00) && (in_error_set == 0x00)) {  /* && (first_response_byte != 0x00) */
            proto_tree_add_text(tree, tvb, offset, 1, "End marker for good values (bad values with error code may follow): 0x%02x", item_number);
            in_error_set = 1;
            offset += 1;
            item_number = tvb_get_guint8(tvb, offset);
        }
        /* Wenn jetzt trotzdem noch ein 0x00 folgt, dann ist Ende */
        if (item_number == 0) {
            break;
        }    
        
        
        offset_at_start = offset;
        if (in_error_set == 0x00) {
            offset = s7commp_decode_item_value(tvb, tree, offset);
        } else {
            offset = s7commp_decode_item_errorvalue(tvb, tree, offset);
        }
        
        /* Fehler abfangen, falls das nicht funktioniert */
        if (offset - offset_at_start >= dlength) break;
        
    } while (item_number != 0x00);
    
    return offset;
}
/*******************************************************************************************************
 *******************************************************************************************************
 *
 * S7-Protocol plus (main tree)
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static gboolean
dissect_s7commp(tvbuff_t *tvb, 
                packet_info *pinfo, 
                proto_tree *tree, 
                void *data _U_)
{
    proto_item *s7commp_item = NULL;
    proto_item *s7commp_sub_item = NULL;
    proto_tree *s7commp_tree = NULL;
    proto_item *item = NULL;
    
    proto_tree *s7commp_header_tree = NULL;
    proto_tree *s7commp_data_tree = NULL;
    proto_tree *s7commp_data_item_tree = NULL;
    proto_tree *s7commp_trailer_tree = NULL;
    proto_tree *item_tree = NULL;
    
    proto_tree *data_tree = NULL;

    guint32 offset = 0;
    guint32 offset_save = 0;

    guint8 pdutype = 0;
    guint8 hlength = 4;
    guint8 datatype = 0;
    guint8 bRes = 0;
    guint8 item_number = 0;
    guint16 plength = 0;
    guint16 dlength = 0;
    guint16 seqnum = 0;
    guint16 function = 0;
    gboolean has_trailer;
    
    guint32 uint32val = 0;
    guint16 uint16val = 0;
    gint16 int16val = 0;
    gint32 int32val = 0;
    guint8 uint8val = 0;
    gint8 int8val = 0;
    
    guint16 packetlength;

    packetlength = tvb_length(tvb);
    /*----------------- Heuristic Checks - Begin */
    /* 1) check for minimum length */
    if (packetlength < S7COMMP_MIN_TELEGRAM_LENGTH) {
        return 0;
    }
    /* 2) first byte must be 0x72 */
    if ( tvb_get_guint8(tvb, 0) != S7COMM_PLUS_PROT_ID ) {
        return 0;
    }        
    /*----------------- Heuristic Checks - End */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM_PLUS);
    col_clear(pinfo->cinfo, COL_INFO);

    pdutype = tvb_get_guint8( tvb, 1 );                     /* Get the type byte */
    hlength = 4;                                            /* Header 4 Bytes */

    /* display some infos in info-column of wireshark */
    col_add_fstr(pinfo->cinfo, COL_INFO, "PDU-Type: [%s]", val_to_str(pdutype, pdutype_names, "PDU-Type: 0x%02x"));
    
    if (tree) {
        s7commp_item = proto_tree_add_item(tree, proto_s7commp, tvb, 0, -1, FALSE);
        s7commp_tree = proto_item_add_subtree(s7commp_item, ett_s7commp);
        
        /******************************************************
         * 4 Bytes Header
         ******************************************************/
         
        /* insert header tree */
        s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_header, tvb, offset, hlength, FALSE );
        /* insert sub-items in header tree */
        s7commp_header_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_header);
        
        proto_item_append_text(s7commp_header_tree, ", PDU-Type: %s", val_to_str(pdutype, pdutype_names, ", PDU-Type: 0x%02x"));       
        
        /* 1: Protocol Identifier, constant 0x72 */
        proto_tree_add_item(s7commp_header_tree, hf_s7commp_header_protid, tvb, offset, 1, FALSE);
        offset += 1;
        
        /* 2: Type */
        proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_pdutype, tvb, offset, 1, pdutype);
        offset += 1;
        
        /* Typ FF Pakete scheinen eine Art Keep-Alive Telegramme zu sein. Diese sind nur 4 Bytes lang
         * 1. Protocol-id, 2.PDU Typ und dann 3. eine Art sequenz-Nummer, und das 4. Byte bisher immer 0
         */
        if (pdutype == S7COMMP_PDUTYPE_FF) {
            seqnum = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(s7commp_header_tree, hf_s7commp_data_seqnum, tvb, offset, 1, seqnum);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Seq.num: [%d]", seqnum);
            offset += 1;
            /* dann noch ein Byte, noch nicht klar wozu */
            proto_tree_add_text(s7commp_header_tree, tvb, offset , 1, "Reserved? : 0x%02x", tvb_get_guint8(tvb, offset));
            offset += 1;
        } else {
        /* 3/4: Data length */
        dlength = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_datlg, tvb, offset, 2, dlength);
        offset += 2;
        
        /* Paket hat einen Trailer, wenn nach der angegebenen Datenlänge noch 4 Bytes übrig bleiben */
        has_trailer = packetlength > (dlength + 4);
            
        /******************************************************
         * data part
         ******************************************************/
        
        /* insert data tree */
        s7commp_sub_item = proto_tree_add_item( s7commp_tree, hf_s7commp_data, tvb, offset, dlength, FALSE );
        /* insert sub-items in data tree */
        s7commp_data_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_data);
        
        /* Prüfen ob das erste Byte eine bekannte Kennung hat */
        
        /* Ich weiß nicht ob das richtig ist ein Paket anhand dieser Kennung zu prüfen!
         * Es ist möglich dass Pakete über mehrere PDUs fragmentiert übertragen werden:
         * Dabei hat das erste Paket keinen trailer, aber den Data-Header.
         * Die mittleren Pakete besitzen keinen Data-Header und auch keinen Trailer.
         * Das letzte Paket besitzt keinen Data-Header, aber einen Trailer.
         *
         * Wenn die Prüfung so wie sie jetzt hier programmiert ist funktionieren soll, wären im
         * ersten Byte des Data-Teils die zu überprüfenden Bytes nicht erlaubt. 
         * Das ist aber wahrscheinlich nicht der Fall. So wie es aussieht ist das Byte ganz normal
         * im Datenstrom, sodass die Erkennung so wie sie jetzt programmiert ist nur
         * zufällig funktioniert.
         * Um das in Wireshark zu erkennen, müsste man sich Informationen von vorigen Paketen "merken"
         * und dann in folgenden Paketen kombinieren.
         * Da habe ich aber noch keine Idee wie man das in Wireshark umsetzen kann.
         * Man müsste nicht beendete Telegramme anhand der Sequenznummern (und IP/Port) auf einen Stack für "offene PDUs" legen.
         * Erst mit dem Endtelegramm werden diese wieder vom Stack gelöscht.
         */
        
        /* 1: Kennung*? */
        datatype = tvb_get_guint8(tvb, offset);
        
        proto_item_append_text(s7commp_data_tree, ", Type of data: %s", val_to_str(datatype, datatype_names, "Unknown type of data: 0x%02x"));  
        
        if ((datatype == S7COMMP_DATATYPE_REQ) || (datatype == S7COMMP_DATATYPE_RES) || (datatype == S7COMMP_DATATYPE_CYC)) {
            /* 1: Kennung*? */
            proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_datatype, tvb, offset, 1, datatype);
            /* add type to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " Type of data: [%s]", val_to_str(datatype, datatype_names, "Unknown type of data: 0x%02x"));
            offset += 1;
            dlength -= 1;
        
            /* 2/3: Reserve? bisher immer null */            
            proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_unknown1, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            dlength -= 2;
            
            /* 4/5: Funktionscode? */
            function = tvb_get_ntohs(tvb, offset);
            
            /* Funktionsbezeichnung in Abhängigkeit vom PDU Typ */
            if (pdutype == S7COMMP_PDUTYPE_1) {
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_pdu1function, tvb, offset, 2, function);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Function: [0x%04x - %s]", function, 
                    val_to_str(function, pdu1_datafunc_names, "?"));
            } else if (pdutype == S7COMMP_PDUTYPE_2) {
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_pdu2function, tvb, offset, 2, function);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Function: [0x%04x - %s]", function, 
                    val_to_str(function, pdu2_datafunc_names, "?"));
            } else {
                proto_tree_add_text(s7commp_data_tree, tvb, offset , 2, "Function: 0x%04x", function);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Function: [0x%04x]", function);
            }
            offset += 2;
            dlength -= 2;
            
            /* 6/7: Reserve? bisher immer null */
            proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_unknown2, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            dlength -= 2;
        
            /* 8/9: Sequenz-Nummer für die Referenzierung Request/Response, bei zyklischen Daten steht hier immer Null */
            seqnum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_seqnum, tvb, offset, 2, seqnum);
            /*if (datatype != S7COMMP_DATATYPE_CYC) { */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%d", seqnum);
            /*}*/
            offset += 2;
            dlength -= 2;
        }
        
        
        
        /* Der Inhalt im Datenteil ist abhängig vom PDU Typ
         * Hier ein paar Dinge testen.
         * Später sollten diese in eigene Unterfunktionen zerlegt werden.
         */
        
        if (pdutype == S7COMMP_PDUTYPE_1) {        /* 1 - Connect */
            if (((datatype == S7COMMP_DATATYPE_REQ) || (datatype == S7COMMP_DATATYPE_RES)) && (function == S7COMMP_PDU1_DATAFUNC_STARTSESSION)) {

                offset_save = offset;
                offset = s7commp_decode_connect_req_startsession(tvb, s7commp_data_tree, offset);
                dlength = dlength - (offset - offset_save);
            }        
        
        } else if (pdutype == S7COMMP_PDUTYPE_2) {                     /* 2 - Data */
            if (datatype == S7COMMP_DATATYPE_REQ) {             /* Request */
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_requnknown1, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
                dlength -= 2;
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_sessionid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
                dlength -= 2;
                proto_tree_add_text(s7commp_data_tree, tvb, offset , 1,   "Req. Typ 2? : 0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                dlength -= 1;
                
                
                if (function == S7COMMP_PDU2_DATAFUNC_READ1) {
                    item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_req_set, tvb, offset, -1, FALSE);
                    item_tree = proto_item_add_subtree(item, ett_s7commp_data_req_set);
                    offset_save = offset;
                    offset = s7commp_decode_data_request_read(tvb, item_tree, dlength, offset);
                    proto_item_set_len(item_tree, offset - offset_save);
                    dlength = dlength - (offset - offset_save);                    
                } else if (function == S7COMMP_PDU2_DATAFUNC_WRITE1) {
                    /* Ein HMI Write-Request hat in den 4 Bytes nach dem 0x34 normalerweise 0x0000.
                     * Beim ersten Write-Request nach dem Verbindungsaufbau, steht hier die Session-Id, und der
                     * Aufbau des Datensatzes ist anders. 
                     * TODO: Außerhalb Abfangen!
                     */
                    item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_req_set, tvb, offset, -1, FALSE);
                    item_tree = proto_item_add_subtree(item, ett_s7commp_data_req_set);
                    offset_save = offset;
                    offset = s7commp_decode_data_request_write(tvb, item_tree, dlength, offset);
                    proto_item_set_len(item_tree, offset - offset_save);
                    dlength = dlength - (offset - offset_save); 
                }
                
            } else if (datatype == S7COMMP_DATATYPE_RES) {      /* Response */
                proto_tree_add_text(s7commp_data_tree, tvb, offset , 1,   "Res. Typ 2? : 0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                dlength -= 1;
                
                
                /* Testweise ein Antworttelegramm von der SPS einer HMI-Anfrage 
                 * Passt aber nur bei einer 1200
                 * Die 1500 scheint schon wieder alles anders zu machen
                 * So wie es aussieht gibt es verschiedene Datenformate für den Austausch, was wohl am Anfang der
                 * Session ausgehandelt wird. 
                 */
                if (function == S7COMMP_PDU2_DATAFUNC_READ1) {
                    item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_res_set, tvb, offset, -1, FALSE);
                    item_tree = proto_item_add_subtree(item, ett_s7commp_data_res_set);
                    
                    offset_save = offset;
                    offset = s7commp_decode_data_response_read(tvb, item_tree, dlength, offset);
                    proto_item_set_len(item_tree, offset - offset_save);
                    dlength = dlength - (offset - offset_save);                    
                }
            }
        }           
         
        /* Alles was noch fehlt als Hex anzeigen */
        if (dlength > 0) {
            proto_tree_add_bytes(s7commp_data_tree, hf_s7commp_data_data, tvb, offset, dlength, tvb_get_ptr(tvb, offset, dlength));
            offset += dlength;
        }
        
        /******************************************************
         * Trailer
         * 4 Bytes Anhängsel mit 0x72, Typecode wie im Header, und folgende 0x00 0x00
         * Es gibt Pakete die über mehrere Telegramme gehe, da fehlt dieser Part
         ******************************************************/
        
        if (has_trailer) {
            /* insert trailer tree */
            s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_trailer, tvb, offset, 4, FALSE );
            /* insert sub-items in data tree */
            s7commp_trailer_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_trailer);
  
            /* 1: Protocol Identifier, constant 0x32 */
            proto_tree_add_item(s7commp_trailer_tree, hf_s7commp_trailer_protid, tvb, offset, 1, FALSE);
            offset += 1;
        
            /* 2: PDU Type */
            proto_tree_add_uint(s7commp_trailer_tree, hf_s7commp_trailer_pdutype, tvb, offset, 1, tvb_get_guint8( tvb, offset));
            proto_item_append_text(s7commp_trailer_tree, ", PDU-Type: %s", val_to_str(tvb_get_guint8( tvb, offset), pdutype_names, ", PDU-Type: 0x%02x"));  
            offset += 1;
        
            /* 3/4: Data length, hier immer 0 */
            proto_tree_add_uint(s7commp_trailer_tree, hf_s7commp_trailer_datlg, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
        }
        }
    }
    return TRUE;
}
