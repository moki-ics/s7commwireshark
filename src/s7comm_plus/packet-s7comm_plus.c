/* packet-s7comm_plus.c
 *
 * Author:      Thomas Wiens, 2014 <th.wiens@gmx.de>
 * Description: Wireshark dissector for S7 Communication plus
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

/* Length of trailing block within read and write requests */
#define RW_REQUEST_TRAILER_LEN 27

/* Max number of array values displays on Item-Value tree. */
#define S7COMMP_ITEMVAL_ARR_MAX_DISPLAY     10

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
#define S7COMMP_DATATYPE_RES2               0x02    /* V13 HMI bei zyklischen Daten, dann ist in dem Request Typ2=0x74 anstatt 0x34 */

static const value_string datatype_names[] = {
    { S7COMMP_DATATYPE_x05,                 "? 0x05 ?" },
    { S7COMMP_DATATYPE_REQ,                 "Request " },
    { S7COMMP_DATATYPE_RES,                 "Response" },
    { S7COMMP_DATATYPE_CYC,                 "Cyclic  " },
    { S7COMMP_DATATYPE_x88,                 "? 0x88 ?" },
    { S7COMMP_DATATYPE_xba,                 "? 0xba ?" },
    { S7COMMP_DATATYPE_RES2,                "Response2" },
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
#define S7COMMP_PDU2_DATAFUNC_WRITE         0x0542      /* kommt immer nach PDU1 connect, und wenn Variablen geschrieben werden */
#define S7COMMP_PDU2_DATAFUNC_READ          0x054c      /* Allgemeines Read, für alles mögliche */
#define S7COMMP_PDU2_DATAFUNC_WATCHTABLE12  0x0071      /* Werteübertragung in einer Beobachtungstabelle bei einer 1200 */

static const value_string pdu2_datafunc_names[] = {
    { S7COMMP_PDU2_DATAFUNC_BLOCK,          "Block" },
    { S7COMMP_PDU2_DATAFUNC_ENDSESSION,     "End session" },
    { S7COMMP_PDU2_DATAFUNC_WRITE,          "Write" },
    { S7COMMP_PDU2_DATAFUNC_READ,           "Read" },
    { S7COMMP_PDU2_DATAFUNC_WATCHTABLE12,   "Watch table data 1200" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Wert Datentypen in HMI Antworttelegrammen
 *
 */

/*** Binärzahlen **/
#define S7COMMP_ITEM_DATA_TYPE_BOOL         0x01        /* BOOL, Wert in 1 Byte */
/*** Ganzzahlen ohne Vorzeichen ***/
#define S7COMMP_ITEM_DATA_TYPE_USINT        0x02        /* USINT oder CHAR, Wert in 1 Byte */
#define S7COMMP_ITEM_DATA_TYPE_UINT         0x03        /* UINT, oder auch DATE, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_UDINT        0x04        /* UDint, TIME_OF_DAY, Wert in 4 Bytes, bzw. abhängig vom Wert da kann es aber noch ein Byte mehr sein*/
#define S7COMMP_ITEM_DATA_TYPE_ULINT        0x05        /* ULInt, Wert in varuint64 */
/*** Ganzzahlen mit Vorzeichen ***/
#define S7COMMP_ITEM_DATA_TYPE_SINT         0x06        /* SINT, Wert in 1 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_INT          0x07        /* INT, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_DINT         0x08        /* DINT, Wert in 4 Byte, kommt auch bei erster Antwort von der SPS, auch für TIME */
#define S7COMMP_ITEM_DATA_TYPE_LINT         0x09        /* LInt, Wert in varint64 */
/*** Bitfolgen ***/
#define S7COMMP_ITEM_DATA_TYPE_BYTE         0x0a        /* BYTE, Wert in 1 Byte */
#define S7COMMP_ITEM_DATA_TYPE_WORD         0x0b        /* WORD, Wert in 2 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_DWORD        0x0c        /* DWORD, Wert in 4 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_LWORD        0x0d        /* LWORD, Wert in 8 Bytes */
/*** Gleitpunktzahlen ***/
#define S7COMMP_ITEM_DATA_TYPE_REAL         0x0e        /* REAL, Wert in 4 Bytes */
#define S7COMMP_ITEM_DATA_TYPE_LREAL        0x0f        /* LREAL, Wert in 8 Bytes */
/*** Spezial ***/
#define S7COMMP_ITEM_DATA_TYPE_IEC_COUNTER  0x10
#define S7COMMP_ITEM_DATA_TYPE_IEC_LTIMER   0x11

/**************************************************************************
 * Datatype IDs in Connect -> Session telegrams
 * appear in the start session request/response and within the write after start session
 */
#define S7COMMP_ITEM_DATA_TYPE_NULL         0x00
#define S7COMMP_SESS_TYPEID_STRING          0x15
#define S7COMMP_TYPEID_STRUCT               0x17
/* Why two dwords, maybe one is integer? */
#define S7COMMP_SESS_TYPEID_DWORD1          0xd3
#define S7COMMP_SESS_TYPEID_DWORD2          0x12

#define S7COMMP_ITEM_DATA_TYPE_3BYTE        0x14    /* unknown meaning, 3 bytes long */


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
    { S7COMMP_ITEM_DATA_TYPE_IEC_COUNTER,   "IEC Counter" },
    { S7COMMP_ITEM_DATA_TYPE_IEC_LTIMER,    "IEC LTimer" },
    { S7COMMP_ITEM_DATA_TYPE_NULL,          "Null" },
    { S7COMMP_SESS_TYPEID_STRING,           "String with length header" },
    { S7COMMP_TYPEID_STRUCT,                "Struct" },
    { S7COMMP_SESS_TYPEID_DWORD1,           "DWORD 1" },
    { S7COMMP_SESS_TYPEID_DWORD2,           "DWORD 2" },
    { S7COMMP_ITEM_DATA_TYPE_3BYTE,         "3Byte" },
    { 0,                                    NULL }
};

/* Datatype flags */
#define S7COMMP_DATATYPE_FLAG_ARRAY         0x10
#define S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY 0x20

/**************************************************************************
 * There are IDs which values can be read or be written to.
 * This is some kind of operating system data/function for the plc.
 * The IDs seem to be unique for all telegrams in which they occur.
 * Add the datatype for this value in parentheses.
 */
static const value_string id_number_names[] = {
    { 573673,                       "Cyclic variables subscription name (String with length header)" },
    { 574488,                       "Cyclic variables update set of addresses (UDInt, Addressarray)" },
    { 574489,                       "Cyclic variables update rate (UDInt, in milliseconds)" },
    { 0,                            "NULL" }
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
    { 0,                             NULL }
};

#define S7COMMP_VAR_ITEM_AREA1_DB    0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMMP_VAR_ITEM_AREA1_IQMCT 0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */

static const value_string var_item_area1_names[] = {
    { S7COMMP_VAR_ITEM_AREA1_DB,     "DB" },
    { S7COMMP_VAR_ITEM_AREA1_IQMCT,  "IQMCT" },
    { 0,                             NULL }
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
    { 0,                             NULL }
};

static const value_string var_item_area2_names_short[] = {
    { S7COMMP_VAR_ITEM_AREA2_I,      "I" },
    { S7COMMP_VAR_ITEM_AREA2_Q,      "Q" },
    { S7COMMP_VAR_ITEM_AREA2_M,      "M" },
    { S7COMMP_VAR_ITEM_AREA2_C,      "C" },
    { S7COMMP_VAR_ITEM_AREA2_T,      "T" },
    { S7COMMP_VAR_ITEM_AREA2_DB,     "DB" },
    { 0,                             NULL }
};

#define S7COMMP_VAR_ITEM_BASE_AREA_IQMCT    0x0e98
#define S7COMMP_VAR_ITEM_BASE_AREA_DB       0x09f6
static const value_string var_item_base_area_names[] = {
    { S7COMMP_VAR_ITEM_BASE_AREA_IQMCT, "IQMCT" },
    { S7COMMP_VAR_ITEM_BASE_AREA_DB,    "DB" },
    { 0,                                NULL }
};
/**************************************************************************
 **************************************************************************/
/* Header Block */
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

static gint hf_s7commp_trailer = -1;
static gint hf_s7commp_trailer_protid = -1;
static gint hf_s7commp_trailer_pdutype = -1;
static gint hf_s7commp_trailer_datlg = -1;
static gint hf_s7commp_trailer_item = -1;

/* Read Response */
static gint hf_s7commp_data_req_set = -1;
static gint hf_s7commp_data_res_set = -1;

static gint hf_s7commp_data_id_number = -1;


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

static gint ett_s7commp_itemaddr_area = -1;             /* Subtree for item address area */
static gint ett_s7commp_itemval_array = -1;             /* Subtree if item value is an array */

/* Item Address */
static gint hf_s7commp_item_count = -1;
static gint hf_s7commp_item_no_of_fields = -1;
static gint hf_s7commp_itemaddr_crc = -1;
static gint hf_s7commp_itemaddr_area = -1;
static gint hf_s7commp_itemaddr_area1 = -1;
static gint hf_s7commp_itemaddr_area2 = -1;
static gint hf_s7commp_itemaddr_dbnumber = -1;
static gint hf_s7commp_itemaddr_lid_nesting_depth = -1;
static gint hf_s7commp_itemaddr_base_area = -1;
static gint hf_s7commp_itemaddr_lid_value = -1;

/* Item Value */
static gint hf_s7commp_itemval_itemnumber = -1;
static gint hf_s7commp_itemval_datatype_flags = -1;
static gint hf_s7commp_itemval_datatype_flags_array = -1;       /* 0x10 for array */
static gint hf_s7commp_itemval_datatype_flags_address_array = -1;       /* 0x20 for address-array */
static gint hf_s7commp_itemval_datatype_flags_0x90unkn = -1;    /* 0x90 unknown, seen in S7-1500 */
static gint ett_s7commp_itemval_datatype_flags = -1;
static const int *s7commp_itemval_datatype_flags_fields[] = {
    &hf_s7commp_itemval_datatype_flags_array,
    &hf_s7commp_itemval_datatype_flags_address_array,
    &hf_s7commp_itemval_datatype_flags_0x90unkn,
    NULL
};
static gint hf_s7commp_itemval_datatype = -1;
static gint hf_s7commp_itemval_arraysize = -1;
static gint hf_s7commp_itemval_value = -1;

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
          { "Function", "s7comm-plus.data.pdu1function", FT_UINT16, BASE_HEX, VALS(pdu1_datafunc_names), 0x0,
            "Function for PDUs of type 1", HFILL }},

        { &hf_s7commp_data_unknown2,
          { "Unknown 2", "s7comm-plus.data.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Unknown 2, Reserved? Seems that this is always 0x0000, but not in 'cyclic' telegrams", HFILL }},

        { &hf_s7commp_data_pdu2function,
          { "Function", "s7comm-plus.data.pdu2function", FT_UINT16, BASE_HEX, VALS(pdu2_datafunc_names), 0x0,
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

        { &hf_s7commp_data_req_set,
          { "Request Set", "s7comm-plus.data.req_set", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a set of data in a request telegram", HFILL }},
        { &hf_s7commp_data_res_set,
          { "Response Set", "s7comm-plus.data.res_set", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a set of data in a response telegram", HFILL }},

        { &hf_s7commp_data_id_number,
          { "ID Number", "s7comm-plus.data.id_number", FT_UINT32, BASE_DEC, VALS(id_number_names), 0x0,
            "varuint32: ID Number for function", HFILL }},

        /* Item Address */
        { &hf_s7commp_item_count,
          { "Item Count", "s7comm-plus.item.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of items following", HFILL }},
        { &hf_s7commp_item_no_of_fields,
          { "Number of fields in complete Item-Dataset", "s7comm-plus.item.no_of_fields", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of fields in complete Item-Dataset", HFILL }},
        { &hf_s7commp_itemaddr_crc,
          { "Symbol CRC", "s7comm-plus.item.addr.symbol_crc", FT_UINT32, BASE_HEX, NULL, 0x0,
            "CRC generated out of symbolic name with (x^32+x^31+x^30+x^29+x^28+x^26+x^23+x^21+x^19+x^18+x^15+x^14+x^13+x^12+x^9+x^8+x^4+x+1)", HFILL }},
        { &hf_s7commp_itemaddr_area,
          { "Accessing area", "s7comm-plus.item.addr.area", FT_UINT32, BASE_HEX, NULL, 0x0,
            "varuint32: Specifies the area where to read from, DB, Inputs, Outputs, Flags, etc.", HFILL }},
        { &hf_s7commp_itemaddr_area1,
          { "Accessing area", "s7comm-plus.item.addr.area1", FT_UINT16, BASE_HEX, VALS(var_item_area1_names), 0x0,
            "Area from where to read: DB or Inputs, Outputs, etc.", HFILL }},
        { &hf_s7commp_itemaddr_area2,
          { "Accessing area", "s7comm-plus.item.addr.area2", FT_UINT16, BASE_HEX, VALS(var_item_area2_names), 0x0,
            "Specifies the area from where to read", HFILL }},
        { &hf_s7commp_itemaddr_dbnumber,
          { "DB number", "s7comm-plus.item.addr.dbnumber", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_itemaddr_lid_nesting_depth,
          { "LID Nesting depth", "s7comm-plus.item.addr.lid_nesting_depth", FT_UINT8, BASE_DEC, NULL, 0x0,
            "varuint32: LID Nesting depth", HFILL }},
        { &hf_s7commp_itemaddr_base_area,
          { "LID Access base area (Nesting level 1)", "s7comm-plus.item.addr.base_area", FT_UINT16, BASE_HEX, VALS(var_item_base_area_names), 0x0,
            "This is the base area for all following LIDs", HFILL }},
        { &hf_s7commp_itemaddr_lid_value,
          { "LID Value", "s7comm-plus.item.addr.lid_value", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: LID Value", HFILL }},

        /*** Item value ***/
        { &hf_s7commp_itemval_itemnumber,
          { "Item Number", "s7comm-plus.item.val.item_number", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Item Number", HFILL }},
        /* Datatype flags */
        { &hf_s7commp_itemval_datatype_flags,
        { "Datatype flags", "s7comm-plus.item.val.datatype_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7commp_itemval_datatype_flags_array,
        { "Array", "s7comm-plus.item.val.datatype_flags.array", FT_BOOLEAN, 8, NULL, S7COMMP_DATATYPE_FLAG_ARRAY,
          "The data has to be interpretes as an array of values", HFILL }},
        { &hf_s7commp_itemval_datatype_flags_address_array,
        { "Addressarray", "s7comm-plus.item.val.datatype_flags.address_array", FT_BOOLEAN, 8, NULL, S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY,
          "Array of values for Item Address via CRC and LID", HFILL }},
        { &hf_s7commp_itemval_datatype_flags_0x90unkn,
        { "Unknown-Flag1", "7comm-plus.item.val.datatype_flags.unknown1", FT_BOOLEAN, 8, NULL, 0x80,
          "Current unknown flag. A S7-1500 sets this flag sometimes", HFILL }},

        { &hf_s7commp_itemval_datatype,
          { "Datatype", "s7comm-plus.item.val.datatype", FT_UINT8, BASE_HEX, VALS(item_data_type_names), 0x0,
            "Type of data following", HFILL }},
        { &hf_s7commp_itemval_arraysize,
          { "Array size", "s7comm-plus.item.val.arraysize", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of values of the specified datatype following", HFILL }},
        { &hf_s7commp_itemval_value,
          { "Value", "s7comm-plus.item.val.value", FT_NONE, BASE_NONE, NULL, 0x0,
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
        &ett_s7commp_data_res_set,
        &ett_s7commp_itemaddr_area,

        &ett_s7commp_itemval_datatype_flags,
        &ett_s7commp_itemval_array,
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
    for (counter = 1; counter <= 4+1; counter++) {        /* große Werte benötigen 5 Bytes: 4*7 bit + 4 bit */
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
/*******************************************************************************************************/
guint64
tvb_get_varuint64(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint64 val = 0;
    guint8 octet;
    guint8 cont;
    for (counter = 1; counter <= 8; counter++) {        /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
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
    if(cont) {        /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 8;
        val += octet;
    }
    return  val;
}
/*******************************************************************************************************
 *
 * Decoding of an Address-Array, used to subscribe cyclic variables from HMI
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_udint_address_array(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 array_size,
                                   guint32 offset)
{
    guint32 value = 0;
    guint8 octet_count = 0;
    guint32 item_count = 0;
    guint32 i = 0;
    guint32 array_size_act = 0;
    guint16 tia_var_area1;
    guint16 tia_var_area2;

    value = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_text(tree, tvb, offset, octet_count, "Unknown 1 (ID?): %u", value);
    offset += octet_count;
    array_size_act += 1;

    value = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_text(tree, tvb, offset, octet_count, "Unknown 2: %u", value);
    offset += octet_count;
    array_size_act += 1;

    item_count = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_text(tree, tvb, offset, octet_count, "Number of addresses following: %u", item_count);
    offset += octet_count;
    array_size_act += 1;

    for (i = 1; i <= item_count; i++) {
        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Unknown 1 (ID?): %u", i, value);
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Item reference number: %u", i, value);
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Unknown 2 (LID Nesting depth?): %u", i, value);
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        /* Area ausmaskieren, ist hier etwas anders codiert als bei einem normalen Read einer Variable */
        tia_var_area1 = (value >> 16);
        tia_var_area2 = (value & 0xffff);
        if (tia_var_area1 == S7COMMP_VAR_ITEM_AREA1_DB) {
            proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Area: %u (Datablock, DB-Number %u)", i, value, tia_var_area2);
        } else {
            proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] IQMCT Area: %u (%s)", i, value, val_to_str(value, var_item_area2_names, "Unknown IQMCT Area"));
        }
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Symbol-CRC: %u", i, value);
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] Base Area: %u (%s)", i, value, val_to_str(value, var_item_base_area_names, "Unknown Base Area"));
        offset += octet_count;
        array_size_act += 1;

        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Address[%u] LID-Value: %u", i, value);
        offset += octet_count;
        array_size_act += 1;

        /* break decoding if out of array-size range*/
        if (array_size_act > array_size) {
            break;
        }
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of a single value with datatype flags, datatype specifier and the value data
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_value(tvbuff_t *tvb,
                     proto_tree *data_item_tree,
                     guint32 offset,
                     int* structLevel,
                     const guint32 item_number,
                     const int inSession)
{
    guint8 octet_count = 0;
    guint8 datatype;
    guint8 datatype_flags;
    gboolean is_array = FALSE;
    gboolean is_address_array = FALSE;
    gboolean unknown_type_occured = FALSE;
    guint32 array_size = 1;     /* use 1 as default, so non-arrays can dissected in the same manner as arrays */
    guint32 array_index = 0;

    proto_item *array_item = NULL;
    proto_tree *array_item_tree = NULL;

    guint64 uint64val = 0;
    guint32 uint32val = 0;
    guint16 uint16val = 0;
    gint16 int16val = 0;
    gint32 int32val = 0;
    guint8 uint8val = 0;
    gint8 int8val = 0;
    gchar str_val[128];     /* Value of one single item */
    gchar str_arrval[512];  /* Value of array values */

    guint8 string_actlength = 0;

    guint32 offset_save;
    guint32 start_offset;
    guint32 length_of_value = 0;

    memset(str_val, 0, sizeof(str_val));
    memset(str_arrval, 0, sizeof(str_arrval));

    datatype_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(data_item_tree, tvb, offset, hf_s7commp_itemval_datatype_flags,
        ett_s7commp_itemval_datatype_flags, s7commp_itemval_datatype_flags_fields, ENC_BIG_ENDIAN);
    is_array = (datatype_flags & S7COMMP_DATATYPE_FLAG_ARRAY);
    is_address_array = (datatype_flags & S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY);
    offset += 1;

    datatype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_datatype, tvb, offset, 1, datatype);
    offset += 1;

    if (is_array || is_address_array) {
        array_size = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_arraysize, tvb, offset, octet_count, array_size);
        /* To Display an array value, build a separate tree for the complete array.
         * Under the array tree the array values are displayed.
         */
        offset += octet_count;
        array_item = proto_tree_add_item(data_item_tree, hf_s7commp_itemval_value, tvb, offset, -1, FALSE);
        array_item_tree = proto_item_add_subtree(array_item, ett_s7commp_itemval_array);
        start_offset = offset;
    }

    /* Use array loop also for non-arrays */
    for (array_index = 1; array_index <= array_size; array_index++) {
        switch (datatype) {
            /************************** Binärzahlen **************************/
            case S7COMMP_ITEM_DATA_TYPE_BOOL:
                length_of_value = 1;
                g_snprintf(str_val, sizeof(str_val), "0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                break;
            /************************** Ganzzahlen ohne Vorzeichen **************************/
            case S7COMMP_ITEM_DATA_TYPE_USINT:
                length_of_value = 1;
                g_snprintf(str_val, sizeof(str_val), "%u", tvb_get_guint8(tvb, offset));
                offset += 1;
                break;
            case S7COMMP_ITEM_DATA_TYPE_UINT:
                length_of_value = 2;
                g_snprintf(str_val, sizeof(str_val), "%u", tvb_get_ntohs(tvb, offset));
                offset += 2;
                break;
            case S7COMMP_ITEM_DATA_TYPE_UDINT:
                /* an adress array has its own subfunction */
                if (is_address_array) {
                    offset_save = offset;
                    offset = s7commp_decode_udint_address_array(tvb, array_item_tree, array_size, offset);
                    length_of_value = offset - offset_save;
                    g_strlcpy(str_val, "Array of addresses", sizeof(str_val));
                    /* set array index to zero, because all data decoded inside subfunction */
                    array_index = array_size;
                } else {
                    uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
                    offset += octet_count;
                    length_of_value = octet_count;
                    g_snprintf(str_val, sizeof(str_val), "%u", uint32val);
                }
                break;
            case S7COMMP_ITEM_DATA_TYPE_ULINT:
            case S7COMMP_ITEM_DATA_TYPE_IEC_LTIMER: /* this one has a variable length, guessed to 64 bits */
            case S7COMMP_ITEM_DATA_TYPE_LINT: /* maybe we have to add some kind of sign bit handling */
                uint64val = tvb_get_varuint64(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, sizeof(str_val), "0x%016llx", uint64val);
                break;
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
            case S7COMMP_TYPEID_STRUCT:
                if(structLevel) *structLevel += 1; /* entering a new structure level */
                length_of_value = 4;
                g_snprintf(str_val, sizeof(str_val), "%u", tvb_get_ntohl(tvb, offset)); /* the following struct-items are using this number in ascending order */
                offset += 4;
                break;
            case S7COMMP_ITEM_DATA_TYPE_DWORD:
            case S7COMMP_SESS_TYPEID_DWORD1:        /* 0xd3 */
            case S7COMMP_SESS_TYPEID_DWORD2:        /* 0x12 */
                length_of_value = 4;
                g_snprintf(str_val, sizeof(str_val), "0x%08x", tvb_get_ntohl(tvb, offset));
                offset += 4;
                break;
            case S7COMMP_ITEM_DATA_TYPE_LWORD:
                length_of_value = 8;
                g_snprintf(str_val, sizeof(str_val), "0x%016llx", tvb_get_ntoh64(tvb, offset));
                offset += 8;
                break;
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
            /************************** Special ***************************/
            case S7COMMP_ITEM_DATA_TYPE_NULL:       /* 0x00 */
                /* No value following */
                g_snprintf(str_val, sizeof(str_val), "<NO VALUE>");
                length_of_value = 0;
                break;
            case S7COMMP_SESS_TYPEID_STRING:        /* 0x15 */
                /* Es folgt ein String mit vorab einem Byte für die Stringlänge
                 * TODO: Falls das hier kein S7-String ist, sind auch längere Strings möglich.
                 * Evtl. ist die Stringlänge ein varint?
                 */
                length_of_value = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(data_item_tree, tvb, offset, 1, "STRING Actual length: %d", length_of_value);
                offset += 1;
                g_snprintf(str_val, sizeof(str_val), "%s",
                           tvb_get_string(wmem_packet_scope(), tvb, offset, length_of_value));
                offset += length_of_value;
                break;
            /**************************  ***************************/
            case S7COMMP_ITEM_DATA_TYPE_IEC_COUNTER:
                if(datatype_flags == 0x80) {
                     /* length is known as 8 bytes with flags 0x80 */
                    length_of_value = 8;
                    g_snprintf(str_val, sizeof(str_val), "%s", tvb_bytes_to_ep_str(tvb, offset, length_of_value));
                    offset += length_of_value;
                }
                break;
            /******** Type Ids which meaning is unknown ***********/
            case S7COMMP_ITEM_DATA_TYPE_3BYTE:
                /* TODO:
                 * See capture file S7-1200-Uploading-OB1-TIAV12.pcap #30, #33, #103, #116, #119
                 * Value seems to be 3 bytes long.
                 */
                length_of_value = 3;
                g_snprintf(str_val, sizeof(str_val), "%s", tvb_bytes_to_ep_str(tvb, offset, length_of_value));
                offset += length_of_value;
                break;
            default:
                /* zur Zeit unbekannter Typ, muss abgebrochen werden solange der Aufbau nicht bekannt */
                unknown_type_occured = TRUE;
                g_strlcpy(str_val, "Unknown Type occured. Could not interpret value!", sizeof(str_val));
                break;
        } /* switch */

        if (unknown_type_occured) {
            break;
        }

        if (is_array) {
            /* Build a string of all array values. Maximum number of 10 values */
            if (array_index < S7COMMP_ITEMVAL_ARR_MAX_DISPLAY) {
                g_strlcat(str_arrval, str_val, sizeof(str_arrval));
                if (array_index < array_size) {
                    g_strlcat(str_arrval, ", ", sizeof(str_arrval));
                }
            } else if (array_index == S7COMMP_ITEMVAL_ARR_MAX_DISPLAY) {
                /* truncate */
                g_strlcat(str_arrval, "...", sizeof(str_arrval));
            }
            proto_tree_add_text(array_item_tree, tvb, offset - length_of_value, length_of_value, "Value[%u]: %s", array_index, str_val);
        }
    } /* for */

    /* TODO: This needs a massive cleanup, "inSession" condition should be removed */
    if (is_array) {
        proto_item_append_text(array_item_tree, " Array[%u] = %s", array_size, str_arrval);
        proto_item_set_len(array_item_tree, offset - start_offset);
        if (!inSession) {   /* when "in session", the item number is added outside to additional information */
            proto_item_append_text(data_item_tree, " [%d]: (%s) Array[%u] = %s", item_number,
                val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), array_size, str_arrval);
        } else {
            proto_item_append_text(data_item_tree, " (%s) Array[%u] = %s", val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), array_size, str_arrval);
        }
    } else if (is_address_array) {
        proto_item_append_text(array_item_tree, " = %s", str_val);
        proto_item_set_len(array_item_tree, offset - start_offset);
        if (!inSession) {   /* when "in session", the item number is added outside to additional information */
            proto_item_append_text(data_item_tree, " [%d]: (%s) = %s", item_number, val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), str_val);
        } else {
            proto_item_append_text(data_item_tree, " (%s) = %s", val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), str_val);
        }
    } else { /* not an array or address array */
        if (length_of_value > 0) {
            proto_tree_add_text(data_item_tree, tvb, offset - length_of_value, length_of_value, "Value: %s", str_val);
        }
        if (!inSession) {   /* when "in session", the item number is added outside to additional information */
            proto_item_append_text(data_item_tree, " [%d]: (%s) = %s", item_number, val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), str_val);
        } else {
            proto_item_append_text(data_item_tree, " (%s) = %s", val_to_str(datatype, item_data_type_names, "Unknown datatype: 0x%02x"), str_val);
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Connect -> Request -> Start session
 * passt auch fuer response
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_session_stuff(tvbuff_t *tvb,
                             proto_tree *tree,
                             guint32 offset,
                             const guint32 offsetmax)
{
    guint32 start_offset;
    guint32 item_nr = 1;

    guint32 id_number = 0;
    gboolean unknown_type_occured = FALSE;

    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    int structLevel = 0;
    guint8 octet_count = 0;

    /* Einlesen bis offset == maxoffset */
    while ((unknown_type_occured == FALSE) && (offset + 1 < offsetmax))
    {
        octet_count = 2;

        start_offset = offset;

        data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
        data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);

        /* the size of the id seems also variable */
        id_number = tvb_get_varuint32(tvb, &octet_count, offset);

        proto_tree_add_uint(data_item_tree, hf_s7commp_data_id_number, tvb, offset, octet_count, id_number);
        offset += octet_count;

        if (structLevel > 0) {
            proto_item_append_text(data_item_tree, " [%d]: ID: %u (Struct-Level %d)", item_nr, id_number, structLevel);
        } else {
            proto_item_append_text(data_item_tree, " [%d]: ID: %u", item_nr, id_number);
        }

        if(id_number) /* assuming that item id = 0 marks end of structure */
        {
            /* the type and value assigned to the id is coded in the same way as the read response values */
            offset = s7commp_decode_value(tvb, data_item_tree, offset, &structLevel, item_nr, TRUE);
        }
        item_nr++;

        proto_item_set_len(data_item_tree, offset - start_offset);
        if(!id_number) /* assuming that item id = 0 marks end of structure */
        {
            structLevel--;
            if(structLevel < 0)
            {
                break; /* highest structure terminated -> leave */
            }
        }
    }

    return offset;
}

/*******************************************************************************************************
 *
 * Connect -> Start session
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_connect_startsession(tvbuff_t *tvb,
                                    proto_tree *tree,
                                    guint32 offset,
                                    const guint32 offsetmax,
                                    gboolean is_response)
{
    /* einige Bytes unbekannt */
    guint32 unkownBytes = 0;
    guint8 scannedByte = 0;

    proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 4, tvb_get_ptr(tvb, offset, 4));
    offset += 4;
    if (is_response) {
        /* the following byte becomes part of the session id by adding 0x0380 */
        scannedByte = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "This byte becomes part of the Session Id by adding 0x0380, should be (0x%04x): 0x%02x", (scannedByte + 0x0380), scannedByte);
        offset += 1;
    } else {
        proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 1, tvb_get_ptr(tvb, offset, 1));
        offset += 1;
    }
    while((offset + unkownBytes) < offsetmax) /* as long as we don't know how to find the first position for the following decode, we use this wile as workaround */
    {
        scannedByte = tvb_get_guint8(tvb, offset + unkownBytes);
        if(scannedByte == 0xa3)
        {
            break; /* found some known good ID */
        }
        else unkownBytes++;
    }
    proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, unkownBytes, tvb_get_ptr(tvb, offset, unkownBytes));
    offset += unkownBytes;
    return s7commp_decode_session_stuff(tvb,tree,offset,offsetmax);
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
    proto_item *area_item = NULL;
    proto_item *area_item_tree = NULL;

    guint8 octet_count = 0;
    guint32 value = 0;
    guint32 crc = 0;
    guint16 tia_var_area1 = 0;
    guint16 tia_var_area2 = 0;
    guint32 tia_lid_nest_depth = 0;
    guint32 tia_lid_cnt = 0;
    guint32 offset_at_start = offset;

    *number_of_fields = 0;

    adr_item = proto_tree_add_item(tree, hf_s7commp_data_item_address, tvb, offset, -1, FALSE);
    adr_item_tree = proto_item_add_subtree(adr_item, ett_s7commp_data_item);

    /**************************************************************
     * CRC als varuint
     */
    crc = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_uint(adr_item_tree, hf_s7commp_itemaddr_crc, tvb, offset, octet_count, crc);
    proto_item_append_text(adr_item_tree, ": SYM-CRC=%08x", crc);
    offset += octet_count;

    *number_of_fields += 1;
    /**************************************************************
     * Area 52=Merker usw.
     * when Bytes 2/3 == 0x8a0e then bytes 4/5 are containing the DB number
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);
    area_item = proto_tree_add_uint(adr_item_tree, hf_s7commp_itemaddr_area, tvb, offset, octet_count, value);
    area_item_tree = proto_item_add_subtree(area_item, ett_s7commp_itemaddr_area);

    /* Area ausmaskieren */
    tia_var_area1 = (value >> 16);
    tia_var_area2 = (value & 0xffff);
    proto_tree_add_uint(area_item_tree, hf_s7commp_itemaddr_area1, tvb, offset, octet_count, tia_var_area1);
    if (tia_var_area1 == S7COMMP_VAR_ITEM_AREA1_IQMCT) {
        proto_tree_add_uint(area_item_tree, hf_s7commp_itemaddr_area2, tvb, offset, octet_count, tia_var_area2);
        //proto_tree_add_text(area_item_tree, tvb, offset, octet_count, "Accessing Area: %s", val_to_str(tia_var_area2, var_item_area2_names, "Unknown IQMCT Area: 0x%04x"));
        proto_item_append_text(area_item_tree, " (%s)", val_to_str(tia_var_area2, var_item_area2_names, "Unknown IQMCT Area: 0x%04x"));
        proto_item_append_text(adr_item_tree, ", LID=%s", val_to_str(tia_var_area2, var_item_area2_names_short, "Unknown IQMCT Area: 0x%04x"));
    } else if (tia_var_area1 == S7COMMP_VAR_ITEM_AREA1_DB) {
        proto_tree_add_uint(area_item_tree, hf_s7commp_itemaddr_dbnumber, tvb, offset, octet_count, tia_var_area2);
        proto_item_append_text(area_item_tree, " (Datablock, DB-Number: %u)", tia_var_area2);
        proto_item_append_text(adr_item_tree, ", LID=DB%u", tia_var_area2);
    } else {
        proto_tree_add_text(area_item_tree, tvb, offset, octet_count, "Unknown Area: 0x%04x / 0x%04x", tia_var_area1, tia_var_area2);
        proto_item_append_text(adr_item_tree, " Unknown Area 0x%04x / 0x%04x", tia_var_area1, tia_var_area2);
    }
    offset += octet_count;

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
    proto_tree_add_uint(adr_item_tree, hf_s7commp_itemaddr_lid_nesting_depth, tvb, offset, octet_count, tia_lid_nest_depth);
    offset += octet_count;
    *number_of_fields += 1;

    /**************************************************************
     * Nochmal Angabe des Speicherbereichs.
     * Bei Merkern scheint hier 0xe98 zu stehen, bei DBs 0x9f6
     * Es gibt noch weitere Bereiche, deren Bedeutung z.Zt. unbekannt ist (Systemdaten? äquivalent zu bisherigen SZL?)
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_uint(adr_item_tree, hf_s7commp_itemaddr_base_area, tvb, offset, octet_count, value);
    offset += octet_count;

    *number_of_fields += 1;

    /**************************************************************
     * LID pro Nest-Level
     *
     */
    for (tia_lid_cnt = 2; tia_lid_cnt <= tia_lid_nest_depth; tia_lid_cnt++) {
        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(adr_item_tree, hf_s7commp_itemaddr_lid_value, tvb, offset, octet_count, value);
        /* The old add_text with additional info of the current "nesting level" was nicer, but is not possible with add_uint */
        /*proto_tree_add_text(adr_item_tree, tvb, offset, octet_count, "LID Value (Nesting Level %d): %u", tia_lid_cnt, value);*/
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
    guint32 item_number;
    guint32 start_offset = offset;
    guint8 octet_count = 0;
    int structLevel = 0;

    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);

    item_number = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_itemnumber, tvb, offset, octet_count, item_number);
    offset += octet_count;

    offset = s7commp_decode_value(tvb, data_item_tree, offset, &structLevel, item_number, FALSE);
    proto_item_set_len(data_item_tree, offset - start_offset);
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
    proto_tree_add_bitmask(data_item_tree, tvb, offset, hf_s7commp_itemval_datatype_flags,
        ett_s7commp_itemval_datatype_flags, s7commp_itemval_datatype_flags_fields, ENC_BIG_ENDIAN);
    offset += 1;
    /*///////////////////////////////////////////////////////////////////////////////////////////*/
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
 * s7commp_decode_data_rw_request_trail()
 * Read and write requsts contain a 27 byte long part. For the S7-1200 these content is always the same.
 * But for the S7-1500 the last 4 byte are changing within a session.
 *******************************************************************************************************/
static guint32
s7commp_decode_data_rw_request_trail(tvbuff_t *tvb,
                                     proto_tree *tree,
                                     guint32 offset,
                                     const guint32 offsetmax)
{
    if(offset + RW_REQUEST_TRAILER_LEN <= offsetmax) {
        /* the first 23 bytes do not change */
        proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, RW_REQUEST_TRAILER_LEN-4,
                             tvb_get_ptr(tvb, offset, RW_REQUEST_TRAILER_LEN-4));
        offset += RW_REQUEST_TRAILER_LEN-4;
        /* the last 4 bytes change for the S7-1500 */
        proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, 4,
                             tvb_get_ptr(tvb, offset, 4));
        offset += 4;
    }
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
    guint32 item_count = 0;
    guint32 number_of_fields_in_complete_set = 0;
    guint8 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    guint32 offsetmax = offset + dlength;
    guint8 octet_count = 0;

    guint8 itemAddressCount;
    guint8 ItemAddressRead;
    guint8 ItemReadCount;
    gint32 int32val;
    int remainingDecodeSession;

    /* Wenn die ersten 4 Bytes 0x00, dann ist es ein 'normaler' Schreib-Befehl
     * Es kann sein dass hier die Session-ID steht, dann ist der Aufbau anders
     */
    value = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Unknown: 0x%08x", value);
    offset += 4;

    if (value == 0x00) {
        item_count = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(tree, hf_s7commp_item_count, tvb, offset, octet_count, item_count);
        offset += octet_count;

        number_of_fields_in_complete_set = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(tree, hf_s7commp_item_no_of_fields, tvb, offset, octet_count, number_of_fields_in_complete_set);
        offset += octet_count;

        for (i = 1; i <= item_count; i++) {
            offset = s7commp_decode_item_address(tvb, tree, &number_of_fields, offset);
            number_of_fields_in_complete_set -= number_of_fields;
            /* Eigentlicher Wert */
            offset = s7commp_decode_item_value(tvb, tree, offset);

        }
        /* 27 byte unbekannt */
        offset = s7commp_decode_data_rw_request_trail(tvb, tree, offset, offsetmax);
    } else {
        proto_tree_add_text(tree, tvb, offset-4, 4, "Write Request of session settings for session ID : 0x%08x. ", value);
        item_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Item count: %u", item_count);
        offset +=1;
        itemAddressCount = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Item address count: %u", itemAddressCount);
        offset +=1;
        for(ItemAddressRead=1;
            (ItemAddressRead <= itemAddressCount) && (offset < offsetmax);
            ItemAddressRead++)
        {
            int32val = tvb_get_varint32(tvb, &octet_count, offset);
            proto_tree_add_text(tree, tvb, offset, octet_count, "Item-Address[%d]: 0x%08x : %d",
                                ItemAddressRead, int32val, int32val);
            offset += octet_count;
        }
        /* the begin of the remaining part could be decoded similar to the start session stuff: */
        for(ItemReadCount = 1;
            (ItemReadCount <= item_count) && (offset < offsetmax);
            ItemReadCount++)
        {
            offset = s7commp_decode_session_stuff(tvb,tree,offset,offsetmax);
        }
        {
            /* Bei der S7-1500 folgt ein weiterer Block unbekannter Daten, da s7commp_decode_session_stuff()
             * nicht alles decodieren kann.
             */
            remainingDecodeSession = offsetmax - RW_REQUEST_TRAILER_LEN -offset;
            if(remainingDecodeSession > 0) {
                proto_tree_add_bytes(tree, hf_s7commp_data_data, tvb, offset, remainingDecodeSession,
                                     tvb_get_ptr(tvb, offset, remainingDecodeSession));
                offset += remainingDecodeSession;
            }
        }
        /* Bei S7-1200 und 1500 folgen dann wieder die 27 unbekannten Bytes, wie beim "normalen" read/write */
        offset = s7commp_decode_data_rw_request_trail(tvb, tree, offset, offsetmax);
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
    guint32 item_count = 0;
    guint32 number_of_fields_in_complete_set = 0;
    guint8 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    guint32 offsetmax = offset + dlength;
    guint8 octet_count = 0;

    /* für Variablen-Lesen müssen die ersten 4 Bytes 0 sein
     * Bei einer Variablentabelle steht dort z.b. 0x00000020
     */
    value = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Unknown: 0x%08x", value);
    offset += 4;
    if (value == 0x0) {
        item_count = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(tree, hf_s7commp_item_count, tvb, offset, octet_count, item_count);
        offset += 1;

        /* as sequence 62 of S7-1511-opc-request-all-types.pcap, shows
         * number_of_fields_in_complete_set is a varuint
         */
        number_of_fields_in_complete_set = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint(tree, hf_s7commp_item_no_of_fields, tvb, offset, octet_count, number_of_fields_in_complete_set);
        offset += octet_count;

        for (i = 1; i <= item_count; i++) {
            offset = s7commp_decode_item_address(tvb, tree, &number_of_fields, offset);
            number_of_fields_in_complete_set -= number_of_fields;
        }
        /* 27 byte unbekannt */
        offset = s7commp_decode_data_rw_request_trail(tvb, tree, offset, offsetmax);
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
    guint32 item_number;
    guint8 octet_count = 0;
    guint8 in_error_set = 0;

    guint32 offset_at_start = offset;
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
        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 1: 0x%08x : %d", int32val, int32val);
        offset += octet_count;

        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 2: 0x%08x : %d", int32val, int32val);
        offset += octet_count;
    }

    /********** Items die OK sind ********/
    item_number = tvb_get_varuint32(tvb, &octet_count, offset);
    /* Den einzelnen Items folgen auf jeden Fall immer noch 6 Null-Bytes
     * Bzw. nur 5 Null-Bytes, wenn vorher ein 0x00 als Trenner zum Fehlerdatensatz eingefügt wurde.
     * Evtl. lässt sich dieses vereinheitlichen.
     */
    do {
        item_number = tvb_get_varuint32(tvb, &octet_count, offset);
        /* Dieses ist die nächste Item Nummer
         * ACHTUNG!
         * Gibt es einen Fehlerdatensatz, so wird mit den Items begonnen, dann folgt
         * als Trennung ein Byte 0x00 und dann die Items mit den Fehlerdaten
         */
        if ((item_number == 0x00) && (in_error_set == 0x00)) {  /* && (first_response_byte != 0x00) */
            proto_tree_add_text(tree, tvb, offset, 1, "End marker for good values (bad values with error code may follow): 0x%02x", item_number);
            in_error_set = 1;
            offset += 1;
            item_number = tvb_get_varuint32(tvb, &octet_count, offset);
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
 *
 * Write-Response zu einer Variablen-Anfrage bei einer 1200er
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data_response_write(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint16 dlength,
                                  guint32 offset)
{
/* Der Aufbau scheint ähnlich dem eines Antworttelegramms für eine Lese-Funktion zu sein
 * Evtl. lassen sich später Teile vereinheitlichen.
 * Der Unterschied zum Read-Response scheint, dass man hier sofort im Fehlerbereich ist, wenn
 * das erste Byte != 0.
 */
    guint8 first_response_byte;
    guint32 item_number;
    guint8 octet_count = 0;
    guint8 in_error_set = 0;

    guint32 offset_at_start = offset;
    gint32 int32val = 0;

    first_response_byte = tvb_get_guint8(tvb, offset);
    /* Wenn kein Fehler bei einem Item, kommt als erstes ein 0x00 und dann die Item-Werte
     *
     * Bei Fehler (Vermutung):
     * Tritt ein Fehler auf, ist das erste Byte 0x90 (oder ungleich 0x00)
     * Dann folgen zwei varint Werte (vermutlich).
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
        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 1: 0x%08x : %d", int32val, int32val);
        offset += octet_count;

        int32val = tvb_get_varint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Errorcode 2: 0x%08x : %d", int32val, int32val);
        offset += octet_count;

        /* Beim Write-Response sind wir sofort im Fehler-Bereich */
        in_error_set = 1;
    }

    /********** Items die OK sind ********/
    item_number = tvb_get_varuint32(tvb, &octet_count, offset);
    /* Den einzelnen Items folgen auf jeden Fall immer noch 6 Null-Bytes
     * Bzw. nur 5 Null-Bytes, wenn vorher ein 0x00 als Trenner zum Fehlerdatensatz eingefügt wurde.
     * Evtl. lässt sich dieses vereinheitlichen.
     */
    do {
        item_number = tvb_get_varuint32(tvb, &octet_count, offset);
        /* Dieses ist die nächste Item Nummer
         * ACHTUNG!
         * Gibt es einen Fehlerdatensatz, so wird mit den Items begonnen, dann folgt
         * als Trennung ein Byte 0x00 und dann die Items mit den Fehlerdaten
         */
        if ((item_number == 0x00) && (in_error_set == 0x00)) {  /* && (first_response_byte != 0x00) */
            proto_tree_add_text(tree, tvb, offset, 1, "End marker for good values (bad values with error code may follow): 0x%02x", item_number);
            in_error_set = 1;
            offset += 1;
            item_number = tvb_get_varuint32(tvb, &octet_count, offset);
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
 *
 * Zyklische Daten
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data_cyclic(tvbuff_t *tvb,
                           packet_info *pinfo,
                           proto_tree *tree,
                           guint16 dlength,
                           guint32 offset)
{
    guint16 unknown1;
    guint16 unknown2;
    guint16 ref_number;

    guint16 seqnum;
    guint8 item_return_value;

    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 item_number;
    guint32 start_offset;
    int structLevel = 0;
    gboolean add_data_info_column = FALSE;

    /* Bei zyklischen Daten ist die Funktionsnummer nicht so wie bei anderen Telegrammen. Dieses ist eine
     * Nummer die vorher über ein 0x04ca Telegramm von der SPS zurückkommt.
     * Bei den Daten steht aber bei "unknown 1" ein 0x1000 und bei "unknown 2" ein 0x0400
     */

    /* 2/3: Unbekannt */
    unknown1 = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_data_unknown1, tvb, offset, 2, unknown1);
    offset += 2;

    /* 4/5: Reference number */
    ref_number = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset , 2, "Cyclic reference number: %u", ref_number);
    col_append_fstr(pinfo->cinfo, COL_INFO, " CycRef=%u", ref_number);
    offset += 2;

    /* 6/7: Unbekannt */
    unknown2 = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_data_unknown2, tvb, offset, 2, unknown2);
    offset += 2;

    /* Sequenz-nummer bei "normalen", bei cyclic steht hier immer Null */
    proto_tree_add_text(tree, tvb, offset , 1, "Cyclic Unknown 1: 0x%04x", tvb_get_ntohs(tvb, offset));
    offset += 2;

    if (unknown1 == 0x1000 && unknown2 == 0x0400){
        /* Bei V13 und einer 1200 werden hiermit Daten vom HMI zyklisch
         * bei Änderung übermittelt. Daten sind nur enthalten wenn sich etwas ändert.
         * Sonst gibt es ein verkürztes (Status?)-Telegramm.
         */
        proto_tree_add_text(tree, tvb, offset , 1, "Cyclic Unknown 2: 0x%02x", tvb_get_guint8(tvb, offset));
        offset += 1;

        seqnum = tvb_get_ntohs(tvb, offset);
        proto_tree_add_text(tree, tvb, offset , 2, "Cyclic sequence number: %u", seqnum);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CycSeq=%u", seqnum);
        offset += 2;

        proto_tree_add_text(tree, tvb, offset , 1, "Cyclic Unknown 3: 0x%02x", tvb_get_guint8(tvb, offset));
        offset += 1;

        item_return_value = tvb_get_guint8(tvb, offset);
        /* Return value: Ist der Wert ungleich 0, dann folgt ein Datensatz mit dem bekannten
         * Aufbau aus den anderen Telegrammen.
         * Liegt ein Adressfehler vor, so werden hier auch Fehlerwerte übertragen. Dann ist Datatype=NULL
         * Folgende Rückgabewerte wurden gesichtet:
         *  0x13 -> Fehler bei einer Adresse (S7-1200)
         *  0x92 -> Erfolg (S7-1200)
         *  0x9c -> Bei Beobachtung mit einer Variablentabelle (S7-1200), Aufbau scheint dann anders zu sein
         *
         * Danach können noch weitere Daten folgen, deren Aufbau bisher nicht bekannt ist.
         */
        while (item_return_value) {
            add_data_info_column = TRUE;    /* set flag, to add information into Info-Column at the end*/
            start_offset = offset;

            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);

            proto_tree_add_text(data_item_tree, tvb, offset , 1, "Return value: 0x%02x", item_return_value);
            offset += 1;
            /* Item reference number. Is sent to plc on the subscription-telegram for the addresses. */
            item_number = tvb_get_ntohl(tvb, offset);
            proto_tree_add_text(data_item_tree, tvb, offset, 4, "Item reference number: %u", item_number);
            offset += 4;

            offset = s7commp_decode_value(tvb, data_item_tree, offset, &structLevel, item_number, FALSE);
            proto_item_set_len(data_item_tree, offset - start_offset);

            item_return_value = tvb_get_guint8(tvb, offset);
        }
        if (add_data_info_column) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " <With data>");
        }
    }

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
    proto_tree *s7commp_trailer_tree = NULL;
    proto_tree *item_tree = NULL;

    guint32 offset = 0;
    guint32 offset_save = 0;

    guint8 pdutype = 0;
    guint8 hlength = 4;
    guint8 datatype = 0;
    guint16 dlength = 0;
    guint16 seqnum = 0;
    guint16 function = 0;
    guint16 unknown1 = 0;
    guint16 unknown2 = 0;
    gboolean has_trailer;

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
            col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%d", seqnum);
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

            proto_item_append_text(s7commp_data_tree, ", Data: %s", val_to_str(datatype, datatype_names, "Unknown type of data: 0x%02x"));

            if ((datatype == S7COMMP_DATATYPE_REQ) || (datatype == S7COMMP_DATATYPE_RES) || (datatype == S7COMMP_DATATYPE_RES2)) {
                /* 1: Kennung*? */
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_datatype, tvb, offset, 1, datatype);
                /* add type to info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Data: [%s]", val_to_str(datatype, datatype_names, "Unknown type of data: 0x%02x"));
                offset += 1;
                dlength -= 1;

                /* 2/3: Unbekannt */
                unknown1 = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_unknown1, tvb, offset, 2, unknown1);
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

                /* 6/7: Unbekannt */
                unknown2 = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_unknown2, tvb, offset, 2, unknown2);
                offset += 2;
                dlength -= 2;

                /* 8/9: Sequenz-Nummer für die Referenzierung Request/Response */
                seqnum = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_seqnum, tvb, offset, 2, seqnum);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%d", seqnum);
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
                    offset = s7commp_decode_connect_startsession(tvb, s7commp_data_tree, offset, offset + dlength, (datatype == S7COMMP_DATATYPE_RES));
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
                    if (function == S7COMMP_PDU2_DATAFUNC_READ) {
                        item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_req_set, tvb, offset, -1, FALSE);
                        item_tree = proto_item_add_subtree(item, ett_s7commp_data_req_set);
                        offset_save = offset;
                        offset = s7commp_decode_data_request_read(tvb, item_tree, dlength, offset);
                        proto_item_set_len(item_tree, offset - offset_save);
                        dlength = dlength - (offset - offset_save);
                    } else if (function == S7COMMP_PDU2_DATAFUNC_WRITE) {
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
                    } else if (function == S7COMMP_PDU2_DATAFUNC_BLOCK) {
                        offset_save = offset;
                        offset = s7commp_decode_connect_startsession(tvb, s7commp_data_tree, offset, offset + dlength, (datatype == S7COMMP_DATATYPE_RES));
                        dlength = dlength - (offset - offset_save);
                    }

                } else if ((datatype == S7COMMP_DATATYPE_RES) || (datatype == S7COMMP_DATATYPE_RES2)){      /* Response */
                    proto_tree_add_text(s7commp_data_tree, tvb, offset , 1,   "Res. Typ 2? : 0x%02x", tvb_get_guint8(tvb, offset));
                    offset += 1;
                    dlength -= 1;
                    /* Testweise ein Antworttelegramm von der SPS einer HMI-Anfrage
                     * Passt aber nur bei einer 1200
                     * Die 1500 scheint schon wieder alles anders zu machen
                     * So wie es aussieht gibt es verschiedene Datenformate für den Austausch, was wohl am Anfang der
                     * Session ausgehandelt wird.
                     */
                    if (function == S7COMMP_PDU2_DATAFUNC_READ) {
                        item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_res_set, tvb, offset, -1, FALSE);
                        item_tree = proto_item_add_subtree(item, ett_s7commp_data_res_set);
                        offset_save = offset;
                        offset = s7commp_decode_data_response_read(tvb, item_tree, dlength, offset);
                        proto_item_set_len(item_tree, offset - offset_save);
                        dlength = dlength - (offset - offset_save);
                    } else if (function == S7COMMP_PDU2_DATAFUNC_WRITE) {
                        item = proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_res_set, tvb, offset, -1, FALSE);
                        item_tree = proto_item_add_subtree(item, ett_s7commp_data_res_set);
                        offset_save = offset;
                        offset = s7commp_decode_data_response_write(tvb, item_tree, dlength, offset);
                        proto_item_set_len(item_tree, offset - offset_save);
                        dlength = dlength - (offset - offset_save);
                    }

                } else if (datatype == S7COMMP_DATATYPE_CYC) {
                    /* 1: Kennung -> Standard */
                    proto_tree_add_uint(s7commp_data_tree, hf_s7commp_data_datatype, tvb, offset, 1, datatype);
                    /* add type to info column */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Data: [%s]", val_to_str(datatype, datatype_names, "Unknown type of data: 0x%02x"));
                    offset += 1;
                    dlength -= 1;

                    offset_save = offset;
                    offset = s7commp_decode_data_cyclic(tvb, pinfo, s7commp_data_tree, dlength, offset);
                    dlength = dlength - (offset - offset_save);
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

                /* 1: Protocol Identifier, constant 0x72 */
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
