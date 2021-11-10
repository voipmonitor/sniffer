----------------------------------------
-- script-name: sonusimf.1.12.lua
--
-- Copyright (c) Sonus Networks, 2015
--
-- Version: 1.0 (Released in 15.0)
--   * initial release, provides dissection of SonusIMF packets.
--
-- OVERVIEW: 
-- This script creates a dissector for SonusIMF.   It can be disabled by turning off the 
-- the heuristic and port dissectors using in the SonusCM preferences.   
--
-- HOW TO INSTALL THIS SCRIPT:
--      For Windows :
--          * Install Wireshark version 1.12.0 or later.
--          * Copy this file to the appropriate directory  
--				For wireshark 2.0 or later:
--					C:\Users\<username>\AppData\Roaming\Wireshark\plugins (create directory if needed)
--				For older versions:
--             		Typically C:\Users\<username>\AppData\Roaming\Wireshark\
--           		Add the following line to the end of the init.lua file in the same directory
--                  	dofile(USER_DIR.."sonuscm.lua")
--          * Restart Wireshark.
--
--      For Linux:
--			   * Ensure that Wireshark is compiled with Lua.
--          * Copy this file to the /usr/local/share/wireshark directory
--          * Add the following lines to the end of the /usr/local/share/wireshark/init.lua file 
--                 dofile(USER_DIR.."sonuscm.lua")
--
--      Installing Wireshark from source for Linux:
--          * yum install lua
--          * yum install lua-devel
--          * Download and uncompress Wireshark source code.
--          * Run ./configure --with-lua
--          * make
--          * make install
--
-- DEPENDENCIES:
--     The sonuscm.lua plugin must be present for this plugin to work.
--
----------------------------------------

require "sonuscm"

-- Message types --
local IMF_TYPE_VERSION = 254
local IMF_TYPE_TRAFFIC = 253
local IMF_TYPE_LSTATUS = 252

local imf_msg_types = {
   [IMF_TYPE_LSTATUS] = "Link Status",
   [IMF_TYPE_TRAFFIC] = "Traffic Message",
   [IMF_TYPE_VERSION] = "Version/Handshake"
}

-- MSU Directions 
local IMF_MSU_DIR_UNKNOWN = 0
local IMF_MSU_DIR_INWARD  = 1
local IMF_MSU_DIR_OUTWARD = 2

local imf_msu_dir = {
   [IMF_MSU_DIR_UNKNOWN] = "Unknown",
   [IMF_MSU_DIR_INWARD] = "Incoming",
   [IMF_MSU_DIR_OUTWARD] = "Outgoing"
}

-- SS7 Variants
local IMF_SS7_VAR_UNKNOWN = 0
local IMF_SS7_VAR_ANSI    = 1
local IMF_SS7_VAR_ITU     = 2
local IMF_SS7_VAR_CHINA   = 3
local IMF_SS7_VAR_JAPAN   = 4
local IMF_SS7_NOT_APPLICABLE = 5

local imf_ss7_var = {
   [IMF_SS7_VAR_UNKNOWN] = "Unknown", 
   [IMF_SS7_VAR_ANSI] = "ANSI",
   [IMF_SS7_VAR_ITU] = "ITU",
   [IMF_SS7_VAR_CHINA] = "China",
   [IMF_SS7_VAR_JAPAN] = "Japan",
   [IMF_SS7_NOT_APPLICABLE] = "Not Applicable"
}

-- Link Types
local IMF_LINK_UNKNOWN  =  0
local IMF_LINK_LSL      =  1
local IMF_LINK_ANNEXA   =  2
local IMF_LINK_M2PA     =  3
local IMF_LINK_M2UA     =  4
local IMF_LINK_ATM      =  5
local IMF_LINK_M3UA     =  6
local IMF_LINK_SUA      =  7
local IMF_LINK_CICUA    =  8
--  IMF_LINK_SIP = 9 is now obsolete.
local IMF_LINK_IPSP     = 10 
local IMF_LINK_M3UA_MG  = 11 
local IMF_LINK_DIAMETER = 12 
local IMF_LINK_M3UA_SG  = 13 
local IMF_LINK_M3UA_SRV = 14

local imf_link_media = {
   [IMF_LINK_UNKNOWN] = "Unknown",
   [IMF_LINK_LSL] = "Low Speed Link",
   [IMF_LINK_ANNEXA] = "High Speed Link",
   [IMF_LINK_M2PA] = "M2PA",
   [IMF_LINK_M2UA] = "M2UA",
   [IMF_LINK_ATM] = "ATM",
   [IMF_LINK_M3UA] = "M3UA",
   [IMF_LINK_SUA] = "SUA",
   [IMF_LINK_CICUA] = "CIC UA",
   [IMF_LINK_IPSP] = "IPSP",
   [IMF_LINK_M3UA_MG] = "M3UA MG",
   [IMF_LINK_DIAMETER] = "DIAMETER",
   [IMF_LINK_M3UA_SG] = "M3UA SG",
   [IMF_LINK_M3UA_SRV] = "M3UA SRV"
}

-- Link L3 Status
local IMF_L3_UNKNOWN   = 0
local IMF_L3_INSERVICE = 1
local IMF_L3_OUTOFSERV = 2

local imf_link_status = {
   [IMF_L3_UNKNOWN] = "Unknown",
   [IMF_L3_INSERVICE] = "In Service",
   [IMF_L3_OUTOFSERV] = "Out of Service"
}

-- SG Link IDs
local IMF_SGID_SUA   = 1
local IMF_SGID_M3UA  = 2
local IMF_SGID_CICUA = 3

local imf_sg_link_ids = {
   [IMF_SGID_SUA]   = "SUA",
   [IMF_SGID_M3UA]  = "M3UA",
   [IMF_SGID_CICUA] = "CIC UA"
}

-- Version-type IMF packet */
local IMF_MAX_VERSION  =    4
local IMF_MAX_SLOTS    =   62
local IMF_MAX_NAME_LEN =   16

-- Traffic-type IMF packet
local IMF_MAX_NA       =  256

-- Fill subdissector handles
local ed_mtp3     = Dissector.get("mtp3")
local ed_m3ua     = Dissector.get("m3ua")
local ed_sua      = Dissector.get("sua")
local ed_data     = Dissector.get("data")
local ed_diameter = Dissector.get("diameter")


----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 9) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------
-- Wireshark version 3.0.0 removed the various logging functions (debug, info, message, warn and critical),
-- use the print function instead
local message_fn_not_supported = false
if major and tonumber(major) >= 3 then
  message_fn_not_supported = true
end
if message_fn_not_supported then
	print("Wireshark version = ", get_version())
	print("Lua version = ", _VERSION)
else
	message("Wireshark version = ", get_version())
    message("Lua version = ", _VERSION)
end

----------------------------------------
-- creates a Proto object, but doesn't register it yet
local sonusimf = Proto("sonusimf","Sonus IMF Protocol")

----------------------------------------
-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
-- again the following shows different ways of doing the same thing basically

local pf_msg_type    = ProtoField.new("Message Type",   "sonusimf.msg_type", ftypes.UINT8, imf_msg_types, base.HEX, 0x0, "Which type of message is this.")
local pf_version     = ProtoField.new("Version", "sonusimf.version", ftypes.UINT32,  nil, base.DEC, 0x0, "The version of the protocol being used." )
local pf_slot        = ProtoField.new("Slot",  "sonusimf.slot", ftypes.UINT32, nil, base.DEC, 0x0, "Slot" )
local pf_asp_slot    = ProtoField.new("Slot",  "sonusimf.aspslot", ftypes.UINT8, nil, base.DEC, 0x0, "Slot" )
local pf_name        = ProtoField.new("Name", "sonusimf.name", ftypes.STRING, nil, base.NONE, 0x0, "The name used by the IMF libary to identify itself" )
local pf_time        = ProtoField.absolute_time("sonusimf.time", "Time", base.UTC, "The UTC time stamp" )
local pf_seq_num     = ProtoField.new("Sequence Number", "sonusimf.seq", ftypes.UINT32, nil, base.DEC, 0x0, "The sequence number of this packet" )
local pf_na          = ProtoField.new("Network Appearance", "sonusimf.na", ftypes.UINT8, nil, base.DEC, 0x0, "The network appearance associated with this packet" )
local pf_node_id     = ProtoField.new("DSC Node ID", "sonusimf.dscnode", ftypes.UINT8, nil, base.DEC, 0x0, "The identifier of the DSC Node" )
local pf_adnc_id     = ProtoField.new("ADN Connection IID", "sonusimf.dscnode", ftypes.UINT8, nil, base.DEC, 0x0, "The Internal ID of the ADN Connection" )
local pf_ss7_var     = ProtoField.new("SS7 Variant", "sonusimf.ss7_var", ftypes.UINT8, imf_ss7_var, base.DEC, 0x0, "Which SS7 Variant is in use" )
local pf_slc         = ProtoField.new("Signaling Link Code", "sonusimf.slc", ftypes.UINT8, nil, base.DEC, 0x0, "Signaling Link Code" )
local pf_apc         = ProtoField.new("Adjacent Point Code", "sonusimf.apc", ftypes.UINT24, nil, base.DEC, 0x0, "Adjacent Point Code" )
local pf_sg_link     = ProtoField.new("Link ID", "sonusimf.link_id", ftypes.UINT32, imf_link_ids, base.DEC, 0x0, "Link Identification value" )
local pf_sip_link    = ProtoField.new("Link ID", "sonusimf.link_id", ftypes.UINT32, nil, base.DEC, 0x0, "Link Identification value" )
local pf_adnconnid   = ProtoField.new("ADN Connection ID", "sonusimf.adnconnid", ftypes.UINT32, nil, base.DEC, 0x0, "ADN Connection ID")
local pf_asp_id      = ProtoField.new("ASP ID", "sonusimf.aspid", ftypes.UINT32, nil, base.DEC, 0x0, "ASP ID")
local pf_msu_dir     = ProtoField.new("MSU Direction", "sonusimf.msu_dir", ftypes.UINT8, imf_msu_dir, base.DEC, 0x0, "The direction the MSU was travelling")
local pf_link_media  = ProtoField.new("Link Media", "sonusimf.link_media", ftypes.UINT8, imf_link_media, base.DEC, 0x0, "The type of link media in use")
local pf_reserved1   = ProtoField.new("Reserved", "sonusimf.reserve", ftypes.UINT8, nil, base.DEC, 0x0, "Reserved for future use" )
local pf_dsc_inst    = ProtoField.new("DSC Instance ID", "sonusimf.dscinstance", ftypes.UINT8, nil, base.DEC, 0x0, "DSC instance identifier" )
local pf_reserved2   = ProtoField.new("Reserved", "sonusimf.reserve", ftypes.UINT8, nil, base.DEC, 0x0, "Reserved for future use" )
local pf_msu_len     = ProtoField.new("MSU Length", "sonusimf.msu_len", ftypes.UINT16, nil, base.DEC, 0x0, "Length of the MSU payload" ) 
local pf_l3_state    = ProtoField.new("Link L3 State", "sonusimf.l3_state", ftypes.UINT8, imf_link_status, base.DEC, 0x0, "Status of the L3 link" )
local pf_oos_cause   = ProtoField.new("Out-of-Service Cause", "sonusimf.oos_cause", ftypes.UINT8, nil, base.DEC, 0x0, "The cause for the link being out of service" )

      
----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set dns.fields to it, so as to avoid forgetting a field
sonusimf.fields = { pf_msg_type, pf_version, pf_slot, pf_name, pf_time, pf_seq_num, pf_na, pf_node_id, pf_ss7_var, pf_adnc_id, pf_slc, pf_apc,
	pf_sg_link, pf_sip_link, pf_adnconnid, pf_msu_dir, pf_link_media, pf_reserved1, pf_dsc_inst, pf_reserved2, pf_msu_len, pf_l3_state,
	pf_oos_cause, pf_asp_id, pf_asp_slot }

----------------------------------------
-- create some expert info fields (this is new functionality in 1.11.3)
-- Expert info fields are very similar to proto fields: they're tied to our protocol,
-- they're created in a similar way, and registered by setting a 'experts' field to
-- a table of them just as proto fields were put into the 'dns.fields' above
-- The old way of creating expert info was to just add it to the tree, but that
-- didn't let the expert info be filterable in wireshark, whereas this way does
local ef_invalid_na         =  ProtoExpert.new( "sonusimf.invalid_na", "Network Appearance greater than allowed maximum",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_variant    =  ProtoExpert.new( "sonusimf.invalid_variant", "SS7 Variant outside known values",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_link_id    =  ProtoExpert.new( "sonusimf.invalid_link_id", "Link ID outside known values",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_link_media =  ProtoExpert.new( "sonusimf.invalid_link_media", "Link Media out of bounds",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_link_state =  ProtoExpert.new( "sonusimf.invalid_link_state", "Link state out of bounds",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_direction  =  ProtoExpert.new( "sonusimf.invalid_direction", "MSU Direction out of bounds",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_rsvd_byte  =  ProtoExpert.new( "sonusimf.invalid_reserved_type", "Reserved byte should always be zero.",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_link_proto_error   =  ProtoExpert.new( "sonusimf.link_proto_error", "Link in service, but Out-of-Service cause non-zero",
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_msg_type   =  ProtoExpert.new( "sonusimf.invalid_message_type", "Unrecognized message type", 
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_slot       =  ProtoExpert.new( "sonusimf.invalid_slot", "Slot number outside expected range", 
      expert.group.PROTOCOL, expert.severity.WARN)
local ef_invalid_version    =  ProtoExpert.new( "sonusimf.invalid_version", "Unrecognized message type", 
      expert.group.PROTOCOL, expert.severity.WARN)

-- register them
sonusimf.experts = { ef_invalid_na, ef_invalid_variant, ef_invalid_link_id, ef_invalid_link_state, ef_invalid_direction,
   ef_invalid_rsvd_byte, ef_link_proto_error, ef_invalid_msg_type, ef_invalid_slot, ef_invalid_version }


----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "imf.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
dissect_sonusimf = function( tvbuf, pktinfo, root )

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("SonusIMF")

	if tvbuf:range(0,1):uint() == IMF_TYPE_VERSION then
		return dissect_sonusimf_version_msg(tvbuf, pktinfo, root)
	elseif tvbuf:range(0,1):uint() == IMF_TYPE_TRAFFIC then
		return dissect_sonusimf_traffic_msg(tvbuf, pktinfo, root)
	elseif tvbuf:range(0,1):uint() == IMF_TYPE_LSTATUS then
		return dissect_sonusimf_lstatus_msg(tvbuf, pktinfo, root)
	else 
		root:add_proto_expert_info(ef_invalid_msg_type)
	end

	return 0
	
end


----------------------------------------
-- heuristic dissection function passed to sonuscm plugin
heur_dissect_sonusimf = function( tvbuf, pktinfo, root )

  -- Make sure there is at least one byte for the msg type
  if tvbuf:len() < 1 then
	if message_fn_not_supported then
		print("heur_dissect_imf: tvb too short", imf_too_short)
	else
		message("heur_dissect_imf: tvb too short", imf_too_short)
	end
    return 0
  end

  -- pull out the header type
  local header_type = tvbuf:range(0,1):uint()  

  -- VERSION messages
  -- do we believe this could be a version message?
  if header_type == IMF_TYPE_VERSION then

    -- Name is optional, max length is 16,  min length is 0
    if tvbuf:len() > 25 or tvbuf:len() < 9 then
      return 0
    end

    -- decode the version
    local version = tvbuf:range(1,4):uint()
    -- validate the version 
    if version == 0 or version > IMF_MAX_VERSION then
		if message_fn_not_supported then
			print("heur_dissect_imf: not a recognized version")
		else
			message("heur_dissect_imf: not a recognized version")
		end
      return 0
    end

    -- decode the slot
    local slot = tvbuf:range(5,4):uint()
    -- validate the slot
    if slot == 0 or slot > IMF_MAX_SLOTS then
		if message_fn_not_supported then
			print("heur_dissect_imf: not a recognized slot "..slot)
		else
			message("heur_dissect_imf: not a recognized slot "..slot)
		end
      return 0
    end

  -- TRAFFIC messages
  elseif header_type == IMF_TYPE_TRAFFIC then

    if tvbuf:len() < 23 then
      return 0
    end
    -- skip the timestamp  (6 bytes)
    -- skip the seq number (4 bytes)

    -- luckily both of these values are limited to the same range
    -- it's not necessary to wait until we know the link type to
    -- validate it.
    local na_or_node_id = tvbuf:range(11,1):uint()
    if na_or_node_id == 0 or na_or_node_id > 99 then
      return 0
    end

    -- validate the variant
    local var = tvbuf:range(12,1):uint()
    if imf_ss7_var[ var ] == nil then
		if message_fn_not_supported then
			print("Variant is invalid "..var)
		else
			message("Variant is invalid "..var)
		end
      return 0
    end

    -- grab the link id/user id/adn connection id but don't validate
    -- it until we know the link media type.
    local link_user_adn_id = tvbuf:range(13,4):uint()

    -- validate the direction
    local dir = tvbuf:range(17,1):uint() 
    if imf_msu_dir[ dir ] == nil then
		if message_fn_not_supported then
			print("heur_dissect_imf: invalid dir "..dir)
		else
			message("heur_dissect_imf: invalid dir "..dir)
		end
      return 0
    end

    -- validate the link media
    local ltype = tvbuf:range(18,1):uint()
    if imf_link_media[ltype] == nil then
      if message_fn_not_supported then
        print("heur_dissect_imf: invalid link media "..ltype)
      else
        message("heur_dissect_imf: invalid link media "..ltype)
      end
      return 0
    end

    -- reserved byte except for DSC
    local rbyte = tvbuf:range(19,1):uint()

    if ltype ~= IMF_LINK_DIAMETER and rbyte ~= 0 then
		  if message_fn_not_supported then
			  print("heur_dissect_imf: invalid reserved byte 19: "..rbyte)
		  else
			  message("heur_dissect_imf: invalid reserved byte 19: "..rbyte)
		  end
      return 0
    end

    -- second reserved byte must be zero 
    local rbyte_20 = tvbuf:range(20,1):uint()
    if rbyte_20 ~= 0 then
		  if message_fn_not_supported then
			  print("heur_dissect_imf: invalid reserved byte 20: "..rbyte_20)
		  else
			  message("heur_dissect_imf: invalid reserved byte 20: "..rbyte_20)
		  end
      return 0
    end

    -- need exact match in terms of bytes
    local len = tvbuf:range(21,2):uint()
    if len > tvbuf:len() - 23 then
		if message_fn_not_supported then
			print("heur_dissect_imf: invalid length. Should be "..(tvbuf:len() - 23) )
		else
			message("heur_dissect_imf: invalid length. Should be "..(tvbuf:len() - 23) )
		end
		return 0
    end
          
  elseif header_type == IMF_TYPE_LSTATUS then

    if tvbuf:len() < 20 then
      return 0
    end

    -- validate the NA
    local na = tvbuf:range(11,1):uint()
    if na > 99 or na < 1 then
      return 0
    end

    -- L3 State Field
    local l3state = tvbuf:range(17,1):uint()
    if imf_link_status[l3state] == nil then 
		if message_fn_not_supported then
			print("heur_dissect_imf: invalid l3 state"..l3state)
		else
			message("heur_dissect_imf: invalid l3 state"..l3state)
		end
      return 0
    end

    -- validate the link media
    local lmedia = tvbuf:range(18,1):uint()
    if imf_link_media[ lmedia ] == nil then
		if message_fn_not_supported then
			print("heur_dissect_imf: invalid link media "..lmedia)
		else
			message("heur_dissect_imf: invalid link media "..lmedia)
		end
      return 0
    end

  else
    return 0
  end

  -- ok, looks like it's ours, so go dissect it
  br3 = dissect_sonusimf( tvbuf, pktinfo, root )

  return br3

end

-- now register that heuristic dissector into the tcp and tipc heuristic list

sonuscm.register_heuristic( heur_dissect_sonusimf )

-- We're done!
-- our protocol (Proto) gets automatically registered after this script finishes loading
----------------------------------------

dissect_sonusimf_version_msg = function(tvbuf, pktinfo, root)

  local tree = root:add( sonusimf, tvbuf:len(), "Sonus IMF")

  -- Add the message type to the tree
  tree:add( pf_msg_type, tvbuf:range(0,1) )

  -- Add the version
  tree:add( pf_version, tvbuf:range(1,4) )
  if ( tvbuf:range(1,4):uint() > IMF_MAX_VERSION ) then
    tree:add_proto_expert_info( ef_invalid_version )
  end
   
  tree:add( pf_slot, tvbuf:range(5,4) )
  if ( tvbuf:range(5,4):uint() > IMF_MAX_SLOTS ) then
    tree:add_proto_expert_info( ef_invalid_slot )
  end
   
  -- Add optional name len.
  if tvbuf:len() > 9 then
    tree:add( pf_name, tvbuf:range(9) )
  end
   
  return true

end


-- Dissects a LinkStatus-type IMF message subordinate to dissect_sonusimf() below
dissect_sonusimf_lstatus_msg = function( tvbuf, pktinfo, root )

  local tree = root:add( sonusimf, 20, "Sonus IMF")

  -- Add the message type to the tree
  tree:add( pf_msg_type, tvbuf:range(0,1) )

  -- TODO : Not showing in UTC format yet.
  local nstime = NSTime( tvbuf:range(1,4):uint(), tvbuf:range(5,2):uint() * 1000000 )
  tree:add( pf_time, nstime )
  -- Add the sequence number
  tree:add( pf_seq_num, tvbuf:range(7,4) )
  -- Add the NA
  tree:add( pf_na, tvbuf:range(11,1) )
  -- Add the variant
  tree:add( pf_ss7_var, tvbuf:range(12,1) )
  if imf_ss7_var[ tvbuf:range(12,1):uint() ] == nil then
    tree:add_proto_expert_info( ef_invalid_variant )
  end

  -- Add and check L3 Link State 
  local link_state = tvbuf:range(17, 1):uint()
  tree:add( pf_l3_state, tvbuf:range(17, 1) )
  if imf_link_status[ link_state ] == nil then
    tree:add_proto_expert_info( ef_invalid_link_state )
  end

  -- Add and check Link Media
  tree:add( pf_link_media, tvbuf:range(18,1) )
  if imf_link_media[ tvbuf:range(18,1):uint() ] == nil then
    tree:add_proto_expert_info( ef_invalid_link_media )
  end

  -- Add and check Out-of-Service Cause
  tree:add( pf_oos_cause, tvbuf:range(19,1) )
  if link_state ~= IMF_L3_OUTOFSERV then
    if tvbuf:range(19,1):uint() ~= 0 then
      imftree:add_proto_expert_info( ef_link_proto_error )
    end
  end
   
  return true
end

-- Dissects data payload from TRAFFIC messages subordinate to dissect_sonusimf_traffic_msg() below
dissect_sonusimf_payload = function(tvbuf, pktinfo, tree, payload_type )

  -- Choose subdissector 
  if payload_type == IMF_LINK_LSL or payload_type == IMF_LINK_ANNEXA or payload_type == IMF_LINK_M2PA
         or payload_type == IMF_LINK_M2UA or payload_type == IMF_LINK_ATM or payload_type == IMF_LINK_M3UA_SG
         or payload_type == IMF_LINK_M3UA_MG or payload_type == IMF_LINK_IPSP or payload_type == IMF_LINK_M3UA_SRV then
    if ed_mtp3 ~= nil then
      ed_mtp3:call(tvbuf:tvb(), pktinfo, tree)
    end
  elseif payload_type == IMF_LINK_M3UA then
    if ed_m3ua ~= nil then
      ed_m3ua:call(tvbuf:tvb(), pktinfo, tree)
    end
  elseif payload_type == IMF_LINK_SUA then
    if ed_sua ~= nil then
      ed_sua:call(tvbuf:tvb(), pktinfo, tree)
    end
  elseif payload_type == IMF_LINK_DIAMETER then
    if ed_diameter ~= nil then
      ed_diameter:call(tvbuf:tvb(), pktinfo, tree)
    end
  elseif payload_type == IMF_LINK_CICUA then
    if ed_data ~= nil then
      ed_data:call(tvbuf:tvb(), pktinfo, tree)
    end
  end

end

-- Dissects a Traffic-type IMF message subordinate to dissect_sonusimf() below
dissect_sonusimf_traffic_msg = function( tvbuf, pktinfo, root )

  local msu_len = tvbuf:range(21,2):uint()
  local tree = root:add( sonusimf, msu_len + 23, "Sonus IMF")

  -- Add the message type to the tree
  tree:add( pf_msg_type, tvbuf:range(0,1) )

  -- TODO : Not showing in UTC format yet.
  local nstime = NSTime( tvbuf:range(1,4):uint(), tvbuf:range(5,2):uint() * 1000000 )
  tree:add( pf_time, nstime )
  tree:add( pf_seq_num, tvbuf:range(7,4) )

  local link_media = tvbuf:range(18,1):uint()

  if link_media == IMF_LINK_DIAMETER then
    tree:add( pf_node_id, tvbuf:range(11,1) )
  elseif link_media == IMF_LINK_M3UA or link_media == IMF_LINK_SUA then
    tree:add( pf_asp_slot, tvbuf:range(11,1) )
  else
    tree:add( pf_na, tvbuf:range(11,1) )
  end

  -- Add SS7 Variant
  if link_media ~= IMF_LINK_M3UA and link_media ~= IMF_LINK_SUA then
    tree:add( pf_ss7_var, tvbuf:range(12,1) )
    if imf_ss7_var[ tvbuf:range(12,1):uint() ] == nil then
      tree:add_proto_expert_info( ef_invalid_variant )
    end
  end

  if link_media == IMF_LINK_LSL or link_media == IMF_LINK_ANNEXA or link_media == IMF_LINK_M2PA
         or link_media == IMF_LINK_M2UA or link_media == IMF_LINK_ATM or link_media == IMF_LINK_M3UA_MG 
         or link_media == IMF_LINK_M3UA_SRV then
    tree:add( pf_slc, tvbuf:range(13,1) )
    local apc = " " .. tvbuf(14,1):uint() .. "." .. tvbuf(15,1):uint() .. "." .. tvbuf(16,1):uint()
    tree:add( pf_apc, tvbuf:range(14,3) ):set_text( "APC " .. apc )
  elseif link_media == IMF_LINK_DIAMETER then
    tree:add( pf_adnc_id, tvbuf:range(13,4) )
  elseif link_media == IMF_LINK_M3UA or link_media == IMF_LINK_SUA then
    tree:add( pf_asp_id, tvbuf:range(13,4) )
  end

  -- Add MSU Direction
  tree:add( pf_msu_dir, tvbuf:range(17,1) )
  if imf_msu_dir[ tvbuf:range(17,1):uint() ] == nil then
    tree:add_proto_expert_info( ef_invalid_msu_dir )
  end

  -- Add and check Link Media
  local link_media = tvbuf:range(18,1):uint()
  tree:add( pf_link_media, tvbuf:range(18,1) )
  if imf_link_media[ link_media ] == nil then
    imftree:add_proto_expert_info( ef_invalid_link_media )
  end

  -- Add and check Reserved bytes (1 and 2)
  if link_media == IMF_LINK_DIAMETER then
    tree:add( pf_dsc_inst, tvbuf:range(19,1) )
    tree:add( pf_reserved2, tvbuf:range(20,1) )
    if tvbuf:range(20,1):uint() ~= 0 then
      tree:add_proto_expert_info( ef_invalid_rsvd_byte )
    end
  elseif link_media ~= IMF_LINK_M3UA and link_media ~= IMF_LINK_SUA then
    tree:add( pf_reserved2, tvbuf:range(19,2) )
    if tvbuf:range(19,2):uint() ~= 0 then
      tree:add_proto_expert_info( ef_invalid_rsvd_byte )
    end
  end

  -- Add MSU Length
  tree:add( pf_msu_len, tvbuf:range(21,2) )

  local msu_len = tvbuf:range(21,2):uint()
  -- Dissect payload
  dissect_sonusimf_payload( tvbuf(23, msu_len), pktinfo, root, link_media )

  return true

end
