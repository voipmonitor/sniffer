----------------------------------------
-- script-name: sonuscm.lua
--
-- author: bwilson, ckaramalis
-- Copyright (c) Sonus Networks, 2015, 2016
--
-- Version: 1.1 (Released in 15.0)
--   * initial release, provides dissection of SonusCM packets.
-- Version: 2.0 (Released in 15.2)
--   * Handles multiple messages per packet and messages that spill over different packets
--   Requires Wireshark 2.0 and above to work
--
-- OVERVIEW:
-- This script creates a dissector for SonusCM.   It can be disabled by turning off the 
-- the heuristic and port dissectors using in the SonusCM preferences.   
--
-- HOW TO INSTALL THIS SCRIPT:
--       For Windows :
--           * Install Wireshark version 1.12.0 or later.
--           * Copy this file to the appropriate directory  
--				For wireshark 2.0 or later:
--					C:\Users\<username>\AppData\Roaming\Wireshark\plugins (create directory if needed)
-- 
--       For Linux:
--           * Ensure that Wireshark is compiled with Lua.
--           * Copy this file to the /usr/local/share/wireshark directory
--           * Add the following lines to the end of the /usr/local/share/wireshark/init.lua file 
---                 dofile(USER_DIR.."sonuscm.lua")
-- 
--       Installing Wireshark from source for Linux:
--           * yum install lua
--           * yum install lua-devel
--           * Download and uncompress Wireshark source code.
--           * Run ./configure --with-lua
--           * make
--           * make install
-- 
--

module( "sonuscm", package.seeall )

local FPM_MSG_HDR_LEN = 4

-- Default preferences
local default_settings =
{
    ports             = "",
    heuristic_enabled = true
}

-- a heuristic dissector table for myProto
local sonuscm_heuristic_table = {}

-- a function to register into myProto's heuristic table
function register_heuristic(func)
    sonuscm_heuristic_table[#sonuscm_heuristic_table + 1] = func
end


----------------------------------------
-- Verify that the version of Wireshark is correct.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 9) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

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
local sonuscm = Proto("sonuscm","SonusCM Protocol")
local sonuscmTCP = Proto("sonuscmTCP","SonusCP TCP Protocol")
local sonuscmTIPC = Proto("sonuscmTIPC","SonusCP TIPC Protocol")

----------------------------------------
-- message commands
local sonuscm_msg_cmds = {
        [0] = "No Command",
        [1] = "Pulse",
        [2] = "Pulse-Ack"
}

local sonuscm_msg_errors = {
		[0] = "Packet is truncated. Unable to decode"
}

-- create the protocol fields
local pf_msg_class    = ProtoField.new("Message Class",   "sonuscm.msg_class",   ftypes.UINT8,  nil, base.DEC, 0x0, "Message Class (Reserved for future use (must be zero))")
local pf_msg_command  = ProtoField.new("Message Command", "sonuscm.msg_command", ftypes.UINT8,  sonuscm_msg_cmds, base.DEC, 0x0, "Message Command" )
local pf_msg_len      = ProtoField.new("Message Length",  "sonuscm.msg_len", ftypes.UINT16, nil, base.DEC, 0x0, "Message Length" )
local pf_msg_error    = ProtoField.new("Decoding Error",  "sonuscm.msg_errors", ftypes.UINT8, sonuscm_msg_errors, base.DEC, 0x0, "Decoding error" )


----------------------------------------
-- register ALL protocol fields
sonuscm.fields = { pf_msg_class, pf_msg_command, pf_msg_len, pf_msg_error }

----------------------------------------
-- create some expert info fields (this is new functionality in 1.11.3)
-- Expert info fields are very similar to proto fields: they're tied to our protocol,
-- they're created in a similar way, and registered by setting a 'experts' field to
-- a table of them just as proto fields were put into the 'sonuscm.fields' above
local ef_too_long = ProtoExpert.new("sonuscm.too_long.expert", "Length is too long.  Not enough bytes to decode.",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_invalid_msg_command = ProtoExpert.new("sonuscm.invalid_msg_command.expert", "Message Command invalid",
                                     expert.group.MALFORMED, expert.severity.WARN)
local ef_invalid_msg_class = ProtoExpert.new("sonuscm.invalid_msg_class.expert", "Message Class invalid",
                                     expert.group.MALFORMED, expert.severity.WARN)

-- register them
sonuscm.experts = { ef_too_long, ef_invalid_msg_command, ef_invalid_msg_class }

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- defines whether or not the heuristic dissector will be called for TCP packets
sonuscm.prefs.heuristic_enabled  = Pref.bool("Heuristic dissecotor enabled", default_settings.heuristic_enabled,
                            "Enable the heuristic dissector for TCP and TIPC packets")

-- TCP Ports to force dissection on.  
sonuscm.prefs.ports  = Pref.range("Manual TCP Ports", default_settings.ports,
                            "The port-based dissector forces dissection on these ports",60000)



----------------------------------------
-- a function for handling prefs being changed
function sonuscm.prefs_changed()

    default_settings.heuristic_enabled = sonuscm.prefs.heuristic_enabled

    -- have the port settings changed?
    if default_settings.ports ~= sonuscm.prefs.ports then
        -- remove the old preferences, if they exist
        if default_settings.ports ~= nil then
			message( "removing the old port preferences" )
            DissectorTable.get("tcp.port"):remove(default_settings.ports, sonuscm)
        end
        -- set our new default
        default_settings.ports = sonuscm.prefs.ports
        -- add new one, if not 0
        if default_settings.ports ~= nil then
			message( "adding the new preferences "..default_settings.ports )
            DissectorTable.get("tcp.port"):add(default_settings.ports, sonuscm)
        end
    end


end

----------------------------------------
---- some constants for later use ----
-- the SCM header size
local SCM_HDR_LEN = 4


local function do_the_dissecting(tvbuf, pktinfo,root)
    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("SonusCM")
	-- get the length of the packet
    local pktlen = tvbuf:reported_length_remaining()
	-- now let's check it's not too short
    if pktlen < SCM_HDR_LEN then
       tree:add_proto_expert_info(ef_too_short)
       return
    end  
	local offset = 0
	
	-- We start by adding our protocol to the dissection display tree.
        -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
        -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
        -- case (Sonus CM protocol) that's the remainder of the packet.
        local tree = root:add(sonuscm, tvbuf:range(0,SCM_HDR_LEN), "SonusCM")
        -- Add the one byte message class
        tree:add( pf_msg_class, tvbuf:range(offset,1) )
	    offset = offset + 1
        -- Add the one byte message command
        tree:add( pf_msg_command, tvbuf:range(offset,1) )
	   	offset = offset + 1
        -- Now let's add our message length.
	    local mlen = tvbuf:range(offset,2):uint()
		tree:add( pf_msg_len, tvbuf:range(offset,2) )
	
	    --offset = offset + 2
		
		if mlen>tvbuf:len() then
			tree:add( pf_msg_error, 0 )
			return offset+mlen
		end
	    if mlen ~= 0 then
	        -- call the heuristic dissector functions of my sub protocols
            -- with the portion of the tvb that belongs to them
	        for _, func in ipairs(sonuscm_heuristic_table) do
                -- call the heuristic
		        local result = func(tvbuf:range(4,mlen):tvb(), pktinfo, tree)
                if result == true then
			        break
                end
			end
		end		
		offset = offset + mlen
	return offset
end

local function get_msg_len(tvbuf, pktinfo, offset)
	local lengthTvbr = tvbuf:range(2+offset,2)
	local lengthVal = lengthTvbr:uint()
	return lengthVal+4
end


----------------------------------------
-- The following creates the callback function for the dissector.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function sonuscm.dissector(tvbuf,pktinfo,root)
	local offset = 0
	dissect_tcp_pdus(tvbuf, root,4, get_msg_len, do_the_dissecting, true)
	offset = tvbuf:len()
    --offset = do_the_dissecting(tvbuf, pktinfo, root)

    -- tell wireshark how much of tvbuff we dissected
    return offset
end



----------------------------------------
-- we want to have our protocol dissection invoked for a specific TCP port.
DissectorTable.get("tcp.port"):add(default_settings.ports, sonuscm)

----------------------------------------
-- heuristic function
local function heur_dissect_sonuscm(tvbuf,pktinfo,root)
	
    -- if our preferences tell us not to do this, return false
    if not default_settings.heuristic_enabled then
        return false
    end

    -- is there enough data for a header
    if tvbuf:len() < SCM_HDR_LEN then
        return false
    end

    -- the msg clss must be 0
    if tvbuf:range(0,1):uint() ~= 0 then
       return false
    end

    -- the msg command must be less than 3
    if tvbuf:range(1,1):uint() > 2 then
       return false
    end
	
	-- decode the message length and make sure it's not too big.
    local msg_len  = tvbuf:range(2,2):uint()
	--print(msg_len)
	--print(tvbuf:len())
    --if msg_len > tvbuf:len() - 4 then 
    --    return true
	--	return 
    --end 
	--pktinfo.desegment_len = msg_len - tvbuf:len()
    -- ok, looks like it's ours, so go dissect it
	
    sonuscm.dissector(tvbuf,pktinfo,root)

    -- since this is over a transport protocol, such as TCP, we can set the
    -- conversation to make it sticky for our dissector, so that all future
    -- packets to/from the same address:port pair will just call our dissector
    -- function directly instead of this heuristic function
    -- this is a new attribute of pinfo in 1.11.3
    pktinfo.conversation = sonuscm 
    return true
end

-- register the heuristic dissector into the tcp and tipc heuristic list.  if preferences
-- are turned off then we check that in the heuristic function rather than deregistering
-- the heuristic
sonuscmTCP:register_heuristic("tcp",heur_dissect_sonuscm)
sonuscmTIPC:register_heuristic("tipc",heur_dissect_sonuscm)


