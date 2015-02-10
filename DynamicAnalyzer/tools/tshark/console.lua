-- console
-- A console and a window to execute commands in lua
--
-- (c) 2006 Luis E. Garcia Ontanon <luis@ontanon.org>
--
-- $Id$
-- 
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


if (gui_enabled()) then 
	-- Note that everything is "local" to this "if then" 
	-- this way we don't add globals

	-- Evaluate Window
	local function evaluate_lua()
		local w = TextWindow.new("Evaluate Lua")
		w:set_editable()

		-- button callback
		local function eval()
			-- get the window's text and remove the result 
			local text = string.gsub(w:get_text(),"%c*--%[%[.*--%]%]$","")

			-- if the text begins with '=' then convert = into return
			text = string.gsub(text,"^=","return ")

			-- evaluate text
			local result = assert(loadstring(text))()

			if (result ~= nil) then
				w:set(text .. '\n\n--[[ Result:\n' .. result .. '\n--]]')
			else
				w:set(text .. '\n\n--[[  Evaluated --]]')
			end
		end

	   w:add_button("Evaluate",eval)
	end

	local console_open = false

	local date = rawget(os,"date") -- use rawget to avoid disabled's os.__index

	if type(date) ~= "function" then
		-- 'os' has been disabled, use a dummy function for date
		date = function() return "" end
	end

	-- Console Window
	local function run_console()
		if console_open then return end
		console_open = true

		local w = TextWindow.new("Console")

		-- save original logger functions
		local orig = {
			critical = critical,
			warn = warn,
			message = message,
			info = info,
			debug = debug
		}

		-- define new logger functions that append text to the window
		function critical(x)  w:append( date() .. " CRITICAL: " .. tostring(x) .. "\n") end
		function warn(x)  w:append( date() .. " WARN: " .. tostring(x) .. "\n") end
		function message(x)  w:append( date() .. " MESSAGE: " .. tostring(x) .. "\n") end
		function info(x)  w:append( date() .. " INFO: " .. tostring(x) .. "\n") end
		function debug(x)  w:append( date() .. " DEBUG: " .. tostring(x) .. "\n") end

		-- when the window gets closed restore the original logger functions
		local function at_close()
			critical = orig.critical
			warn = orig.warn
			message = orig.message
			info = orig.info
			debug = orig.debug

			console_open = false
		end

		w:set_atclose(at_close)
		info("Console opened")
	end

	function ref_manual()
		browser_open_url("http://www.wireshark.org/docs/wsug_html_chunked/wsluarm.html")
	end
	
	function wiki_page()
		browser_open_url("http://wiki.wireshark.org/Lua")
	end

	register_menu("Lua/Evaluate", evaluate_lua, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Console", run_console, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Manual", ref_manual, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Wiki", wiki_page, MENU_TOOLS_UNSORTED)
end
