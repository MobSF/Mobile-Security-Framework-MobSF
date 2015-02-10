-- dtd_gen.lua
--
-- a DTD generator for wireshark
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

if gui_enabled() then
	local xml_fld = Field.new("xml")

	local function dtd_generator()
		local displayed = {} -- whether or not a dtd is already displayed
		local dtds = {} -- the dtds
		local changed = {} -- whether or not a dtd has been modified
		local dtd -- the dtd being dealt with
		local dtd_name -- its name

		-- we'll tap onto every frame that has xml

		local ws = {} -- the windows for each dtd
		local w = TextWindow.new("DTD Generator")

		local function help()
			local wh = TextWindow.new("DTD Generator Help")
			-- XXX write help
			wh:set('DTD Generator Help\n')
		end

		local function get_dtd_from_xml(text,d,parent)
		-- obtains dtd information from xml
		--   text: xml to be parsed
		--   d: the current dtd (if any)
		--   parent: parent entity (if any)

			-- cleanup the text from useless chars
			text = string.gsub(text ,"%s*<%s*","<");
			text = string.gsub(text ,"%s*>%s*",">");
			text = string.gsub(text ,"<%-%-(.-)%-%->"," ");
			text = string.gsub(text ,"%s+"," ");

			while true do
				-- find the first tag
				local open_tag = string.match(text,"%b<>")

				if open_tag == nil then 
					-- no more tags, we're done
					return true
				end

				local name = string.match(open_tag,"[%w%d_-]+")
				local this_ent = nil

				if d == nil then
					-- there's no current dtd, this is entity is it
					d = dtds[name]

					if d == nil then
						d = {ents = {}, attrs = {}}
						dtds[name] = d
					end

					dtd = d
					dtd_name = name
				end

				this_ent = d[name]

				if this_ent == nil then
					-- no entity by this name in this dtd, create it
					this_ent = {ents = {}, attrs = {}}
					d.ents[name] = this_ent
					changed[dtd_name] = true
				end

				if parent ~= nil then
					-- add this entity to its parent
					parent.ents[name] = 1
					changed[dtd_name] = true
				end
				
				-- add the attrs to the entity
				for att in string.gmatch(open_tag, "([%w%d_-]+)%s*=") do
					if not this_ent.attrs[att] then
						changed[dtd_name] = true
						this_ent.attrs[att] = true
					end
				end

				if string.match(open_tag,"/>") then
					-- this tag is "self closed" just remove it and continue
					text = string.gsub(text,"%b<>","",1)
				else
					local close_tag_pat = "</%s*" .. name .. "%s*>"
					if not string.match(text,close_tag_pat) then return false end
					local span,left = string.match(text,"%b<>(.-)" .. close_tag_pat .. "(.*)")

					if span ~= nil then
						-- recurse to find child entities
						if not get_dtd_from_xml(span,d,this_ent) then
							return false
						end
					end

					-- continue with what's left
					text = left
				end
			end

			return true
		end

		local function entity_tostring(name,entity_data)
		-- name: the name of the entity
		-- entity_data: a table containg the entity data
		-- returns the dtd text for that entity
			local text = ''
			text = text .. '\t<!ELEMENT ' .. name .. '  (' --)
			for e,j in pairs(entity_data.ents) do
				text = text .. " " .. e .. ' |'
			end
			text = text .. " #PCDATA ) >\n"
			
			text = text .. "\t<!ATTLIST " .. name
			for a,j in pairs(entity_data.attrs) do
				text = text .. "\n\t\t" .. a .. ' CDTATA #IMPLIED'
			end
			text = text .. " >\n\n"
			
			text = string.gsub(text,"<!ATTLIST " .. name .. " >\n","")
			
			return text
		end

		local function dtd_tostring(name,doctype) 
			local text = '<? wireshark:protocol proto_name="' .. name ..'" hierarchy="yes" ?>\n\n'
			local root = doctype.ents[name]
			doctype.ents[name] = nil

			text = text .. entity_tostring(name,root)
			
			for n,es in pairs(doctype.ents) do
				text = text .. entity_tostring(n,es)
			end

			doctype.ents[name] = root

			return text
		end


		local function element_body(name,text)
		-- get the entity's children from dtd text
		--    name: the name of the element
		--    text: the list of children
			text = string.gsub(text,"[%s%?%*%#%+%(%)]","")
			text = string.gsub(text,"$","|")
			text = string.gsub(text,
							   "^(.-)|",
							   function(s)
									if dtd.ents[name] == nil then
									   dtd.ents[name] = {ents={},attrs={}}
									end
							   
									dtd.ents[name].ents[s] = true
									return ""
							   end
							   )
			return ''
		end

		local function attlist_body(name,text)
		-- get the entity's attributes from dtd text
		--    name: the name of the element
		--    text: the list of attributes
		text = string.gsub(text,"([%w%d_-]+) [A-Z]+ #[A-Z]+",
								function(s)
									dtd.atts[s] = true
									return ""
								end
								)
			return ''
		end

		local function dtd_body(buff)
		-- get the dtd's entities from dtd text
		--    buff: the dtd text

			local old_buff = buff

			buff = string.gsub(buff,"<!ELEMENT ([%w%d_-]+) (%b())>%s*",element_body)
			buff = string.gsub(buff,"<!ATTLIST ([%w%d_-]+) (.-)>%s*",attlist_body)
		end

		local function load_dtd(filename)
			local dtd_filename = USER_DIR ..  "/dtds/" .. filename
			local buff = ''
			local wireshark_info

			dtd_name = nil
			dtd = nil

			for line in io.lines(dtd_filename) do
				buff = buff .. line
			end

			buff = string.gsub(buff ,"%s*<%!%s*","<!");
			buff = string.gsub(buff ,"%s*>%s*",">");
			buff = string.gsub(buff ,"<!%-%-(.-)%-%->"," ");
			buff = string.gsub(buff ,"%s+"," ");
			buff = string.gsub(buff ,"^%s+","");


			buff = string.gsub(buff,'(<%?%s*wireshark:protocol%s+.-%s*%?>)',
							   function(s)
									wireshark_info = s
							   end
							   )

			buff = string.gsub(buff,"^<!DOCTYPE ([%w%d_-]+) (%b[])%s*>",
							   function(name,body) 
								   dtd = { ents = {}, attrs = {}}
								   dtd_name = name
								   
								   dtds[name] = dtd
								   
								   dtd_body(body)
								   
								   return ""
							   end
							   )

			if not dtd then
				dtd_body(buff)
			end
			
			if wireshark_info then
				dtd.wstag = wireshark_info
			end
		end

		local function load_dtds()
		-- loads all existing dtds in the user directory
			local dirname = persconffile_path("dtds")
			local status, dir = pcall(Dir.open,dirname,".dtd")

			 w:set('Loading DTDs from ' .. dirname .. ' \n')

			if not status then
				w:append("Error: could not open the directory" .. dirname .. " , make sure it exists.\n")
				return
			end
						 
			for dtd_filename in dir do
				w:append("File:" .. dtd_filename .. "\n")
				load_dtd(dtd_filename)
			end

		end

		local function dtd_window(name)
			return function()
				local wd = TextWindow.new(name .. '.dtd')
				wd:set(dtd_tostring(name,dtds[name]))
				wd:set_editable()

				local function save()
					local file = io.open(persconffile_path("dtds/") .. name .. ".dtd" ,"w")
					file:write(wd:get_text())
					file:close()
				end
				
				wd:add_button("Save",save)
			end
		end

		local function close()
			if li ~= nil then
				li:remove()
				li = nil
			end
		end

		w:set_atclose(close)

		-- w:add_button("Help",help)

		load_dtds()

		local li = Listener.new("frame","xml")

		w:append('Running')

		function li.packet() 
			w:append('.')
			local txt = xml_fld().range:string();
			get_dtd_from_xml(txt)
		end

		function li.draw()

			for name,j in pairs(changed) do
				w:append("\n" .. name .. " has changed\n")
				if not displayed[name] then
					w:add_button(name,dtd_window(name))
					displayed[name] = true
				end
			end
		end

		retap_packets()
		 w:append(t2s(dtds))
		w:append('\n')

	end

	register_menu("DTD Generator",dtd_generator,MENU_TOOLS_UNSORTED)
end
