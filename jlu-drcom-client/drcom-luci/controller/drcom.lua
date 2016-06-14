--[[
RA-MOD
]]--

module("luci.controller.drcom", package.seeall)

function index()
	
	if not nixio.fs.access("/etc/config/drcom") then
		return
	end

	local page

	page = entry({"admin", "services", "DrCOM"}, cbi("drcom"), _("DrCOM"), 45)
	page.i18n = "DrCOM"
	page.dependent = true
end
