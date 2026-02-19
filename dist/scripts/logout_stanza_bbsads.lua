-- To use this with Magicka, replace the logout_stanza.lua in your
-- MagickaBBS/scripts directory. 

-- You could also git pull as a cronjob to grab the latest ansis say
-- once a week.

-- Requirements:
-- You will need an uptodate git version of Magicka for it to work. 

function scandir(directory)
    local i, t, popen = 0, {}, io.popen
    local pfile = popen('find "'..directory..'" -maxdepth 1 -type f')
    for filename in pfile:lines() do
		if string.lower(string.sub(filename, -4)) == ".ans" then
			i = i + 1
			t[i] = filename
		end
    end
    pfile:close()
    return t
end

function logout() 
	-- Change this to your adverts directory...
	local t = scandir("/home/andrew/bbs-ansi-adverts/adverts");
	local rand = math.random(#t);
	
	bbs_write_string("\027[2J\027[1;1H");
	
	bbs_display_ansi(t[rand]);
	
	bbs_write_string("\027[0mPress any key to continue...");
	bbs_read_char();
	
	bbs_write_string("\027[2J\027[1;1H");
	
	bbs_display_ansi("goodbye");
	os.execute("sleep 1");
	return 1;
end
