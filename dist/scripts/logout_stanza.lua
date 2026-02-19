function logout() 
	bbs_write_string("\027[2J\027[1;1H");
	bbs_display_ansi("goodbye");
	return 1;
end
