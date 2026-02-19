#if defined(ENABLE_WWW)

#include <limits.h>
#include <sys/stat.h>
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

extern struct bbs_config conf;

int lw_dataPath(lua_State *L) {
	char buffer[PATH_MAX];
	struct stat s;
	snprintf(buffer, PATH_MAX, "%s/data/", conf.script_path);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	lua_pushstring(L, buffer);

	return 1;
}

void www_push_cfunctions(lua_State *L) {
	lua_pushcfunction(L, lw_dataPath);
	lua_setglobal(L, "bbs_data_path");
}

char *www_script_parse(struct MHD_Connection *connection, char *script) {
	char buffer[PATH_MAX];
	struct stat s;
	char *lRet;
	int result;
	lua_State *L;

	if (strchr(script, '/') != NULL || strchr(script, '.') != NULL) {
		return NULL;
	}

	snprintf(buffer, PATH_MAX, "%s/www/%s.lua", conf.script_path, script);

	if (stat(buffer, &s) != 0) {
		return NULL;
	}
	L = luaL_newstate();
	luaL_openlibs(L);
	www_push_cfunctions(L);
	luaL_loadfile(L, buffer);
	result = lua_pcall(L, 0, 0, 0);
	if (result) {
		lua_close(L);
		return NULL;
	}

	lua_getglobal(L, "www");
	result = lua_pcall(L, 0, 1, 0);
	if (result) {
		lua_close(L);
		return NULL;
	}

	char *data = strdup(lua_tostring(L, -1));
	lua_close(L);

	return data;
}

#endif