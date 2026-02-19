#include <assert.h>
#include <stddef.h>

#include "bbs.h"

static inline struct mail_conference *get_conf(size_t c) {
	extern struct bbs_config conf;
	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, c);
	assert(mc != NULL);
	return mc;
}

static inline struct mail_conference *get_user_conf(struct user_record *user) {
	assert(user != NULL);
	return get_conf(user->cur_mail_conf);
}

static inline struct mail_area *get_area(size_t c, size_t a) {
	struct mail_conference *mc = get_conf(c);
	struct mail_area *ma = ptr_vector_get(&mc->mail_areas, a);
	assert(ma != NULL);
	return ma;
}

static inline struct mail_area *get_user_area(struct user_record *user) {
	assert(user != NULL);
	return get_area(user->cur_mail_conf, user->cur_mail_area);
}
