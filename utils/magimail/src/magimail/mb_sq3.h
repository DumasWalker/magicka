bool sq3_beforefunc(void);
bool sq3_afterfunc(bool success);
bool sq3_importfunc(struct MemMessage *mm,struct Area *area);
bool sq3_exportfunc(struct Area *area,bool (*handlefunc)(struct MemMessage *mm));
bool sq3_rescanfunc(struct Area *area,uint32_t max,bool (*handlefunc)(struct MemMessage *mm));
