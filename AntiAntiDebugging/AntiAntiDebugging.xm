static int (*oldptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
static int (*oldsyscall)(long request, long pid, long addr, long data);
static const char* (*olddyld)(uint32_t image_index);
static int newptrace(int _request, pid_t _pid, caddr_t _addr, int _data){
if (request == 31) {
request = -1;
}
return oldptrace(request,pid,addr,data);
}


static int newsyscall(long request, long pid, long addr, long data) {
if (request == 26) {
return 0;
}
return oldsyscall(request,pid,addr,data);
}
static const char* newdyld(uint32_t image_index){
    const char* Name=olddyld(image_index);
    NSString* currentName=[NSString stringWithUTF8String:Name];
    if([currentName containsString:@"AntiAnti"]){//Hide Ourself.Needs to be implemented in more elegant method
        
        return olddyld(1);
    }
    else{
        
        return Name;
    }
    
    
}


%ctor {
MSHookFunction((void *)MSFindSymbol(NULL,"_ptrace"), (void *)newptrace, (void **)&oldptrace);
MSHookFunction((void *)MSFindSymbol(NULL,"_syscall"),(void *)newsyscall,(void **)&oldsyscall);
MSHookFunction((void *)MSFindSymbol(NULL,"__dyld_get_image_name"),(void *)newdyld,(void **)&olddyld);
}