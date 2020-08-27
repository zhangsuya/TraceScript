#!/usr/sbin/dtrace -s
#pragma D option quiet
dtrace:::BEGIN
{
    printf("Starting... Hit Ctrl-C to end.\n");
}

pid$target::objc_msgSend:entry
{
  this->selector = copyinstr(arg1);
}

pid$target::objc_msgSend:entry / arg0 > 0x100000000 &&
                    this->selector != "retain" &&
                  this->selector != "release" /
{
    size = sizeof(uintptr_t);
    this->isa = *((uintptr_t *)copyin(arg0, size));
    this->rax = *((uintptr_t *)copyin((this->isa + 0x20), size));
    this->rax =  (this->rax & 0x7ffffffffff8);
    this->rbx = *((uintptr_t *)copyin((this->rax + 0x38), size));
    this->rax = *((uintptr_t *)copyin((this->rax + 0x8),  size));
    this->rax = *((uintptr_t *)copyin((this->rax + 0x18), size));
    this->classname = copyinstr(this->rbx != 0 ?
                                 this->rbx  : this->rax);
    printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu}\n",this->selector,"B",pid,tid,timestamp);
//    printf("0x%016p +|-[%s %s]\n", arg0, this->classname,
//                                         this->selector);
}

pid$target::objc_msgSend:return / arg0 > 0x100000000 &&
                    this->selector != "retain" &&
                  this->selector != "release" /
{
    size = sizeof(uintptr_t);
    this->isa = *((uintptr_t *)copyin(arg0, size));
    this->rax = *((uintptr_t *)copyin((this->isa + 0x20), size));
    this->rax =  (this->rax & 0x7ffffffffff8);
    this->rbx = *((uintptr_t *)copyin((this->rax + 0x38), size));
    this->rax = *((uintptr_t *)copyin((this->rax + 0x8),  size));
    this->rax = *((uintptr_t *)copyin((this->rax + 0x18), size));
    this->classname = copyinstr(this->rbx != 0 ?
                                 this->rbx  : this->rax);
    printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu}",this->selector,"B",pid,tid,timestamp);
//    printf("0x%016p +|-[%s %s]\n", arg0, this->classname,
//                                         this->selector);
}

