#!/usr/sbin/dtrace -s
#pragma D option quiet

dtrace:::BEGIN
{
    printf("Starting... Hit Ctrl-C to end.\n");
}

objc$target:::entry
{
  this->selector = copyinstr(arg1);
}

objc$target:::entry /
                    this->selector != "retain" &&
                  this->selector != "release" /
{
    method = (string)&probefunc[1];
    type = probefunc[0];
    class = strjoin("[",probemod);
    classTmp = strjoin(class,"]");
    classmethod = strjoin(classTmp,method);

    printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu},",classmethod,"B",pid,tid,timestamp);
}

objc$target:::return /
                    this->selector != "retain" &&
                  this->selector != "release" /
{
    method = (string)&probefunc[1];
    type = probefunc[0];
    class = probemod;
    classmethod = strjoin(class,method);
    printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu},",classmethod,"E",pid,tid,timestamp);
}

