

import lldb
import os
import shlex
import optparse
import subprocess
import sys
from stat import *

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f snoopie.handle_command snoopie -h "Profile stripped ObjC methods using DTrace"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Generates a DTrace sciprt that will only profile classes implemented
    in the main executable irregardless if binary is stripped or not.
    '''
    # command_args = shlex.split(command)
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return


    script = generateDTraceScript(exe_ctx.target, options)
    pid = exe_ctx.process.id
    filename = '/tmp/lldb_dtrace_profile_snoopiehahha.d'
    
    createOrTouchFilePath(filename, script)
    cmd = 'sudo {0}  -p {1}'.format(filename, pid)
    copycommand = 'echo \"{} \" |pbcopy'.format(cmd)
#    print(run_shell(cmd))
#    createOrTouchLogFilePath('/Users/zhangsuya/Downloads/mydtracedemo/tracetrace.appletrace',str(run_shell(copycommand)))
    
    os.system(copycommand)
    result.AppendMessage('Copied script to clipboard... paste in Terminal hahha')

#    out,error = proc.communicate()
    
#    result.AppendMessage(run_shell(copycommand))

def run_shell(shell):
    cmd = subprocess.Popen(shell, stdin=subprocess.PIPE, stderr=sys.stderr, close_fds=True,
                       stdout=sys.stdout, universal_newlines=True, shell=True, bufsize=1)

    cmd.communicate()
    
    return cmd.returncode

def createOrTouchFilePath(filepath, dtrace_script):
    file = open(filepath, "w")
    file.write(dtrace_script)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()

def createOrTouchLogFilePath(filepath, logstr):
    file = open(filepath, "w")
    file.write(logstr)
    file.flush()
    st = os.stat(filepath)
    file.close()

def generateDTraceScript(target, options):
    path = target.executable.fullpath
    section = target.module[path].section['__DATA']
    start_address = section.GetLoadAddress(target)
    end_address = start_address + section.size


      
    dataSectionFilter = '''{} <= *((uintptr_t *)copyin(arg0, sizeof(uintptr_t))) &&
                                *((uintptr_t *)copyin(arg0, sizeof(uintptr_t))) <= {}'''
                                
    if options.all:
        dataSectionFilter = '1'
    else:
        dataSectionFilter = dataSectionFilter.format(start_address, end_address)


    predicate = '''/ arg0 > 0x100000000 &&
    {} &&
    this->selector != "retain" &&
    this->selector != "release" /'''.format(dataSectionFilter)

    script = r'''#!/usr/sbin/dtrace -s
    #pragma D option quiet

    dtrace:::BEGIN
    {
        printf("Starting... Hit Ctrl-C to end.\n");
    }

    objc$target:::entry
    {
      this->selector = copyinstr(arg1);
    }

    objc$target:::entry ''' + predicate + r'''
    {
        method = (string)&probefunc[1];
        type = probefunc[0];
        class = strjoin("[",probemod);
        classTmp = strjoin(class,"]");
        classmethod = strjoin(classTmp,method);

        printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu},",classmethod,"B",pid,tid,timestamp);
    }

    objc$target:::return ''' + predicate + r'''
    {
        method = (string)&probefunc[1];
        type = probefunc[0];
        class = probemod;
        classmethod = strjoin(class,method);
        printf("{\"name\":\"%s\",\"cat\":\"catname\",\"ph\":\"%s\",\"pid\":\"%d\",\"tid\":%llu,\"ts\":%llu},",classmethod,"E",pid,tid,timestamp);
    }'''
    return script



def generate_option_parser():
    usage = "usage: %prog [options] snoopie"
    parser = optparse.OptionParser(usage=usage, prog="snoopie")
    parser.add_option("-a", "--all",
                      action="store_true",
                      default=False,
                      dest="all",
                      help="DTrace all Objective-C code instead of just the main executable")
    return parser
