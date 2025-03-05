import json
from cinspector.interfaces import CCode
import os
from cinspector.analysis import CallGraph
from cinspector.nodes import CompoundStatementNode, DeclarationNode, IfStatementNode,Edit, AssignmentExpressionNode, IdentifierNode, InitDeclaratorNode, ParenthesizedExpressionNode, FunctionDefinitionNode
import subprocess


code = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlmemory.h>
#include <libxml/parseFr.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parserInternals.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/xinclude.h>
#include <libxml/catalog.h>
#include <libxml/uri.h>
#include <libxml/valid.h>
#include <libxml/xmlsave.h>
#include <libxml/nanoftp.h>
#include <libxml/nanohttp.h>
#include <libxml/schemasInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlschemas.h>
#include <libxml/dict.h>
#include <libxml/pattern.h>
#include <libxml/hash.h>
#include <libxml/xmlversion.h>
#include <libxml/xmlschemastypes.h>



int main() {
    xmlXPathParserContextPtr ctxt = xmlXPathNewParserContext(NULL, NULL); // Create a new xmlXPathParserContextPtr

    // Assign a non-NULL value to ctxt->valueTab[ctxt->valueNr]
    ctxt->valueTab[ctxt->valueNr] = (xmlXPathObjectPtr) malloc(sizeof(xmlXPathObject));
    
    // Call the valuePop function
    xmlXPathObjectPtr ret = valuePop(ctxt);

    // Check the call status
    if (ret != NULL) {
        printf("Calling valuePop success\n");
        fflush(stdout);
    } else {
        printf("Calling valuePop fail\n");
        fflush(stdout);
        xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
        return 123;
    }

    xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
    return 0;
}
'''
errmsg1 = '''
before pcap_can_set_rfmon
Calling pcap_can_set_rfmon success

=================================================================
==133016==ERROR: AddressSanitizer: attempting double-free on 0x618000000080 in thread T0:
    #0 0x7ff5bd2b2537 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:127
    #1 0x55938e16d5a2 in main ../scripts/auto_gen/pcap_can_set_rfmon.c:43
    #2 0x7ff5bc97dd8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x7ff5bc97de3f in __libc_start_main_impl ../csu/libc-start.c:392
    #4 0x55938e16d264 in _start (../scripts/auto_gen/pcap_can_set_rfmon+0x1264)

0x618000000080 is located 0 bytes inside of 792-byte region [0x618000000080,0x618000000398)
freed by thread T0 here:
    #0 0x7ff5bd2b2537 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:127
    #1 0x55938e16d533 in main ../scripts/auto_gen/pcap_can_set_rfmon.c:30
    #2 0x7ff5bc97dd8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

previously allocated by thread T0 here:
    #0 0x7ff5bd2b2a57 in __interceptor_calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:154
    #1 0x7ff5bd1bf8ba in pcap_alloc_pcap_t pcap.c:2468
    #2 0x7ff5bd1bf8ba in pcap_create_common pcap.c:2507

SUMMARY: AddressSanitizer: double-free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:127 in __interceptor_free
==133016==ABORTING

'''
errmsg2 = '''
==337328== Memcheck, a memory error detector
==337328== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==337328== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==337328== Command: ./a.out
==337328== 
All devices freed successfully.
==337328== 
==337328== HEAP SUMMARY:
==337328==     in use at exit: 973 bytes in 36 blocks
==337328==   total heap usage: 57 allocs, 21 frees, 51,093 bytes allocated
==337328== 
==337328== 973 (40 direct, 933 indirect) bytes in 1 blocks are definitely lost in loss record 16 of 16
==337328==    at 0x4848899: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==337328==    by 0x486FF7A: add_dev (pcap.c:1316)
==337328==    by 0x4870147: find_or_add_dev (pcap.c:1268)
==337328==    by 0x4870220: find_or_add_if (pcap.c:1051)
==337328==    by 0x4870220: add_addr_to_if (pcap.c:1087)
==337328==    by 0x486D1E8: pcap_findalldevs_interfaces (fad-getad.c:266)
==337328==    by 0x486D062: pcap_platform_finddevs (pcap-linux.c:1753)
==337328==    by 0x4870386: pcap_findalldevs (pcap.c:723)
==337328==    by 0x10921F: main (test.c:10)
==337328== 
==337328== LEAK SUMMARY:
==337328==    definitely lost: 40 bytes in 1 blocks
==337328==    indirectly lost: 933 bytes in 35 blocks
==337328==      possibly lost: 0 bytes in 0 blocks
==337328==    still reachable: 0 bytes in 0 blocks
==337328==         suppressed: 0 bytes in 0 blocks
==337328== 
==337328== For lists of detected and suppressed errors, rerun with: -s
==337328== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
'''
errmsg3 = '''
==343012== Conditional jump or move depends on uninitialised value(s)
==343012==    at 0x1091B9: main (test.c:12)
==343012== 
Database opened successfully!
==343012== Conditional jump or move depends on uninitialised value(s)
==343012==    at 0x48D9C85: sqlite3Close (sqlite3.c:176110)
==343012==    by 0x109207: main (test.c:20)
==343012== '''

errmsg4 = '''
Database opened successfully!'''

errmsg5 = '''valuePop.c:38:35: runtime error: store to null pointer of type 'struct xmlXPathObject *'
AddressSanitizer:DEADLYSIGNAL
=================================================================
==37161==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55c0c08fd4bf bp 0x7ffc32094870 sp 0x7ffc32094850 T0)
==37161==The signal is caused by a WRITE memory access.
==37161==Hint: address points to the zero page.
    #0 0x55c0c08fd4bf in main ../scripts/auto_gen/valuePop.c:38
    #1 0x7f7af3348d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #2 0x7f7af3348e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #3 0x55c0c08fd244 in _start (../scripts/auto_gen/valuePop+0x1244)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../scripts/auto_gen/valuePop.c:38 in main
==37161==ABORTING
'''

# valgrind_no_use = ['Conditional jump or move depends on uninitialised value', 'Syscall param', 'Use of uninitialised value of size']
valgrind_no_use = []

# for valgrind
# return True: has error, return False: no error
def parse_errmsg(code, errmsg):
    if errmsg.find('==') == -1:
        return False, ''
    if errmsg.find('AddressSanitizer') != -1:
        return True, errmsg
    tmp_lines = errmsg.strip('\n').split('\n')
    errmsg_lines = list()
    # remove irrelevant lines
    for line in tmp_lines:
        if len(line) < 2:
            continue
        if line[0] == '=' and line[1] == '=':
            errmsg_lines.append(line)

    # get dif reason of err
    errmsg_part = list()
    new_part = ''
    for line in errmsg_lines:

        tmp = line.strip()

        if len(tmp) < 2:
            print('code error, check')
            exit(1)
        if tmp[-1] == '=' and tmp[-2] == '=':
            if new_part != '':
                errmsg_part.append(new_part)
            new_part = ''
            continue
        new_part += line
        new_part += '\n'
    i  =0
    if new_part != '' and new_part not in errmsg_part:
        errmsg_part.append(new_part)
    # if len(errmsg_part) > 0:
    error_flag = False
    parsed_messages = ''
    for part in errmsg_part:
        i += 1

        hit_flag = False
        for info in valgrind_no_use:
            uninit = part.find(info)
            if uninit != -1:
                hit_flag = True
                break
        if not hit_flag:
            parsed_messages += part
            error_flag = True

    return error_flag, parsed_messages

def get_error_code(code, errmsg, api, file_name):

    code = code.replace('\\n', '')
    # file_name = api + '.c'
    code_lines = code.strip('\n').split('\n')

    i = -1
    while 1:
        i += 1
        if i >= len(code_lines):
            break

    errmsg_lines = errmsg.strip('\n').split('\n')
    error_related_code = list()
    msg_related_list = list()
    err_index = 0
    for err in errmsg_lines:
        err_index += 1
        begin_index = err.find(file_name)
        if begin_index == -1:
            continue

        
        num_str = err[begin_index+ len(file_name) + 1: ]

        end_index = begin_index+ len(file_name) + 1
        for ch in list(num_str):
            if ch.isdigit():
                end_index += 1
                continue
            else:
                break

        if end_index == len(err):
            
            num_str = err[begin_index+ len(file_name) + 1: ]
        else:
            num_str = err[begin_index+ len(file_name) + 1: end_index]

        try:
            num = int(num_str)
        except:
            continue

        if num <= len(code_lines):
            i = -1
            while 1:
                i += 1
                if i >= len(code_lines):
                    break

            if code_lines[num - 1] != '':
                msg_related_list.append(err_index)
                error_related_code.append(code_lines[num - 1])

        # else:
        #     print('error parse')
        #     print(len(code_lines))
        #     print('num: ', num)

    return error_related_code, msg_related_list


def check_err_stack(err_lines, hit_index, api, other_fc):
    
    err_index = 0
    err_stack = list()
    target_name = api + '.c'

    for line in err_lines:
        err_index += 1
        
        if (line.find(' in ') != -1 and line.find('==') == -1 ) or (line.find('==') != -1 and (line.find('at 0x') != -1 or line.find('by 0x') != -1)):
            
            err_stack.append(line)
        elif line.find('#') != -1:
            begin = line.find('#')
            tmp_num = list(line)[begin + 1]

            if tmp_num.isdigit():
                err_stack.append(line)
        else:
            err_stack = list()
        if err_index == hit_index:
            break
    if len(err_stack) == 0:

        return False

    new_err_stack = list()
    for line in err_stack:
        new_err_stack.append(line)

        if line.find(target_name) != -1:
            break
    if len(new_err_stack) != len(err_stack):
        return False

    parse_flag = False
    for line in new_err_stack:

        if line.find(target_name) != -1:
            continue
        hit_other = False
        for fc in other_fc:

            if line.find(fc) != -1:

                hit_other = True
                break
        if hit_other != False:

            return False
        else:
            parse_flag = True
    if parse_flag:
        return True
    else:
        return False
    

        
    

def if_api_related(code, errmsg, api, filename, fc_list, compile_cmd_in):

    fc_list = []

    # exit(1)
    not_use, errmsg = parse_errmsg(code, errmsg)
    if errmsg.find(filename) == -1 and compile_cmd_in != '':
        tmp_code = './tmp.c'
        with open(tmp_code, 'w') as f:
            f.write(code)
        compile_cmd = compile_cmd_in.replace(api, 'tmp')
        os.system(compile_cmd)
        run_cmd = 'valgrind --leak-check=full --quiet ./tmp_val'
        return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out, err = return_info.communicate()
        errmsg = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    errmsg = errmsg.replace('before ' + api, 'BEFORE_FLAG')
    errmsg = errmsg.replace('Calling ' + api, 'CALLING_FLAG')

    err_lines = errmsg.split('\n')
    if errmsg.find(filename) == -1 and errmsg.find('tmp.c') == -1:

        skip_flag = False
        for line in err_lines:
            if line.find(' in ') != -1 and line.find('.c') != -1:

                skip_flag = True
                break
        if not skip_flag:

            if errmsg.find('CALLING_FLAG') == -1 and errmsg.find('BEFORE_FLAG') != -1:
                return True
            else:
                return False
        
        else:

            for fc in fc_list:
                match_str = 'in ' + fc
                if errmsg.find(match_str) != -1:
                    return True
    code_list, hit_err_lines = get_error_code(code, errmsg, api, filename)

    


    hit_flag = False
    other_fc = list()
    i = 0
    for item in code_list:
        hit_flag = False
        cc = CCode(item)
        fc = cc.get_by_type_name('call_expression') 
        hit_err_line = hit_err_lines[i]
        for c in fc:
            fc_name = c.function.src
            if fc_name == api:
                hit_flag = True
                
            else:
                other_fc.append(fc_name)
        if hit_flag:


            if check_err_stack(err_lines, hit_err_line, api, other_fc):

                return True
        else:
            other_fc = list()
        i += 1
    
    hit_index = 0
    for line in err_lines:
        hit_index += 1
        if line.find('in ' + api) != -1:
            if check_err_stack(err_lines, hit_index, api, []):
                    return True
    
    return False


def print_code(code):
    code_lines = code.strip('\n').split('\n')
    i = 1
    for code in code_lines:
        print(str(i) + ': ' + code + '\n')
        i += 1

if __name__ == '__main__':

    code_compile = '''
    #include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parserInternals.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/xinclude.h>
#include <libxml/catalog.h>
#include <libxml/uri.h>
#include <libxml/valid.h>
#include <libxml/xmlsave.h>
#include <libxml/nanoftp.h>
#include <libxml/nanohttp.h>
#include <libxml/schemasInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlschemas.h>
#include <libxml/dict.h>
#include <libxml/pattern.h>
#include <libxml/hash.h>
#include <libxml/xmlversion.h>
#include <libxml/xmlschemastypes.h>



int main() {
    const char *buffer = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root></root>";
    size_t size = strlen(buffer);
    const char *URL = "example.xml";

    printf("before xmlSAXParseMemory");
    fflush(stdout);

    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if (ctxt == NULL) {
        printf("Failed to create parser context");
        fflush(stdout);
        return 123;
    }
    
    xmlDocPtr doc = xmlSAXParseMemory(ctxt->sax, buffer, size, 0);
    if (doc == NULL) {
        printf("Calling xmlSAXParseMemory fail");
        fflush(stdout);
        xmlFreeParserCtxt(ctxt);
        return 123;
    }

    printf("Calling xmlSAXParseMemory success");
    fflush(stdout);

    xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);

    // Violation of the rule by passing malicious data
    const char* maliciousData = "<root><unclosed></root>";
    xmlSAXParseMemory(ctxt->sax, maliciousData, strlen(maliciousData), 0);

    return 0;
}




'''
    errmsg_compile = '''
   before xmlSAXParseMemory
Calling xmlSAXParseMemory success

=================================================================
==400589==ERROR: AddressSanitizer: heap-use-after-free on address 0x617000000080 at pc 0x55a423d0157d bp 0x7ffd2addc830 sp 0x7ffd2addc820
READ of size 8 at 0x617000000080 thread T0
    #0 0x55a423d0157c in main ../scripts/auto_gen/xmlSAXParseMemory.c:65
    #1 0x7f6b1b3bad8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #2 0x7f6b1b3bae3f in __libc_start_main_impl ../csu/libc-start.c:392
    #3 0x55a423d01224 in _start (../scripts/auto_gen/xmlSAXParseMemory+0x1224)

0x617000000080 is located 0 bytes inside of 760-byte region [0x617000000080,0x617000000378)
freed by thread T0 here:
    #0 0x7f6b1be07537 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:127
    #1 0x55a423d01504 in main ../scripts/auto_gen/xmlSAXParseMemory.c:61
    #2 0x7f6b1b3bad8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

previously allocated by thread T0 here:
    #0 0x7f6b1be07887 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x7f6b1bc4d35c in xmlNewSAXParserCtxt ../repos/libxml2/parserInternals.c:2126

SUMMARY: AddressSanitizer: heap-use-after-free ../scripts/auto_gen/xmlSAXParseMemory.c:65 in main
Shadow bytes around the buggy address:
  0x0c2e7fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c2e7fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c2e7fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c2e7fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c2e7fff8000: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c2e7fff8010:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c2e7fff8020: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c2e7fff8030: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c2e7fff8040: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c2e7fff8050: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c2e7fff8060: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==400589==ABORTING


'''

    errmsg = '''
Direct leak of 1296 byte(s) in 2 object(s) allocated from:
    #0 0x7f653336aa57 in __interceptor_calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:154
    #1 0x7f6533278fd5 in pcap_open_dead_with_tstamp_precision pcap.c:4435

SUMMARY: AddressSanitizer: 1296 byte(s) leaked in 2 allocation(s).
==9838== 648 bytes in 1 blocks are definitely lost in loss record 1 of 2
==9838==    at 0x484DA83: calloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9838==    by 0x4871FD5: pcap_open_dead_with_tstamp_precision (pcap.c:4435)
==9838==    by 0x1093F3: main (wrong_pcap_dump_flush7.c:42)
==9838== 
==9838== 648 bytes in 1 blocks are definitely lost in loss record 2 of 2
==9838==    at 0x484DA83: calloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==9838==    by 0x4871FD5: pcap_open_dead_with_tstamp_precision (pcap.c:4435)
==9838==    by 0x10941E: main (wrong_pcap_dump_flush7.c:43)
==9838== 


    '''
    code = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_dumper_t* dumper;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        printf("Error opening live capture: %s", errbuf);
        fflush(stdout);
        return 123;
    }

    printf("before pcap_dump_flush");
    fflush(stdout);

    dumper = pcap_dump_open(handle, "example.pcap");
    if (dumper == NULL) {
        printf("Error opening dump file: %s", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }

    // Write captured packets to the dump file

    if (pcap_dump_flush(dumper) == -1) {
        printf("Calling pcap_dump_flush failed: %s", pcap_geterr(handle));
        fflush(stdout);
        pcap_dump_close(dumper);
        pcap_close(handle);
        return 123;
    }

    pcap_dumper_t* p1 = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), "example.pcap");
    pcap_dumper_t* p2 = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), "example2.pcap");
    pcap_dump_flush(p1);
    pcap_dump_flush(p2);
    
    pcap_dump_close(p1); // Added line to close p1 before reassignment
    p1 = p2;
    pcap_dump_flush(p1);

    pcap_dump_close(p2); // Added line to close p2
    pcap_dump_close(dumper);
    pcap_close(handle);

    printf("Calling pcap_dump_flush success");
    fflush(stdout);

    return 0;
}


    '''
    call_list = ["pcap_platform_finddevs", "pcap_freealldevs"]

    
    # with