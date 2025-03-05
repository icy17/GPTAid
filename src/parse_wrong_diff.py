import sys
import json
import os
from cinspector.interfaces import CCode
from cinspector.analysis import CallGraph
from cinspector.nodes import CompoundStatementNode, DeclarationNode, IfStatementNode,Edit, AssignmentExpressionNode, IdentifierNode, InitDeclaratorNode, ParenthesizedExpressionNode, FunctionDefinitionNode
import difflib
import re
import copy

blob_code2 = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>




int main() {
    CURL *curl = curl_easy_init();
    if (curl) {
        printf("before curl_ws_send\n");
        fflush(stdout);

        const void *buffer = "Hello, world!";
        size_t buflen = 1000000000; // Excessively large buflen value
        size_t sent;
        curl_off_t fragsize = 1024;
        unsigned int flags = 0;

        curl_ws_send(curl, buffer, buflen, &sent, fragsize, flags);

        printf("Calling curl_ws_send\n");
        fflush(stdout);

        curl_easy_cleanup(curl);
    } else {
        printf("curl_easy_init failed\n");
        fflush(stdout);
        return 123;
    }

    return 0;
}

'''

blob_code1 = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>


int main() {
    CURL *curl = curl_easy_init();
    if (curl) {
        printf("before curl_ws_send\n");
        fflush(stdout);

        const void *buffer = "Hello, world!";
        size_t buflen = strlen(buffer);
        size_t sent = 0;
        curl_off_t fragsize = 1024;
        unsigned int flags = 0;

        CURLcode res = curl_ws_send(curl, buffer, buflen, &sent, fragsize, flags);
        if (res == CURLE_OK) {
            printf("Calling curl_ws_send success\n");
        } else {
            printf("Calling curl_ws_send fail: %s\n", curl_easy_strerror(res));
        }
        fflush(stdout);

        curl_easy_cleanup(curl);
    } else {
        printf("curl_easy_init failed\n");
        fflush(stdout);
        return 123;
    }

    return 0;
}
'''
def if_valid_return(code):
    cc = CCode(code)
    returns = cc.get_by_type_name('return_statement')
    # print(returns)
    for return_stat in returns:

        number_literal = return_stat.children_by_type_name('number_literal')
        if len(number_literal) == 0:
            continue
        number_literal = number_literal[0].src
        if number_literal.find('0x') != -1:
            number = int(number_literal, 16)
        else:
            number = int(number_literal)
        if number != 0 and number != 123:
            return False, number_literal
    return True, 0

def read_json(in_path):
    # in_list = list()
    out_list = list()
    with open(in_path, 'r') as f:
        tmp_list = f.readlines()
    for line in tmp_list:
        line = line.strip('')
        line_json = json.loads(line)
        out_list.append(line_json)
    return out_list

bindint1 =  '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>
int main() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        printf("Failed to open database: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        return 123;
    }

    rc = sqlite3_exec(db, "CREATE TABLE example_table (column1 INTEGER)", NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to create table: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    rc = sqlite3_prepare_v2(db, "INSERT INTO example_table (column1) VALUES (?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    int value = 42;
    rc = sqlite3_bind_int(stmt, 1, value);
    if (rc != SQLITE_OK) {
        printf("Calling sqlite3_bind_int fail\n");
        fflush(stdout);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 123;
    }

    printf("Calling sqlite3_bind_int success\n");
    fflush(stdout);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}
'''

bindint2 = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

int main() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        printf("Failed to open database: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        return 123;
    }

    rc = sqlite3_exec(db, "CREATE TABLE example_table (column1 INTEGER)", NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to create table: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    rc = sqlite3_prepare_v2(db, "INSERT INTO example_table (column1) VALUES (?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    printf("before sqlite3_bind_int\n"); // Added printf statement before sqlite3_bind_int

    int value = 42;
    rc = sqlite3_bind_int(stmt, 1, value);
    if (rc != SQLITE_OK) {
        printf("Calling sqlite3_bind_int fail\n");
        fflush(stdout);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 123;
    }

    printf("Calling sqlite3_bind_int success\n");
    fflush(stdout);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}'''

valuePop1 = '''
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
    xmlXPathParserContextPtr ctxt = xmlXPathNewParserContext(NULL, NULL); // Create a new xmlXPathParserContextPtr

    printf("before valuePop"); // Add the printf statement before the valuePop function

    // Call the valuePop function
    xmlXPathObjectPtr ret = valuePop(ctxt);

    // Check the call status
    if (ret != NULL) {
        printf("Calling valuePop success");
        fflush(stdout);
    } else {
        printf("Calling valuePop fail");
        fflush(stdout);
        xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
        return 123;
    }

    xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
    return 0;
}
'''

valuePop2 = '''

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

    // Call the valuePop function
    xmlXPathObjectPtr ret = valuePop(ctxt);

    // Check the call status
    if (ret != NULL) {
        printf("Calling valuePop success");
        fflush(stdout);
    } else {
        printf("Calling valuePop fail");
        fflush(stdout);
        xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
        return 123;
    }

    xmlXPathFreeParserContext(ctxt); // Free the xmlXPathParserContextPtr
    return 0;
}
'''
wrong_code1 = '''
#include <stdio.h>
#include <pcap.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create("eth0", errbuf); // create handle
    if (handle == NULL)
    {
        printf("Error creating handle: %s", errbuf);
        return -1;
    }

    int rfmon = pcap_can_set_rfmon(handle); // check if rfmon is supported
    if (rfmon < 0)
    {
        printf("Error checking rfmon support: %s", pcap_geterr(handle));
        return -1;
    }

    printf("rfmon is %ssupported", rfmon ? "" : "not ");

    pcap_close(handle); // close handle

    return 0;
}
'''

wrong_code2 = '''

#include <stdio.h>
#include <pcap.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // create handle
    if (handle == NULL)
    {
        printf("Error creating handle: %s", errbuf);
        return -1;
    }

    int rfmon = pcap_can_set_rfmon(handle); // check if rfmon is supported
    if (rfmon < 0)
    {
        printf("Error checking rfmon support: %s", pcap_geterr(handle));
        return -1;
    }

    printf("rfmon is %ssupported", rfmon ? "" : "not ");

    pcap_close(handle); // close handle

    return 0;
}

'''
wrong_code2_1 = '''
#include <stdlib.h>

void pcap_free_tstamp_types(int *tstamp_type_list);

int main() {
    int *tstamp_type_list = malloc(sizeof(int) * 3); // example list
    pcap_free_tstamp_types(tstamp_type_list);
    return 0;
}
'''

wrong_code2_2 = '''
#include <stdlib.h>

void pcap_free_tstamp_types(int *tstamp_type_list);

int main() {
    int *tstamp_type_list = malloc(sizeof(int) * 3); // example list
    free(tstamp_type_list); // violating the specification by freeing the list after passing it to the function
    pcap_free_tstamp_types(tstamp_type_list);
    return 0;
}'''

right_code3_2 = '''
#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"

int main(){
    sqlite3* db;
    char* err_msg;
    int rc = sqlite3_open("example.db", &db);
    if(rc != SQLITE_OK){
        printf("Error opening database: %s", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS my_table(id INT PRIMARY KEY NOT NULL, name TEXT NOT NULL);", NULL, 0, &err_msg);
    if(rc != SQLITE_OK){
        printf("Error creating table: %s", err_msg);
        fflush(stdout);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 123;
    }

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, "SELECT * FROM my_table", -1, &stmt, NULL);
    if(rc != SQLITE_OK){
        printf("Error preparing statement: %s", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    int explain = sqlite3_stmt_isexplain(stmt);
    if (explain == 1) {
        printf("Invalid value returned by sqlite3_stmt_isexplain");
        fflush(stdout);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 123;
    }
    printf("explain: %d", explain);
    fflush(stdout);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}
'''
right_code3_1 = '''
#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"

int main(){
    sqlite3* db;
    char* err_msg;
    int rc = sqlite3_open("example.db", &db);
    if(rc != SQLITE_OK){
        printf("Error opening database: %s", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS my_table(id INT PRIMARY KEY NOT NULL, name TEXT NOT NULL);", NULL, 0, &err_msg);
    if(rc != SQLITE_OK){
        printf("Error creating table: %s", err_msg);
        fflush(stdout);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 123;
    }

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, "SELECT * FROM my_table", -1, &stmt, NULL);
    if(rc != SQLITE_OK){
        printf("Error preparing statement: %s", sqlite3_errmsg(db));
        fflush(stdout);
        sqlite3_close(db);
        return 123;
    }

    int explain = sqlite3_stmt_isexplain(stmt);
    printf("explain: %d", explain);
    fflush(stdout);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}
'''

def read_json(in_path):
    # in_list = list()
    out_list = list()
    with open(in_path, 'r') as f:
        tmp_list = f.readlines()
    for line in tmp_list:
        line = line.strip('')
        line_json = json.loads(line)
        out_list.append(line_json)
    return out_list

def del_comment(cc1: CCode, code1: str):
    # basic_edit = Edit(cc1.node)
    comments = cc1.get_by_type_name('comment')
    byte_list = list()
    if len(comments) == 0:
        return code1
    for comment in comments:
        
        start_byte = comment.internal.start_byte
        end_byte = comment.internal.end_byte
        info_dict = dict()
        info_dict['start'] = start_byte
        info_dict['end'] = end_byte
        byte_list.append(info_dict)
        # # print('comment:')
        # # print(code1[start_byte + 1: end_byte + 2])
        # new_cc = basic_edit.remove_child(comment)
    out_code = ''
    for comment in byte_list:
        comment_index = byte_list.index(comment)
        if comment_index == 0:
            out_code = code1[: comment['start']]
        else:
            before_dict = byte_list[comment_index - 1]
            before_end = before_dict['end']
            out_code = out_code + code1[before_end + 1 : comment['start']]
        if comment_index == len(byte_list) - 1:
            out_code = out_code + code1[comment['end'] + 1: ]
    # print(out_code)
    return out_code

def get_tree(cc: CCode):
    # # print(cc)
    funcs = cc.get_by_type_name_and_query('function_definition', {'identifier': 'main'})
    funcs_other = cc.get_by_type_name('function_definition')
    if len(funcs) == 0:
        return [], []
    func = funcs[0]
    children_list = func.body.children
    # print(children_list)
    # exit(1)
    type_list = list()
    for child in children_list:
        type_list.append(type(child))
    #     # print(child)
    #     # print(type(child))
        # # print(child.children)
    
    for func in funcs_other:
        # print(func.name.src)
        if func.name.src == 'main':
            continue
        children_list.extend(func.body.children)
        declaration = func.children_by_type_name('function_declarator')[0]
        children_list.append(declaration)
        type_list.append(type(declaration))
        # # print(func.body.children)
        # type_list = list()
        for child in children_list:
            type_list.append(type(child))
    # exit(1)
    return children_list, type_list

    # return []

# need to know change code, change code loc
# TODO:change
def diff_code(code1:str, code2:str, flag_target):
    loc = 0
    change_code = []
    
    # if delete/add child:
    d = difflib.Differ()
    re = list(d.compare(code1.splitlines(keepends=True), code2.splitlines(keepends=True)))
    for item in re:
        # print(item)
        flag = item[0]
        # item = item[1:]
        if flag != flag_target:
            continue
        if item[1:].strip().strip('') == '':
            continue

        # # print(list(item))
        # break
        # if item
        # # print(item)
        change_code.append(item[1:].strip().strip(''))
    # # print(re)
    # for child in tree_list2:
        
    # # print(tree_list)
    # comment = cc1.get_by_type_name('comment')
    # # print(after_del)
    return change_code

def get_target_str(target_node, api):
    out_dict = dict()
    type_dict = dict()
    # # print('in get_target_str')
    # print(target_node)
    fcs = target_node.children_by_type_name('call_expression')
    if len(fcs) == 0:
        # # print('get_target_str fc not 1!')
        # print(fcs)
        # print(target_node)
        # exit(1)
        return None, None
        # exit(1)
    fc = None
    # print(api)
    for fc_tmp in fcs:
        name = fc_tmp.function.src
        # print(name)
        if name.strip() == api.strip():
            fc = fc_tmp
    if fc == None:
        # print('in get_target_str, cannot find API call in this Node:')
        # print(target_node.src)
        return None, None
    # fc = fcs[0]
    parent = fc.parent
    # get arguments:
    arguments = fc.arguments
    # 获取API 调用的所有参数名
    for argument in arguments:
        
        # print("arg name")
        # print(argument)
        # print(type(argument))
        a_index = arguments.index(argument)
        type_dict['arg' + str(a_index)] = type(argument)
        # if a_index == 3:
        #     exit(1)
        if type(argument) == IdentifierNode:
            out_dict['arg' + str(a_index)] = argument.src
        else:
            values = argument.children_by_type_name('identifier')
            # print(type(argument.src))
            # print(argument.src)
            if len(values) != 1:
                # # print('error when parse identifier')
                # # print(target_node)
                # # print(argument)
                # # print(values)
                value = 'constant'
                out_dict['arg' + str(a_index)] = '___CONSTANT-' + argument.src
            else:
                value = values[0]
                out_dict['arg' + str(a_index)] = value.src
    # # print(parent)
    # 获取目标API调用的返回值相关变量
    if parent.equal(target_node):
        out_dict['ret'] = -1
    else:
        if type(parent) == AssignmentExpressionNode:
            # # print(parent.print_tree())
            ret_value = parent.left.src
            out_dict['ret'] = ret_value
        elif type(parent) == InitDeclaratorNode:
            declarator = parent.declarator
            if type(declarator) != IdentifierNode:
                declarator = declarator.children_by_type_name('identifier')[0]
            out_dict['ret'] = declarator.src
        elif type(parent) == ParenthesizedExpressionNode:
            out_dict['ret'] = fc.function.src
        else:
            out_dict['ret'] = fc.function.src
            # # print(type(ret_value))
            # # print(type(parent))
            # # print('assign')
        # # print('no ret')
    # # print(fc)
    # print(out_dict)
    # exit(1)
    return out_dict, type_dict

def get_line_names(code_line):
    cc = CCode(code_line)
    names = cc.get_by_type_name('identifier')
    out_list = list()
    for name in names:
        name = name.src
        out_list.append(name)
    return out_list

def del_comment_re(code):
    bds0 = '//.*'               #标准匹配单行注释
    bds1 = '\/\*(?:[^\*]|\*+[^\/\*])*\*+\/'  #标准匹配多行注释  可匹配跨行注释

    target0 = re.compile(bds0)  #单行注释
    target = re.compile(bds1)   #编译正则表达式

    result0 =target0.findall(code)
    # # print("单行注释：")
    # for i in result0:
    #     # print(i)

    result = target.findall(code)
    # # print("多行注释：")
    # for i in result:
    #     # print(i)
    result+=result0
    # # print(f'删除前：{data}')
    for i in result:
        code = code.replace(i,'')  #替换为空字符串
    # # print(f'删除后：{data}')
    return code

# code1:orig, code2: after change, api: target api, rule: violate rule
def auto_check(code1, code2, api, target_arg):
    target_times = code1.count(api)
    target_times2 = code2.count(api)
    if target_times != target_times2:
        return True, 'Add/Del target API', 'in', dict()
    # TODO: check if the code after change has target API
    if code2.find(api) == -1:
        return False, 'No Target API: ' + api, '', dict()
    
    cc1 = CCode(code1.strip(''))
    cc2 = CCode(code2.strip(''))
    # # print(cc1.node.internal_src)
    after_del1 = del_comment_re(code1)
    after_del2 = del_comment_re(code2)
    cc1 = CCode(after_del1)
    cc2 = CCode(after_del2)
    # after_del1 = code1
    # after_del2 = code2
    # # print(api)
    # # print(after_del2)
    tree_list1, type_list1 = get_tree(cc1)
    tree_list2, type_list12 = get_tree(cc2)
    target_dict1 = dict()
    target_dict2 = dict()
    for child in tree_list1:
        src = child.src
        if src.find(api) != -1:
            target_dict1, type_dict1 = get_target_str(child, api)
            if target_dict1:
                break
    for child in tree_list2:
        src = child.src
        if src.find(api) != -1:
            target_dict2, type_dict2 = get_target_str(child, api)
            if target_dict2:
                break
            # break
    if len(target_dict1.keys()) == 0:
        return False, 'No Target API in right code: ' + api, '', dict()
    # # print('target_dict1')
    # # print(target_dict1)
    # # print(target_dict2)
    change_code = diff_code(after_del1, after_del2, '+')
    # # print(change_code)
    change_lines_dict = dict()
    code_lines = list()
    code_in = code2.split('')
    fc_line = ''
    for line in code_in:
        line = line.strip()
        code_lines.append(line)
        if line.find(api) != -1 and line.find('printf') == -1:
            fc_line = line
        # # print(line)
    # # print(code_lines)
    i = 0
    for key in target_dict2.keys():
        i += 1
        target_str = target_dict2[key]
        # # print(target_str)
        change_lines_dict[key] = list()
        for line in change_code:
            # # print(line)
            code_line = line[1:].strip()
            # if i == 1:
            #     code_lines.append(code_line)
            # # print(code_line)
            for child in tree_list2:
                src = child.src
                ce_list = child.children_by_type_name('call_expression')
                # # print(ce_list)
                skip_flag = False
                for ce in ce_list:
                    if ce.function == api:
                        skip_flag = True
                        break
                
                if skip_flag:
                    # # print('api:')
                    # # print(src)
                    fc_line = src.split('')[0]
                    continue
                
                # # print(src)
                # # print('code line:' + code_line)
                # # print(code_line)
                if code_line.find(src) != -1 or src.find(code_line) != -1:
                    # # print('in')
                    identifiers = child.children_by_type_name('identifier')
                    # # print(identifiers)
                    for identifier in identifiers:
                        name = identifier.src
                        if name == target_str:
                            change_lines_dict[key].append(code_line)
    # # print(change_lines_dict)
    # # print('fc_line: ')
    # # print(fc_line)
    # if fc_line == '':
        
    for key in target_dict2.keys():
        if target_dict2[key] != target_dict1[key]:
            # print(target_dict1[key])
            # print(target_dict2[key])
            change_lines_dict[key].append(fc_line)
    # # print(change_lines_dict)
    change_index = list()
    for line in code_lines:
        if line.find(fc_line) != -1:
            fc_line_index = code_lines.index(line)
            break
    
    for key in change_lines_dict.keys():
        if len(change_lines_dict[key]) != 0:
            change_index.append(key)
    if target_arg == '':
        loc_info = 'after'
        for line in code_lines:
            if code_lines.index(line) > fc_line_index:
                break
            else:
                if change_code[0][0] == '-':
                    target = change_code[1][1:].strip()
                else:
                    target = change_code[0][1:].strip()
                # # print(target)
                if line.find(target) != -1:
                    loc_info = 'before'
        return False, 'Parse Rule Wrong', loc_info, change_lines_dict
    # target_str1 = target_dict1[target_arg]
    target_str2 = target_dict2[target_arg]
    # if len(change_index) > 1:
    #     return False, 'More Than One', '', change_lines_dict
        # # print()
    loc_list = list()
    if len(change_index) == 0:
        return False, 'No Change', '', change_lines_dict
    else:
        if target_arg in change_index:
            re_lines = list()
            first_flag = True
            for change_line in change_lines_dict[target_arg]:
                change_line = change_line.split('')[0]
                # # print(code_lines)
                # print(change_line)
                # print('fc:')
                # print(code_lines[fc_line_index])
                for line in code_lines:
                    # if line == 'if(BN_mask_bits(a, 4)) {':
                    #     # print('hit?')
                    #     # print(line)
                    #     # print(change_line)
                    if line != '' and (line.find(change_line) != -1 or change_line.find(line) != -1):
                        # print('hit!')
                        # print(line)
                        change_line_index = code_lines.index(line)
                        break
                # change_line_index = code_lines.index(change_line)
                # if api == 'BN_mask_bits' and target_arg == 'ret':
                #     # print(change_line_index)
                #     # print(fc_line_index)
                # print(change_line_index)
                # print(fc_line_index)
                if change_line_index > fc_line_index and first_flag:
                    # print(change_line_index)
                    # # print(fc_line_index)
                    # print('change line after fc_line!')
                    # loc_list.append('after')
                    return True, '', 'after', change_lines_dict
                if change_line_index == fc_line_index and first_flag:
                    return True, '', 'in', change_lines_dict
                # else:
                #     loc_list.append('before')

                del_flag = False
                in_codes = ''
                for line in code_lines:
                    if code_lines.index(line) > change_line_index and code_lines.index(line) < fc_line_index:
                        in_codes = in_codes + line + ''
                # # print(get_line_names(in_codes))
                # # print(target_str2)
                if target_str2 in get_line_names(in_codes):
                    # # print('flag true')
                    del_flag = True
                if not del_flag:
                    re_lines.append(change_line)
                first_flag = False
            # # print(re_lines)
            if len(re_lines) != 0:      
                return True, '', 'before', change_lines_dict
            else:
                return False, 'The modified code is too far ahead, affecting the execution of other code.', 'before', change_lines_dict
        else:
            return False, 'Change Wrong: ' + change_index[0], '', change_lines_dict
        


def if_api_exists(code, api):
    cc_d = CCode(code)
    fcs = cc_d.get_by_type_name('call_expression')
    hit_flag = False
    for fc in fcs:
        name = fc.function.src
        if name == api:
            hit_flag = True
            break

    return hit_flag

def get_parameter_list(declaration):
    cc_d = CCode(declaration)
    func_decla = cc_d.get_by_type_name('function_declarator')
    
    if len(func_decla) != 0:
        func_decla = func_decla[0]
    else:
        return [], 1
    # print(func_decla)
    fc_name = func_decla.declarator.src
    parameter_list = cc_d.get_by_type_name('parameter_declaration')
    # parameter_list1 = copy.deepcopy(parameter_list)
    # print(parameter_list)
    # # print(parameter_)
    for parameter in parameter_list[:]:
        func_name = parameter.parent.parent.declarator.src
        # # print(type(parameter.parent.parent))
        if func_name != fc_name:
            parameter_list.remove(parameter)
    parameter_info = list()
    # print(parameter_list)
    for parameter in parameter_list:
        para_type = parameter.type.src
        # print(para_type)
        # if len(para_type) == 0:
        #     para_type = parameter.children_by_type_name('type_identifier')
        #     if len(para_type) == 0:
        #         # print('declaration type wrong!')
        #         # print(parameter)
        #         # print(declaration)
        #         # print(parameter.type)
        #     else:
        #         para_type = para_type[0].src
        # else:
        #     para_type = para_type[0].src
        if parameter.name == None:
            continue
            # print(parameter)
            # print(declaration)
            # print(para_type)
        name = parameter.name.src
        para_dict = dict()
        para_dict['type'] = para_type
        para_dict['name'] = name
        parameter_info.append(para_dict)
    return parameter_info, 0

def macro_or_func(declaration):
    cc_d = CCode(declaration)
    func_decla = cc_d.get_by_type_name('function_declarator')
    if len(func_decla) == 0:
        return 'macro'
    else:
        return 'func'

def get_pre_para_list(declaration):
    cc_d = CCode(declaration)
    func_decla = cc_d.get_by_type_name('preproc_function_def')
    
    if len(func_decla) != 0:
        func_decla = func_decla[0]
    else:
        return [], 1
    # print(func_decla)
    fc_name = func_decla.name.src
    parameter_list = cc_d.get_by_type_name('preproc_params')
    # parameter_list1 = copy.deepcopy(parameter_list)
    # print(parameter_list)
    # # print(parameter_)
    for parameter in parameter_list[:]:
        func_name = parameter.parent.name.src
        # print(type(parameter.parent))
        if func_name != fc_name:
            parameter_list.remove(parameter)
    parameter_info = list()
    # print(parameter_list)
    for parameter in parameter_list:
        # print(parameter)
        name = parameter.children_by_type_name('identifier')[0].src
        para_dict = dict()
        para_dict['type'] = ''
        para_dict['name'] = name
        parameter_info.append(para_dict)
    return parameter_info, 0

def get_related_index(rule):
    prefix = 'Parameter'
    begin = rule.find(prefix)
    out_list = list()
    end = rule.find(':')
    nums_str = rule[begin + len(prefix) : end]
    # print(nums_str)
    num_list = nums_str.split(',')
    for num_str in num_list:
        try:
            num = int(num_str)
            out_list.append(num)
        except:
            continue
    return out_list

def parse_rule(rule, declaration):
    para_indexs = get_related_index(rule)
    if len(para_indexs) == 0:
        return parse_rule_before(rule, declaration)
    out_list = list()
    loc_info = ''
    if rule.find('after') != -1 or rule.find('later') != -1:
        loc_info = 'after'
    elif rule.find('before') != -1:
        loc_info = 'before'
    else:
        loc_info = ''
    for para_index in para_indexs:
        out_list.append('arg' + str(para_index - 1))
    return out_list, loc_info

def parse_rule_before(rule, declaration):
    arg_list = list()
    cc_d = CCode(declaration)
    rule = rule.replace('*', '')
    rule = rule.replace('&', '')
    rule = rule.strip('.')
    func_decla = cc_d.get_by_type_name('function_declarator')
    if rule.find('after') != -1 and rule.find('before') != -1:
        loc_info = ''
    elif rule.find('after') != -1 or rule.find('later') != -1 or rule.find('no longer') != -1:
        loc_info = 'after'
    else:
        loc_info = 'before'
    if len(func_decla) != 0:
        func_decla = func_decla[0]
    else:
        return [], loc_info
    # # print(func_decla)
    start = func_decla.internal.start_byte
    ret_type = declaration[: start]
    loc_info = ''
    # if rule.find('before') != -1:
    #     loc_info = 'before'
    
    
    
    
    # # print(loc_info)
    # exit(1)
    
    parameter_list = cc_d.get_by_type_name('parameter_declaration')
    # parameter_list1 = copy.deepcopy(parameter_list)
    # # print(parameter_list)
    for parameter in parameter_list[:]:
        p = parameter.parent.parent.parent
        if type(p) != DeclarationNode:
            parameter_list.remove(parameter)
    # print(parameter_list)
    # exit(1)
    word_list = rule.split(' ')
    # print(word_list)
    hit_list = list()
    parameter_info = list()
    # print(parameter_list)
    for parameter in parameter_list:
        # print(parameter)
        # para_type = parameter.children_by_type_name('primitive_type')
        # if len(para_type) == 0:
        #     para_type = parameter.children_by_type_name('type_identifier')
        #     if len(para_type) == 0:
        #         # print('declaration type wrong!')
        #         # print(declaration)
        para_type = parameter.type.src
        if parameter.name == None:
            continue
            # print(parameter)
            # print(declaration)
            # print(para_type)
        name = parameter.name.src
        para_dict = dict()
        para_dict['type'] = para_type
        para_dict['name'] = name
        parameter_info.append(para_dict)
        # print(para_type)
        # print(name)
        # print(para_type + ' ' + name)
    # parse rule
    
        for word in word_list:
            word = word.strip('`')
            word = word.strip('"')
            # # print('word:')
            # # print(word)
            if word == para_type or word == name or word == para_type + ' ' + name:
                hit_list.append(parameter_list.index(parameter))
    # print('hit:')
    hit_list = list(set(hit_list))
    # print(hit_list)
    if len(hit_list) == 1 and rule.find('`') == -1 and rule.find('return value') == -1:
        if loc_info == '':
            loc_info = 'before'
        return ['arg' + str(hit_list[0])], loc_info
    else:
        for item in hit_list:
            name1 = '`' + parameter_info[item]['name'] + '`'
            type1 = '`' + parameter_info[item]['type'] + '`'
            name2 = '"' + parameter_info[item]['name'] + '"'
            type2 = '"' + parameter_info[item]['type'] + '"'
            name3 = '`' + parameter_info[item]['type'] + ' ' + parameter_info[item]['name'] + '`'
            # print(name1)
            # print(type1)
            # print(name2)
            # print(type2)
            # print(name3)
            if name1 in word_list or type1 in word_list or name2 in word_list or type2 in word_list:
                if loc_info == '':
                    loc_info = 'before'
                arg_list.append('arg' + str(item))
            if rule.find(name3) != -1:
                if loc_info == '':
                    loc_info = 'before'
                arg_list.append('arg' + str(item))
        # # print(loc_info)
        # exit(1)
        if len(arg_list) == 0:
            if rule.find('return value') != -1 or rule.find('ret value') != -1 or rule.find('return') != -1:
                return ['ret'], 'after'
        return arg_list, loc_info
    return [], loc_info

# 用于生成和目标API调用相关的所有变量的名字（可能会多，但是没关系）。如果有多个调用，则返回结果是多个调用的变量集合
# output: {begin_index: , end_index, related_str: {ret: [], arg0: []}}
def get_target_paraname(code, api):
    cc = CCode(code.strip(''))
    # print('before get tree')
    # print(code)
    child_list, type_list = get_tree(cc)
    target_out = list()
    for child in child_list:
        code_src = child.src
        # 这个子node可能包含API，可以进行后续处理
        if code_src.find(api) != -1:
            # 尝试获取该疑似API调用节点的相关变量名
            target_dict, type_dict = get_target_str(child, api)
            # print(target_dict)
            # exit(1)
            # 如果该节点有目标fc，则加入到最终的结果中
            if target_dict != None:
                new_dict = dict()
                # # print(child.internal.start_byte)
                # # print(child.internal.end_byte)
                new_dict['begin_index'] = child.internal.start_byte
                new_dict['end_index'] = child.internal.end_byte
                new_dict['related_str'] = target_dict
                new_dict['related_type'] = type_dict
                new_dict['src'] = child.src
                # print(new_dict)
                # exit(1)
                target_out.append(new_dict)
    return target_out
                    
# output: [{src: , node: , begin_index: , end_index: , identifiers: []}]
def get_identifier(code, code_list):
    cc = CCode(code)
    # print('before get_tree')
    # # print(code)
    # exit(1)
    child_list, type_list = get_tree(cc)
    # # print(child_list)
    # # print(type_list)
    # exit(1)
    out_list = list()
    # # print(code_list)
    for code_item in code_list:
        # print('match code: ')
        # print(code_item)
        cc_child = CCode(code_item)
        target_identifiers = cc_child.get_by_type_name('identifier')
        for child in child_list:
            code_src = child.src
            if code_src.find(code_item) != -1 or code_item.find(code_src) != -1:
                # if type(child) == IfStatementNode:
                #     continue
                # print('Match!!')
                # print(type(child))
                # print(code_src)
                # if code_item == 'size_t buflen = 1000000000;':
                #     exit(1)
                new_dict = dict()
                new_dict['src'] = code_src
                new_dict['node'] = child
                new_dict['begin_index'] = child.internal.start_byte
                new_dict['end_index'] = child.internal.end_byte
                new_dict['identifiers'] = list()
                # identifiers_node = child.children_by_type_name('identifier')
                for identifier in target_identifiers:
                    id_name = identifier.src
                    new_dict['identifiers'].append(id_name)
                if len(new_dict['identifiers']) != 0:
                    # print(new_dict)
                    out_list.append(new_dict)
    # exit(1)
    # print(out_list)
    # exit(1)
    return out_list 
# dict1:{begin_index: , end_index, related_str: {ret: [], arg0: []}}
# dict2:{src: , node: , begin_index: , end_index: , identifiers: []}
# 需要判断dict2的node相对于dict1来说是before还是after
def get_loc_info(dict1, dict2):
    # print('in get_loc_info')
    # print(dict1)
    # print(dict2)
    # exit(1)
    target_begin = dict1['begin_index']
    target_end = dict1['end_index']

    change_begin = dict2['begin_index']
    change_end = dict2['end_index']
    change_len = change_end - change_begin
    target_len = target_end - target_begin
    if change_len == target_len and abs(change_begin - target_begin) < 5 and dict1['src'].strip() == dict2['src']:
        return ''

    if change_end <= target_end:
        return 'before'
    else:
        if change_begin >=target_end:
            return 'after'
    return 'before'

def get_line_index(identifier_index, code):
    # print(len(code))
    # print(identifier_index)
    begin = code.rfind('\n', 0, identifier_index)
    end = code.find('\n', identifier_index)
    return code[begin: end]

def if_far(target_identifier, change_begin_index, change_end_index, api_index, code):
    cc = CCode(code)
    # print('if_far')
    # print(code)
    # print(change_begin_index)
    # print(change_end_index)
    # print(api_index)
    max_start = -1
    identifiers = cc.get_by_type_name('identifier')
    for id in identifiers:
        name = id.src
        if name != target_identifier:
            continue
        # print(id)
        start_index = id.internal.start_byte
        
        end_index = id.internal.end_byte
        # print(start_index)
        # print(end_index)
        if start_index >= change_end_index and start_index <= api_index:
            # print(start_index)
            if start_index > max_start:
                if get_line_index(api_index, code) != get_line_index(start_index, code):
                    max_start = start_index
                    # print(get_line_index(api_index, code))
                    # print(get_line_index(start_index, code))
                else:
                    break
            # return True
    if max_start != -1:
        # # print(code)
        # print(get_line_index(max_start, code))
        # print(get_line_index(api_index, code))
        # print(get_line_index(change_begin_index, code))
        # exit(1)
        return True, get_line_index(max_start, code)
    # # print(identifiers)
    # exit(1)
    return False, ''

def auto_check2_add(wrong_code1, wrong_code2, target_api, declaration, rule):
    # 1.获取目标rule涉及到的所有可能parameter/ret
    target_list, loc_rule = parse_rule(rule, declaration)
    # # print(target_list)
    # exit(1)
    # # print(target_list)
    # # print(loc_rule)
    # exit(1)
    if len(target_list) == 0:
        return True, 'parse arg wrong, target_list is empty', loc_rule, target_list, None, None,''
    if wrong_code2.find(target_api) == -1:
        # print('Wrong! No target API!')
        return False, 'No target API!', loc_rule, target_list, None, None,''
    # 2.通过diff判断两个代码中哪些parameter/ret发生了修改
    # output：{arg0: [], ret: [...]}
    change_dict = dict()
    wrong_code1 = del_comment_re(wrong_code1)
    wrong_code2 = del_comment_re(wrong_code2)

    # # print(wrong_code1)
    # {begin_index: , end_index, related_str: {ret: [], arg0: []}}
    target_str_list_2 = get_target_paraname(wrong_code2, target_api)
    target_str_list_1 = get_target_paraname(wrong_code1, target_api)
    
    # print(target_str_list_2)
    # print(target_str_list_1)
    # exit(1)
    # 检查是否前后涉及到的key数量错误，或者是否有constant变化
    # # print(target_str_list_1)
    # # print(target_str_list_2)
    # # print(wrong_code1)
    # # print(wrong_code2)
    if len(target_str_list_2) != len(target_str_list_1):
        return True, 'Add / Delete target API!', loc_rule, target_list, None, None,''
    for item in target_str_list_2:
        str_dict = item['related_str']
        type_dict1 = item['related_type']
        index2 = target_str_list_2.index(item)
        item2 = target_str_list_1[index2]
        str_dict2 = item2['related_str']
        type_dict2 = item2['related_type']
        hit_flag = False
        for key in str_dict.keys():
            change_dict[key] = list()
            if key not in str_dict2.keys():
                change_dict[key].append(item['src'])
            else:
                # print(str_dict2[key])
                if key != 'ret' and (str_dict2[key].find('CONSTANT') != -1 or str_dict[key].find('CONSTANT') != -1):
                # if key != 'ret' and str_dict2[key] != str_dict[key]:
                    if str_dict2[key] != str_dict[key]:
                        change_dict[key].append(item['src'])
                if key != 'ret' and type_dict2[key] != type_dict1[key]:
                    change_dict[key].append(item['src'])
        for key in str_dict2.keys():
            if key not in change_dict.keys():
                change_dict[key] = list()
                change_dict[key].append(item['src'])

    # print('target_str_list:')
    # print(target_str_list_1)
    # print(target_str_list_2)
    i= 0
    for item in target_str_list_1:
        item.pop('related_type')
        target_str_list_1[i] = item
        i += 1
    i= 0
    for item in target_str_list_2:
        item.pop('related_type')
        target_str_list_2[i] = item
        i += 1
    # print(target_str_list_1)
    # print(target_str_list_2)
    # print(change_dict)
    # exit(1)
    if len(target_str_list_2) == 0:
        return True, 'No related str', loc_rule, target_list, None, None,''
    # diff_code只返回在wrong code中的行（也就是code2，加号行）
    change_code_lines = diff_code(wrong_code1, wrong_code2, '+')
    # print(change_code_lines)
    # exit(1)
    change_code_lines = list(set(change_code_lines))
    # print(change_code_lines)

    # exit(1)
    # TODO 把change code对应到node上，形成一个node list：
    # [{src: , node: , begin_index: , end_index: , identifiers: []}]
    id_list = get_identifier(wrong_code2, change_code_lines)
    # print(id_list)
    # TODO 获取每个change node中的变量名，组成2个dict {arg0: [before, after]}, {arg0: [{code: , loc: before/after}]}
    # exit(1)
    # 分别检查每个FC对应的变量有没有被修改
    # target_str_list_2: {begin_index: , end_index, related_str: {ret: [], arg0: []}}
    out_dict1 = dict()
    out_dict_debug = dict()
    far_flag = False
    far_info = ''
    for target_dict in target_str_list_2:           
        related_str_dict = target_dict['related_str']
        for key in related_str_dict.keys():
            id_name = related_str_dict[key]
            for change_item in id_list:
                if change_item['src'] == target_dict['src']:
                    continue
                identifiers = change_item['identifiers']
                # 说明该change_item修改了key对应的str
                if id_name in identifiers:
                    # # print('change_item')
                    # # print(change_item)
                    # exit(1)
                    # 如果改修改离目标太远，则继续搜索
                    if_far_flag, far_info = if_far(id_name, change_item['begin_index'], change_item['end_index'], target_dict['begin_index'], wrong_code2)
                    # print('parse_wrong_diff')
                    # print(far_info)
                    if if_far_flag:
                        # print('Change Too Far!')
                        far_flag = True
                        continue
                    loc_info = get_loc_info(target_dict, change_item)
                    if loc_info == '':
                        loc_info = loc_rule
                    if key not in out_dict1.keys():
                        out_dict1[key] = list()
                        out_dict1[key].append(loc_info)
                        
                        out_dict_debug[key] = list()
                        new_dict = dict()
                        new_dict['code'] = change_item['src']
                        new_dict['loc'] = loc_info
                        new_dict['begin_index'] = change_item['begin_index']
                        new_dict['id'] = id_name
                        out_dict_debug[key].append(new_dict)
                    else:
                        out_dict1[key].append(loc_info)
                        out_dict1[key] = list(set(out_dict1[key]))
                        
                        new_dict = dict()
                        new_dict['code'] = change_item['src']
                        new_dict['loc'] = loc_info
                        new_dict['begin_index'] = change_item['begin_index']
                        new_dict['id'] = id_name
                        out_dict_debug[key].append(new_dict)
    # out_dict1：{arg0: [before, after]}代表所有修改的成分以及修改是在哪里发生的
    right_flag = False
    # print('change dict:')
    # print(out_dict1)
    # print(change_dict)
    # print('rule info: ')
    # print(target_list)
    # print(loc_rule)
    # print('out_debug_dict')
    # print(out_dict_debug)
    # exit(1)
    for target_str in target_list:
        
        if target_str in out_dict1.keys():
            if loc_rule == '':
                right_flag = True
            else:
                if loc_rule in out_dict1[target_str]:
                    right_flag = True
        if target_str in change_dict.keys() and len(change_dict[target_str]) != 0 and loc_rule != 'after':
            
            right_flag = True
    if right_flag:
        # print('Right Change')
        return True, 'right change', loc_rule, target_list, target_str_list_2, out_dict_debug, far_info
    else:
        
        # print('Wrong Change')
        if far_flag:
            # print('before add return')
            # print(far_info)
            return False, 'TooFar', loc_rule, target_list, target_str_list_2, out_dict_debug, far_info.strip('\n')
        return False, 'wrong change', loc_rule, target_list, target_str_list_2, out_dict_debug, far_info

def auto_check2_delete(wrong_code1, wrong_code2, target_api, declaration, rule):
    # 1.获取目标rule涉及到的所有可能parameter/ret
    target_list, loc_rule = parse_rule(rule, declaration)
    # # print(target_list)
    # exit(1)
    # # print(target_list)
    # # print(loc_rule)
    # exit(1)
    if len(target_list) == 0:
        return True, 'parse arg wrong, target_list is empty', loc_rule, target_list, None, None, ''
    # # print(wrong_code2)
    # # print(target_api)
    if wrong_code2.find(target_api) == -1:
        # print('Wrong! No target API!')
        # # print(target_api)
        # exit(1)
        return False, 'No target API!', loc_rule, target_list, None, None, ''
    # 2.通过diff判断两个代码中哪些parameter/ret发生了修改
    # output：{arg0: [], ret: [...]}
    change_dict = dict()
    wrong_code1 = del_comment_re(wrong_code1)
    wrong_code2 = del_comment_re(wrong_code2)

    # {begin_index: , end_index, related_str: {ret: [], arg0: []}}
    target_str_list_1 = get_target_paraname(wrong_code1, target_api)
    # target_str_list_2 = get_target_paraname(wrong_code2, target_api)
    # 检查是否前后涉及到的key数量错误，或者是否有constant变化
    # # print(target_str_list_1)
    # # print(target_str_list_2)
    # # print(wrong_code1)
    # # print(wrong_code2)
    # if len(target_str_list_2) != len(target_str_list_1):
    #     return True, 'Add / Delete target API!', loc_rule, target_list, None, None
    # for item in target_str_list_1:
    #     str_dict = item['related_str']
    #     index2 = target_str_list_1.index(item)
    #     item2 = target_str_list_1[index2]
    #     str_dict2 = item2['related_str']
    #     hit_flag = False
    #     for key in str_dict.keys():
    #         change_dict[key] = list()
    #         if key not in str_dict2.keys():
    #             change_dict[key].append(item['src'])
    #         else:
    #             # print(str_dict2[key])
    #             if key != 'ret' and (str_dict2[key].find('CONSTANT') != -1 or str_dict[key].find('CONSTANT') != -1):
    #                 if str_dict2[key] != str_dict[key]:
    #                     change_dict[key].append(item['src'])
    #     for key in str_dict2.keys():
    #         if key not in change_dict.keys():
    #             change_dict[key] = list()
    #             change_dict[key].append(item['src'])

    # # print('target_str_list:')
    # # print(target_str_list_1)
    # # print(target_str_list_2)
    if len(target_str_list_1) == 0:
        # print('Wrong! No str related to the API call! Check the Code')
        return True, 'No target API!', loc_rule, target_list, None, None, ''
    # diff_code只返回在wrong code中的行（也就是code2，加号行）
    change_code_lines = diff_code(wrong_code1, wrong_code2, '-')
    # print(target_str_list_1)
    # print(change_code_lines)
    # exit(1)
    # # print(change_code_lines)
    # exit(1)
    # for line in change_code_lines:
    #     # print(line)
    change_code_lines = list(set(change_code_lines))
    # print(change_code_lines)
    # exit(1)
    # TODO 把change code对应到node上，形成一个node list：
    # [{src: , node: , begin_index: , end_index: , identifiers: []}]
    id_list = get_identifier(wrong_code1, change_code_lines)
    # print(id_list)
    # exit(1)
    # TODO 获取每个change node中的变量名，组成2个dict {arg0: [before, after]}, {arg0: [{code: , loc: before/after}]}
     
    # 分别检查每个FC对应的变量有没有被修改
    # target_str_list_2: {begin_index: , end_index, related_str: {ret: [], arg0: []}}
    out_dict1 = dict()
    out_dict_debug = dict()
    far_flag = False
    far_info = ''
    for target_dict in target_str_list_1:           
        related_str_dict = target_dict['related_str']
        for key in related_str_dict.keys():
            id_name = related_str_dict[key]
            for change_item in id_list:
                if change_item['src'] == target_dict['src']:
                    continue
                identifiers = change_item['identifiers']
                # 说明该change_item修改了key对应的str
                if id_name in identifiers:
                    # # print('change_item')
                    # # print(change_item)
                    # exit(1)
                    # 如果改修改离目标太远，则继续搜索
                    if_far_flag, far_info = if_far(id_name, change_item['begin_index'], change_item['end_index'], target_dict['begin_index'], wrong_code2)
                    # print('parse_wrong_diff')
                    # print(far_info)
                    if if_far_flag:
                        # print('Change Too Far!')
                        # exit(1)
                        far_flag = True
                        continue
                    
                    loc_info = get_loc_info(target_dict, change_item)
                    if loc_info == '':
                        loc_info = loc_rule
                    if key not in out_dict1.keys():
                        out_dict1[key] = list()
                        out_dict1[key].append(loc_info)
                        
                        out_dict_debug[key] = list()
                        new_dict = dict()
                        new_dict['code'] = change_item['src']
                        new_dict['loc'] = loc_info
                        new_dict['begin_index'] = change_item['begin_index']
                        new_dict['id'] = id_name
                        out_dict_debug[key].append(new_dict)
                    else:
                        out_dict1[key].append(loc_info)
                        out_dict1[key] = list(set(out_dict1[key]))
                        
                        new_dict = dict()
                        new_dict['code'] = change_item['src']
                        new_dict['loc'] = loc_info
                        new_dict['begin_index'] = change_item['begin_index']
                        new_dict['id'] = id_name
                        out_dict_debug[key].append(new_dict)
    # out_dict1：{arg0: [before, after]}代表所有修改的成分以及修改是在哪里发生的
    right_flag = False
    # print('change dict:')
    # print(out_dict1)
    # print(change_dict)
    # print('rule info: ')
    # print(target_list)
    # print(loc_rule)
    # print('out_debug_dict')
    # print(out_dict_debug)
    
    for target_str in target_list:
        
        if target_str in out_dict1.keys():
            if loc_rule == '':
                right_flag = True
            else:
                if loc_rule in out_dict1[target_str]:
                    right_flag = True
        if target_str in change_dict.keys() and len(change_dict[target_str]) != 0 and loc_rule != 'after':
            
            right_flag = True
    if right_flag:
        # print('Right Change')
        return True, 'right change', loc_rule, target_list, target_str_list_1, out_dict_debug, far_info
    else:
        # print('Wrong Change')
        if far_flag:
            # print('before delete return')
            # print(far_info)
            return False, 'TooFar', loc_rule, target_list, target_str_list_1, out_dict_debug, far_info.strip('\n')
        return False, 'wrong change', loc_rule, target_list, target_str_list_1, out_dict_debug, far_info
def if_add_definition(code2, api_name):
    cc = CCode(code2)
    # print(code2)
    funcs = cc.get_by_type_name('function_definition')
    # print(funcs)
    i = 0
    for func in funcs: 
        i += 1
        # print(str(i))
        # print(func)
    func = cc.get_by_type_name_and_query('function_definition', {'identifier': api_name})
    if len(func) != 0:
        return True
    else:
        return False


def if_same_parameter(rule, desc, declaration):
    arg_list, loc =parse_rule(rule, declaration)
    arg_list2, loc2 = parse_rule(desc, declaration)
    # print(arg_list)
    # print(arg_list2)
    if arg_list2 == []:
        return True
    if not arg_list == arg_list2:
        return False
    else:
        return True

# get all the definition of code
def get_all_func(code):
    cc = CCode(code)
    funcs = cc.get_by_type_name('function_definition')
    out_list = list()
    for func in funcs:
        name = func.name.src
        out_list.append(name)
    # print(out_list)
    return out_list

if __name__ == '__main__':
    
    
        target_api = 'curl_ws_send'
        declaration = '''OCURL_EXTERN curl_ws_send(CURL *curl, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  curl_off_t fragsize,
                                  unsigned int flags)'''
        rule = "Parameter 3: Prevent writing more data than the specified length of the packet (`h->caplen`)."
        flag_add, msg_add, loc_rule_add, rule_list_add, target_str_list2_add, out_dict_debug_add, far_info = auto_check2_add(blob_code1, blob_code2, target_api, declaration, rule)
        flag_delete, msg_delete, loc_rule_delete, rule_list_delete, target_str_list2_delete, out_dict_debug_delete, far_info = auto_check2_delete(blob_code1, blob_code2, target_api, declaration, rule)
    
    # target_api = 'pcap_can_set_rfmon'
    # declaration = 'int pcap_can_set_rfmon(pcap_t *p)'
    # rule = '`pcap_t *p` must be a valid pointer and not NULL.'
    # auto_check2(wrong_code1, wrong_code2, target_api, declaration, rule)
    
        
    

    # 2 
    # target_api = 'pcap_freecode'
    # declaration = 'void pcap_freecode(struct bpf_program *program)'
    # rule = '`program` parameter must be a valid pointer to a `struct bpf_program` object.'
    # auto_check2(code1, code2, target_api, declaration, rule)

    
    # 3
    # target_api = 'pcap_free_tstamp_types'
    # declaration = 'void pcap_free_tstamp_types(int *tstamp_type_list)'
    # rule = 'The `tstamp_type_list` parameter must not be used after being passed to this function.'
    # auto_check2(wrong_code2_1, wrong_code2_2, target_api, declaration, rule)
    
    
    # 4：
    # target_api = 'sqlite3_stmt_isexplain'
    # declaration = 'int sqlite3_stmt_isexplain(sqlite3_stmt *pStmt)'
    # rule = 'The function return value must be checked to ensure it is not a sensitive or unexpected value.'
    # auto_check2(right_code3_1, right_code3_2, target_api, declaration, rule)
    
    # 5：
#     target_api = 'sqlite3_bind_text64'
#     declaration = '''sqlite3_bind_text64
# int sqlite3_bind_text64( 
#   sqlite3_stmt *pStmt, 
#   int i, 
#   const char *zData, 
#   sqlite3_uint64 nData, 
#   void (*xDel)(void*),
#   unsigned char enc
# )'''
#     rule = '`enc`: The `enc` parameter must be a valid encoding flag.'
#     target_list, loc_rule = parse_rule(rule, declaration)

    # test get_related_fc:
    