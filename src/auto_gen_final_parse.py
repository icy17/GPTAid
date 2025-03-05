import json
import os
import sys
import openai
import time
import subprocess
import parse_wrong_diff
import identify_error
import tiktoken
import re
import copy

gpt_token_small_limit = 4000
gpt_token_large_limit = 16000
parse_temperature = 0


compile_cmd_prefix = 'gcc -g -pedantic -fsanitize=address -fsanitize=undefined -o FUNC_NAME FUNC_NAME.c '
compile_cmd_valgrind = 'gcc -g -pedantic -o FUNC_NAME_val FUNC_NAME.c '
compile_dict = {"sqlite3": "-lsqlite3", "openssl": '-lssl -lcrypto', "libpcap": "-lpcap", "libxml2": "-lxml2", "FFmpeg": "$(pkg-config --cflags --libs libavcodec libavutil libavformat libavfilter libavdevice)", "libevent": "-levent -lssl -lcrypto -levent_openssl", "zlib": "-lz", "libcurl": "-lcurl", "libzip": "-lzip"}
include_dict = {"sqlite3": "#include <sqlite3.h>", "FFmpeg": '''#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavfilter/avfilter.h>
#include <libswresample/swresample.h>
#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/channel_layout.h>
#include <libavutil/camellia.h>
#include <libavutil/fifo.h>
#include <libavcodec/bsf.h>
#include <libavutil/imgutils.h>''', "libpcap": "#include <pcap.h>", "libxml2": '''#include <libxml/xmlreader.h>
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
''', "openssl": '''
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/cms.h>
#include <openssl/ct.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs12err.h>
''', 
"libevent": '''#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <event2/http.h>
#include <event2/rpc.h>
#include <event2/bufferevent_ssl.h>
''', 
"zlib": "#include <zlib.h>", 
"libzip": "#include <zip.h>",
"libcurl": "#include <curl/curl.h>"}



def clear_env():
    file_list = ['example.db', 'example.pcap', 'example.xml', 'example.zip']
    for file_name in file_list:
        # file_name = 'example.db'
        if os.path.exists(file_name):
            os.remove(file_name)
        os.system('cp ../example_data//' + file_name + ' .')
        # file_name2 = 'example.pcap'
        # if os.path.exists(file_name2):
        #     os.remove(file_name2)
        # os.system('cp ../example_data//example.pcap .')

def rm_env():
    file_list = ['example.db', 'example.pcap', 'example.xml', 'example.zip']
    for file_name in file_list:
        # file_name = 'example.db'
        if os.path.exists(file_name):
            os.remove(file_name)

def read_json(in_path):
    # in_list = list()
    out_list = list()
    with open(in_path, 'r') as f:
        tmp_list = f.readlines()
    for line in tmp_list:
        line = line.strip('\n')
        line_json = json.loads(line)
        out_list.append(line_json)
    return out_list

def get_code(path):
    code = ''
    with open(path, 'r') as f:
        code = f.read()
    return code
def num_tokens_from_messages(prompt, messages, model="gpt-4o-mini"):
    """Return the number of tokens used by a list of messages."""
    if prompt != '':
        messages.append({"role": "user", "content": prompt})
    
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        # print("Warning: model not found. Using cl100k_base encoding.")
        encoding = tiktoken.get_encoding("cl100k_base")
    if model in {
        "gpt-4o-mini",
        "gpt-4o-mini",
        "gpt-4-0314",
        "gpt-4-32k-0314",
        "gpt-4-0613",
        "gpt-4-32k-0613",
        }:
        tokens_per_message = 3
        tokens_per_name = 1
    elif model == "gpt-3.5-turbo-0301":
        tokens_per_message = 4  # every message follows <|start|>{role/name}\n{content}<|end|>\n
        tokens_per_name = -1  # if there's a name, the role is omitted
    elif "gpt-3.5-turbo" in model:
        # print("Warning: gpt-3.5-turbo may update over time. Returning num tokens assuming gpt-4o-mini.")
        return num_tokens_from_messages(messages, model="gpt-4o-mini")
    elif "gpt-4" in model:
        # print("Warning: gpt-4 may update over time. Returning num tokens assuming gpt-4-0613.")
        return num_tokens_from_messages(messages, model="gpt-4-0613")
    else:
        raise NotImplementedError(
            f"""num_tokens_from_messages() is not implemented for model {model}. See https://github.com/openai/openai-python/blob/main/chatml.md for information on how messages are converted to tokens."""
        )
    num_tokens = 0
    for message in messages:
        num_tokens += tokens_per_message
        for key, value in message.items():
            num_tokens += len(encoding.encode(value))
            if key == "name":
                num_tokens += tokens_per_name
    num_tokens += 3  # every reply is primed with <|start|>assistant<|message|>
    return num_tokens


def generate_rule_prompt(func, func_code, question):
    prefix = question.replace('FUNC_NAME', func)
    # prompt = prefix + '\n\n'
    prompt = prefix + '\n\n' + func + ' source code: \n```\n'
    prompt = prompt + func_code + '\n```\n'
    return prompt

def parse_split_rule(rule):
    out_list = list()
    lines = rule.split('\n')
    rule_flag = False
    for line in lines:
        if rule_flag == True:
            if line == '':
                continue
            if line.strip()[0].isdigit():
                rule_begin = line.find('.')
                if rule_begin == -1:
                    # print('cannot find rule_begin in parse_split_rule')
                    exit(1)
                rule = line[rule_begin + 1:].strip('.').strip(' ')
                out_list.append(rule)
            else:
                rule_flag = False
        start_index = line.find(' Rules:')
        if start_index != -1:
            rule_flag = True
        
            # # degree_index = lines.index(line) + 2
            # # degree_info = list(lines[degree_index])
            # # degree = 11
            # # for item in degree_info:
            # #     if item.isdigit():
            # #         degree = int(item)
            # #         break
            # # if degree < 4 or degree == 11:
            # #     continue
            # rule = line[len('Security rule:'):].strip(' ')
            # out_list.append(rule)
    return out_list

def parse_rule(rule):
    out_list = list()
    lines = rule.split('\n')
    rule_flag = False
    for line in lines:
        if rule_flag == True:
            if line == '':
                continue
            if line.strip()[0].isdigit():
                rule_begin = line.find('.')
                if rule_begin == -1:
                    # print('cannot find rule_begin in parse_rule')
                    exit(1)
                rule = line[rule_begin + 1:].strip('.').strip(' ')
                out_list.append(rule)
            else:
                rule_flag = False
        start_index = line.find('Parameter Rules:')
        if start_index != -1:
            rule_flag = True
        
            # # degree_index = lines.index(line) + 2
            # # degree_info = list(lines[degree_index])
            # # degree = 11
            # # for item in degree_info:
            # #     if item.isdigit():
            # #         degree = int(item)
            # #         break
            # # if degree < 4 or degree == 11:
            # #     continue
            # rule = line[len('Security rule:'):].strip(' ')
            # out_list.append(rule)
    return out_list

def parse_desc(rule):
    out_list = list()
    lines = rule.split('\n')
    rule_flag = False
    add_flag = False
    rule = ''
    for line in lines:
        if rule_flag == True:
            if line == '':
                continue
            if line.strip()[0].isdigit():
                if rule != '':
                    out_list.append(rule)
                rule = ''
                add_flag = True
                rule_begin = line.find('.')
                if rule_begin == -1:
                    # print('cannot find rule_begin in parse_desc')
                    exit(1)
                rule = line[rule_begin + 1:].strip('.').strip(' ')
                
            else:
                if add_flag:
                    rule += line
        start_index = line.find('Answer:')
        if start_index != -1:
            rule_flag = True
    if rule not in out_list:  
        out_list.append(rule)
    # out_list = list(set(out_list))
    return out_list

def query_gpt(prompt, message_before, temprature_in, big_flag):
    # answer = ''
    # return answer
    print('waiting for gpt...')
    # print(prompt)
    global one_query
    global gpt_answer_index
    global token_num
    global api_key
    global orig_key
    answer_path = gpt_answer_dir + '/' + str(gpt_answer_index)
    gpt_answer_index += 1
    # if token_num > 500000:
    #     # print('too many token!')
    # Personal:
    openai.organization = orig_key
    openai.api_key = api_key
    flag = ""
    if prompt != '':
        message_before.append({"role": "user", "content": prompt})
    token_before = 0   
    for message in message_before:
        token_before += len(message['content'])
    if token_before > gpt_token_small_limit:
        token_limit = gpt_token_large_limit
        model_select = "gpt-4o-mini"
    elif token_before > gpt_token_large_limit:
        return '', token_before
    token_limit = gpt_token_small_limit
    model_select = "gpt-4o-mini"
    while flag == "":
        try:  
            one_query += 1
            response = openai.ChatCompletion.create( 
            model=model_select, 
            temperature=temprature_in,
            messages=message_before,
            timeout=30)
            if response == None:
                flag = ""
                # print('timeout! continue')
                continue
            # # print('response:')
            # print(response)
            token = response['usage']['total_tokens']
            token_num += token
            finish_reason = response["choices"][0]["finish_reason"]
            response = response["choices"][0]["message"]["content"].strip('\n')
            # # print(type(response["choices"][0]))
            
            
            if finish_reason == 'length':
                # print('in finish reason')
                if model_select == "gpt-4o-mini" and big_flag:
                    model_select = 'gpt-4o-mini'
                    continue
                else:
                    return '', gpt_token_large_limit
            flag = response
            # # print()
            # # print(response)
            out_string = 'Question: \n' + prompt + '\n\n' + 'Answer: \n' + response
            # # print(out_string)
            out_string = ''
            for item in message_before:
                if item['role'] == 'user':
                    out_string  = out_string + '\nQuestion: \n' + item['content'] + '\n'
                else:
                    out_string  = out_string + '\nAnswer: \n' + item['content'] + '\n'
            out_string = out_string + '\nAnswer: \n' + response + '\n'
            with open(answer_path, 'w') as f:
                f.write(out_string)
            return response, token
        except openai.OpenAIError as e:
            if "tokens" in str(e):
                if big_flag and token_limit == gpt_token_small_limit:
                    token_limit = gpt_token_large_limit
                    model_select = 'gpt-4o-mini'
                else:
                    # Handle token limit exceeded error
                    # print("Input text exceeds the maximum token limit.")
                    return '', token_limit
            else:
                # Handle other API errors
                # print("An error occurred:", e)
                return '', token_limit
        except:
            # print("Connection refused by the server..")

            # print("Let me sleep for 5 seconds")

            # print("ZZzzzz...")

            time.sleep(5)

            # print("Was a nice sleep, now let me continue...")

            continue
    

def generate_rightcode_prompt(func, lib, func_code, question):
    prompt = question.replace('FUNC_NAME', func).replace('LIB_NAME', lib)
    # prompt = prompt + '\n\n' + 'invocation specification of ' + func + ': \n```\n'
    # for rule in rule_list:
    #     prompt = prompt + rule + '\n'
    # prompt = prompt + '```'
    prompt = prompt + '\n\n' + func + ' function code: \n```\n'
    prompt = prompt + func_code + '\n```\n'
    return prompt

    # return prompt


def generate_wrongcode_prompt(api, rule, violation_code, right_code, declaration, question, lib):
    prompt = question.replace('RULE_NAME', rule)
    prompt = prompt.replace('RIGHT_CODE_REPLACE', right_code)
    prompt = prompt.replace('DECLARATION_REPLACE', declaration)
    prompt = prompt.replace('FUNC_NAME', api)
    prompt = prompt.replace('VIOLATION', violation_code)
    # # prompt = prompt.replace('``', '`' + rule + '`', 1)
    # prompt = prompt + '\nDeclaration: \n```\n' + declaration + '\n```\nCode: \n```\n' + right_code + '\n```'

    return prompt
    
def add_headers(code, lib):
    fixed_headers = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
'''
    # headers = fixed_headers + '\n' + include_dict[lib]
    # headers_find = headers.replace(' ', '')
    # headers_find = headers_find.replace('<', '')
    # headers_find = headers_find.replace('>', '')
    # headers_find = headers_find.replace('"', '')
    # # headers_find = headers_find.replace('>', '')
    # remain_code = ''
    lines = code.split('\n')
    re_lines = ''
    for line in lines:
        if line.find('#include') != -1:
            continue
        else:
            re_lines = re_lines + line + '\n'
    #         line_find = line.replace(' ', '')
    #         line_find = line_find.replace('<', '')
    #         line_find = line_find.replace('>', '')
    #         line_find = line_find.replace('"', '')
    #     # if line.find(' main') != -1:
    #     #     break
    #         if headers_find.find(line_find) == -1:
    #             remain_code += line
    #             remain_code += '\n'
    #     else:
    #         remain_code += line
    #         remain_code += '\n'
    # out_code = headers + '\n' + remain_code
    # main_index = code.find('int main')
    # if  main_index == -1:
    #     return ''
    headers = include_dict[lib]
    code = re_lines
    out_code = fixed_headers + '\n' + headers + '\n' + code
    return out_code

def parse_right_code(answer, lib):
    if answer.find('```') == -1:
        # print('Cant parse! answer: \n')
        # print(answer)
        return '', ''
    answer = answer.replace('Task 2', 'Task2')
    answer = answer.replace('Task 3', 'Task3')
    answer = answer.replace('Task 4', 'Task4')
    right_code = ''
    compile_cmd = ''
    task_index = answer.find('Task3')
    if task_index == -1:
        task_index = 0
    code_begin_index = answer.find('```cpp', task_index)
    if code_begin_index == -1:
        code_begin_index = answer.find('```c', task_index)
        if code_begin_index == -1:
            code_begin_index = answer.find('```', task_index)
        else:
            code_begin_index += 1
    else:
        code_begin_index += 3
    # if code_begin_index == -1:
    #     return right_code, ''
    
    # if code_begin_index == -1:
    #     return right_code, ''
    code_end_index = answer.find('```', code_begin_index + len('```'))
    right_code = answer[code_begin_index + len('```'): code_end_index].strip('\n')
    right_code = add_headers(right_code, lib)
    # compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
    # compile_valgrind = compile_cmd_valgrind.replace('FUNC_NAME', api) + compile_dict[lib]
    # cmd_begin = answer.find('```', code_end_index + len('```'))
    # if cmd_begin == -1:
    #     return right_code, '', ''
    # cmd_begin = answer.find('gcc', cmd_begin)
    # if cmd_begin == -1:
    #     return right_code, '', ''
    # cmd_end = answer.find('```', cmd_begin)
    # if cmd_end != -1:
    #     compile_cmd = answer[cmd_begin: cmd_end].strip('\n')
    # else:
    #     compile_cmd = answer[cmd_begin: ].strip('\n')
    env_index = answer.find('Task4')
    if env_index != -1:
        env_info = answer[env_index:]
    else:
        env_info = ''
    # print('parse right code:')
    # print(right_code)
    # print(compile_cmd)
    if right_code.find('main') == -1:
        # print('Cant parse! answer: \n')
        # print(answer)
        return '', ''
    return right_code, env_info
    
def parse_wrong_code(answer, lib):
    if answer.find('```') == -1:
        # print('Cant parse! answer: \n')
        # print(answer)
        return '', ''
    if answer.count('main') == 1:
        return parse_right_code(answer, lib)
    # else:
        
    
    compile_cmd = ''
    task_index = answer.find('Task3')
    if task_index == -1:
        task_index = 0
    code_begin_index = answer.find('```cpp', task_index)
    if code_begin_index == -1:
        code_begin_index = answer.find('```c', task_index)
        if code_begin_index == -1:
            code_begin_index = answer.find('```', task_index)
        else:
            code_begin_index += 1
    else:
        code_begin_index += 3
    # if code_begin_index == -1:
    #     return right_code, ''
    
    # if code_begin_index == -1:
    #     return right_code, ''
    code_end_index = answer.find('```', code_begin_index + len('```'))
    right_code = answer[code_begin_index + len('```'): code_end_index].strip('\n')
    right_code = add_headers(right_code, lib)
    # compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
    # compile_valgrind = compile_cmd_valgrind.replace('FUNC_NAME', api) + compile_dict[lib]
    # cmd_begin = answer.find('```', code_end_index + len('```'))
    # if cmd_begin == -1:
    #     return right_code, '', ''
    # cmd_begin = answer.find('gcc', cmd_begin)
    # if cmd_begin == -1:
    #     return right_code, '', ''
    # cmd_end = answer.find('```', cmd_begin)
    # if cmd_end != -1:
    #     compile_cmd = answer[cmd_begin: cmd_end].strip('\n')
    # else:
    #     compile_cmd = answer[cmd_begin: ].strip('\n')
    env_index = answer.find('Task4')
    if env_index != -1:
        env_info = answer[env_index:]
    else:
        env_info = ''
    # print('parse right code:')
    # print(right_code)
    # print(compile_cmd)
    if right_code.find('main') == -1:
        # print('Cant parse! answer: \n')
        # print(answer)
        return '', ''
    return right_code, env_info




def parse_wrong_code(answer):
    
    index_begin = answer.find('```')
    if index_begin == -1:
        return 'ERROR'
    else:
        index_begin = answer.find('```c')
        if index_begin != -1:
            index_begin = index_begin + len('```c')
        else:
            index_begin = answer.find('```') + len('```')
        index_end = answer.find('```', index_begin)
        if index_end == -1:
             wrong_code = answer[index_begin: ]
        else:
            wrong_code = answer[index_begin: index_end]
        wrong_code = add_headers(wrong_code, lib)
        return wrong_code
# TODO
def generate_fix_right_prompt(cmd, right_prefix, errmsg, prev_msg):
    # messages = list()
    # before_a = before_a.replace('Task 3', 'Task3')
    # right_prefix = right_prefix.replace('FUNC_NAME', api)
    # if replace_flag:
    #     task3_begin = before_a.find('Task3:')
    #     answer = before_a[: task3_begin]
    #     answer = answer + '\nTask3: \n```' + wrong_code + '\n```\nTask4: \n```' + wrong_cmd + '\n```'
    #     before_a = answer
    # messages.append({"role": "user", "content": before_q})
    # messages.append({"role": "assistant", "content": before_a})
    prompt = right_prefix + '\n' + cmd + '\n```\nRun Result: \n```\n' + errmsg + '\n```'
    prev_msg.append({"role": "user", "content": prompt})   
    # prompt = ''
    return prev_msg


def generate_fix_wrong_prompt(wrong_cmd, right_prefix, errmsg, prev_msg):
    # messages = list()
    # if replace_flag:
    #     before_a = before_a.replace(before_code, wrong_code)
    # messages.append({"role": "user", "content": before_q})
    # messages.append({"role": "assistant", "content": before_a})
    prompt = right_prefix + '\n' + wrong_cmd + '\n```\nRun Result: \n```\n' + errmsg + '\n```'
    prev_msg.append({"role": "user", "content": prompt})   
    # messages.append({"role": "user", "content": prompt})   
    # prompt = ''
    return prev_msg

# TODO:
def run_watch(api, code, compile_cmd):
    global root_passwd
    run_flag = True
    errmsg = ''
    # write code to out_file file
    code_path = './' + api + '.c'
    with open(code_path, 'w') as f:
        f.write(code)
    # compile
    # os.putenv('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    return_info = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        return False, 'compile', compile_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. '
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # res_flag = return_info[0]
    # info = return_info[1]
    if res_flag != 0:
        # os.system('rm ' + code_path)
        return False, 'compile', info
    run_cmd1 = './' + api
    run_cmd = 'echo %s | sudo -S %s' % (root_passwd, run_cmd1)
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        return False, 'timeout', run_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. '
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # res_flag = return_info[0]
    # info = return_info[1]
    if res_flag != 0:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return False, 'run', info
    else:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return True, '', info

def write_debug_wrong(code1, code2, rule, declaration, api):
    out_log = home_dir + '/output/changed_code_log'
    # out_log = out_dir + '/log'
    # if not os.path.exists(out_dir):
    #     os.mkdir(out_dir)
    # one_out_dir = out_dir + api + '/'   
    # if not os.path.exists(one_out_dir):
    #     os.mkdir(one_out_dir)
    out_dict = dict()
    out_dict['api'] = api
    out_dict['code1'] = code1
    out_dict['code2'] = code2
    out_dict['rule'] = rule
    out_dict['declaration'] = declaration
    with open(out_log, 'a') as f:
        f.write(json.dumps(out_dict))
        f.write('\n')

def compile_code(api, code, compile_cmd):
    run_flag = True
    errmsg = ''
    # write code to out_file file
    code_path = './' + api + '.c'
    with open(code_path, 'w') as f:
        f.write(code)
    if not parse_wrong_diff.if_api_exists(code, api):
        # os.system('rm ' + code_path)
        return False, 'compile', 'No target API `' + api + '`, please check and regenerate the code.'
    # compile
    # os.putenv('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    return_info = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        # os.system('rm ' + code_path)
        return False, 'compile', compile_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. '
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # res_flag = return_info[0]
    # info = return_info[1]
    if res_flag != 0:
        # os.system('rm ' + code_path)
        return False, 'compile', info
    else:
        # os.system('rm ' + code_path)
        return True, 'compile', ''
    
def run_code(api, code):
    global root_passwd
    run_cmd1 = './' + api
    run_cmd = 'echo %s | sudo -S %s' % (root_passwd, run_cmd1)
    code_path = './' + api + '.c'
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if code.find(api) == -1:
        # os.system('rm ' + run_cmd1)
        # os.system('rm ' + code_path)
        return False, -1, 'No target API `' + api + '`, please check and regenerate the code.'
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return False, -1, run_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. '
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # res_flag = return_info[0]
    # info = return_info[1]
    if res_flag != 0:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return False, res_flag, info
    else:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return True, res_flag, info


# TODO test
def generate_fix_continue_prompt(prev_msg, answer_code, errmsg):
    prompt = 'Run result of the code is: \n' + errmsg + "Please fix this code based on the run result. \nNote: I am using the program automation to run the code you gave, so please generate the code directly that will run correctly."
    prompt += '\nAnswer Format: ```code```'
    prev_msg.append({"role": "user", "content": prompt})
    return prev_msg
    
# TODO test
def generate_fix_new_prompt(prev_msg:list, answer_code, error_msg):
    new_prompt = 'Run result of the code is: \n' + error_msg + "Please fix this code based on the run result. \nNote: I am using the program automation to run the code you gave, so please generate the code directly that will run correctly"
    new_prompt += '\nAnswer Format: ```code```'
    right_prompt = prev_msg[0]
    prev_msg = list()
    prev_msg.append({"role": "user", "content": right_prompt})
    prev_msg.append({"role": "assistant", "content": answer_code})
    prev_msg.append({"role": "user", "content": new_prompt})
    return prev_msg


# TODO test
# 1.判断是否error
# 2.如果成功执行（不一定正确，可能123），需要判断是否执行了目标API，否则视为错误执行（run-time error) TODO
# 3.如果未正确执行但执行成功，返回error-handling
# return flag, output, error_stage
def compile_run(code, api, compile_cmd, compile_valgrind_cmd, lib):
    global root_passwd
    flag = False
    output = ''
    error_stage = 'compile'
    # DEBUG:
    # print(api)
    # if code.find('rm ') != -1 and api != 'EC_POINT_add' and api != 'pcap_set_immediate_mode':
    #     # print('may rm smthing')
    if not parse_wrong_diff.if_api_exists(code, api):
        return False, 'There is no calling API `' + api + '`, please check.', 'noapi'
    #1. compile::
    run_flag = True
    errmsg = ''
    # write code to out_file file
    code_path = './' + api + '.c'
    with open(code_path, 'w') as f:
        f.write(code)
    return_info = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        os.system('rm ' + code_path)
        return False, compile_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. ', 'compile'
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")

    if res_flag != 0:
        os.system('rm ' + code_path)
        return False, info, 'compile'
    # compile end
    # print('compile: ' + compile_cmd + '\n Result: ' + info + '\n')
    # 2.run:
    clear_env()
    run_cmd1 = './' + api
    if lib == 'libpcap':
        run_cmd1 = './' + api
        run_cmd = 'echo %s | sudo -S %s' % (root_passwd, run_cmd1)
    else:
        run_cmd = './' + api
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        return False, run_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. ', 'timeout'
    res_flag_run = return_info.returncode
    info_run = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    if res_flag_run != 0 and res_flag_run != 123:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        return False, info_run, 'run'
    # print('run: ' + run_cmd + '\n Result: ' + info_run + '\n')
    # 3.val compile::
    
    return_info = subprocess.Popen(compile_valgrind_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        return False, compile_cmd + ' timed out after 300 seconds. Please check the code to make sure it is non-interactive. ', 'compile'
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    if res_flag != 0:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        return False, info, 'compile'
    # print('compile: ' + compile_cmd + '\n Result: ' + info + '\n')
    # 4. val run:
    val_timeout_flag = False
    clear_env()
    if lib == 'libpcap':
        run_cmd_val = 'valgrind --leak-check=full --quiet ./' + api + '_val'
        run_cmd = 'echo %s | sudo -S %s' % (root_passwd, run_cmd_val)
    else:
        run_cmd = 'valgrind --leak-check=full --quiet ./' + api + '_val'
    
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        val_timeout_flag = True
    
    if val_timeout_flag:
        res_flag_valrun = res_flag_run
        info_valrun = info_run
        if res_flag_run != 123 and res_flag_run != 0:
            val_if_error = True
        else:
            val_if_error = False
    else:
        res_flag_valrun = return_info.returncode
        info_valrun = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # val if error如果是true说明有error
        val_if_error = identify_error.parse_errmsg(code, info_valrun)
    # res_flag_valrun = res_flag_valrun and val_if_error
    # print('run: ' + run_cmd + '\n Result: ' + info_valrun + '\n')
    # 5. orig run
    val_timeout_flag = False
    clear_env()
    if lib == 'libpcap':
        run_cmd_val = './' + api + '_val'
        run_cmd = 'echo %s | sudo -S %s' % (root_passwd, run_cmd_val)
    else:
        run_cmd = './' + api + '_val'
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
    except:
        os.system('rm ' + code_path)
        os.system('rm ' + run_cmd1)
        val_timeout_flag = True
    
    if val_timeout_flag:
        res_flag_valrun = res_flag_run
        info_valrun = info_run
        if res_flag_run != 123 and res_flag_run != 0:
            val_if_error = True
        else:
            val_if_error = False
    else:
        res_flag_orgrun = return_info.returncode
        info_orgrun = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # val if error如果是true说明有error
        # val_if_error = identify_error.parse_errmsg(code, info_valrun)
    # res_flag_valrun = res_flag_valrun and val_if_error
    # print('run: ' + run_cmd + '\n Result: ' + info_orgrun + '\n')
    #end:: result:
    os.system('rm ' + code_path)
    os.system('rm ' + run_cmd1)
    os.system('rm ./' + api + '_val')
    if res_flag_orgrun !=0 and res_flag_orgrun != 123:
        tmp = info_orgrun.find(api)
        if tmp == -1:
            if_call_api = False
        else:
            if_call_api = True
        if if_call_api == False:
            return False, info_orgrun, 'nocallapi'
        return False, info_orgrun, 'run'
        
    tmp = info_run.find(api)
    if tmp == -1:
        if_call_api = False
    else:
        if_call_api = True
    
    if if_call_api == False:
        
        if res_flag_run == 0:
            # 代码中调用了目标API，且执行正确，但是未输出信息来说明
            return False, 'Please check the code, there is no `printf` after the API to show this API is called, please output "Calling ' + api + '" after calling this API' , 'noprintapi'
        # 代码中调用了目标API，执行出现问题，目标API未成功执行，需要fix
        return False, info_run, 'nocallapi'
    if res_flag_run == 0 and res_flag_valrun == 0 and val_if_error == False:
        # 代码执行绝对正确
        return True, info_run, 'run'
    if (res_flag_run == 123 and val_if_error != True) or (res_flag_run == 0 and res_flag_valrun == 123):
        # 代码执行了目标API，但是目标API出现error-handling，对于wrong来说算是正确执行
        return False, info_run, 'error-handling'
    if res_flag_run != 0 and res_flag_run != 123:
        # asan执行出现问题，且执行到了目标API，该结果说明rule正确
        return False, info_run, 'run'
    if (res_flag_valrun != 0 and res_flag_valrun != 123) or val_if_error == True:
        # valgrind执行出现问题，且执行到了目标API，该结果说明rule正确
        return False, info_valrun, 'run'
    
    # print(res_flag_run)
    # print(res_flag_valrun)
    # print(val_if_error)

    # return flag, output, error_stage

# TODO test
# 如果method是new，prev_msg中只有一个right_prompt
# 如果method是add，prev_msg是之前的user，assistant，需要再加一个user

def if_same_list(list1, list2):
    for item in list1:
        if item not in list2:
            return False
    for item in list2:
        if item not in list1:
            return False
    return True

# TODO later
def parse_rule_list(orig_list):
    rule_list = list()
    code_list = list()
    # for item in orig_list:
    #     rule_list.append
    return orig_list
# # TODO check
# def judge_rule_wrong_code(flag, error_stage, code, errmsg, api):
#     if code.find('\\n') == -1:
#         # print(code.split('\n'))
        
#         # # print('in judge rule wrong code exit')
        
#     code = code.replace('\\n', '')
    
#     debug = identify_error.get_error_code(code, errmsg, api)
#     if error_stage == 'error-handling':
#             flag = True
#     if flag == True:
#         # TODO write to file? this rule is a wrong rule
#         return 'wrong-rule', str(debug)
#     if flag == False and error_stage == 'compile':
#         return 'fix', str(debug)
#     if flag == False:
#         # # print(identify_error.if_api_related(code, errmsg, api))
#         # # print(code)
#         # # print(errmsg)
#         # # print(api)
#         # # print(error_stage)

#         if error_stage == 'run' and identify_error.if_api_related(code, errmsg, api):
            
#             return 'right-rule', str(debug)
#         else:
#             return 'fix', str(debug)



# TODO later
def get_fix_method():
    return 'add'


def filter_by_modal(rule):
    modal_verbs = ['must', 'can', 'should', 'shall']
    if rule.find('There are no') != -1 or rule.find('There is no') != -1:
        return False
    for modal_verb in modal_verbs:
        if rule.lower().find(modal_verb) != -1:
            return True
    return False

# def if_same_parameter(rule, desc, declaration):
#     parse_wrong_diff.parse_rule(rule)

def gen_final_rule(right_code, wrong_code, api, para_index, prompt_prefix, log_path, output_info, declaration):
    # gen prompt:
    prompt = prompt_prefix.replace('FUNC_NAME', api)
    # prompt = prompt.replace('PARA_INDEX', str(para_index))
    prompt = prompt.replace('RIGHT_CODE', right_code)
    prompt = prompt.replace('VIOLATION', wrong_code)
    prompt = prompt.replace('DECLARATION', declaration)

    
    output_replace = ''
    if output_info['orig'] != '' and output_info['asan'] == '' and output_info['val'] == '':
        output_msg = output_info['orig']
        output_prefix = '''\t(1)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 -fsanitize=address && ./a.out```
\tAnd I run this code successfully.
\t(2)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 && valgrind --leak-check --quiet ./a.out```
\tAnd I run this code successfully.
\t(3)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 && ./a.out```
\tAnd I run got the error msg: 
\t'''
    elif output_info['orig'] != '' and output_info['asan'] == '' and output_info['val'] != '':
        output_msg = output_info['orig']
        output_prefix = '''\t(1)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 -fsanitize=address && ./a.out```
\tAnd I run this code successfully.
\t(2)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 && valgrind --leak-check --quiet ./a.out```
\tAnd I got this:\n```\n''' + output_info['val'] + '''\n```
\t(3)I compile and run this Error Code with : 
\t```gcc ./sqlite3_bind_text64.c -g -lsqlite3 && ./a.out```
\tAnd I run got the error msg: \n```\n'''
    else:
        if output_info['asan'] != '':
            output_msg = output_info['asan']
        elif output_info['val'] != '':
            output_msg = output_info['val']
        else:
            output_msg = output_info['orig']
        output_prefix = '```\n'
    # output_prefix = ''
    
    output_replace = output_prefix + output_msg + '\n```'
    
    prompt = prompt.replace('ERROR_RE', output_replace)
    # debug:
    # print(prompt)
    # print(log_path)

    # query gpt:
    response, token = query_gpt(prompt, [], parse_temperature, True)
    # save to log
    with open(log_path, 'a') as f:
        f.write('Question: \n' + prompt+ '\nAnswer: \n' + response + '\n')
    # parse result:
    rule = ''
    begin = -1
    if begin != -1:
        response = response[begin:]
    rule_begin = response.find('Security Rule AUTO')
    if rule_begin != -1:
        rule = response[rule_begin + len('Security Rule AUTO'): ]
        rule_end = rule.find('\n')
        rule = rule[:rule_end]
    else:
        rule = ''
    begin = rule.find(':')
    if begin != -1:
        rule = rule[begin + 1:]
    rule_dict = dict()
    rule_dict['do'] = rule

    rule_begin = response.find('Security Rule AUTO_AVOID')
    if rule_begin != -1:
        rule = response[rule_begin + len('Security Rule AUTO_AVOID'): ]
        rule_end = rule.find('\n')
        rule = rule[:rule_end]
    else:
        rule = ''
    begin = rule.find(':')
    if begin != -1:
        rule = rule[begin + 1:]
    rule_dict['notdo'] = rule
    with open(log_path, 'a') as f:
        f.write('\nParsed Rule: ' + rule_dict['notdo'] + '\n' + rule_dict['do'] + '\n')
    return response, rule_dict, token


# output:[[1, 2], [3]]
def if_asan_same(output_list, code_prefix):
    output_small_list = list()
    for item_json in output_list:
        item = item_json['content']
        rule_index = item_json['index']
        code = get_code(code_prefix + rule_index + '.c')
        
        smallest_code = len(code)
        name_list = parse_wrong_diff.get_all_func(code)
        for func in name_list:
            tmp = item.find('in ' + func)
            if tmp < smallest_code and tmp != -1:
                smallest_code = tmp
        # print(smallest_code)

        
        begin = item.find('==ERROR: AddressSanitizer')
        output_begin = item[begin: smallest_code]
        # print(item)
        # print(output_begin)
        lines = output_begin.split('\n')
        output_info = ''
        for line in lines:
            if line.find('#') == -1 and line.find('==') == -1:
                continue
            if line.find('in main') != -1:
                break
            else:
                start_info = line.rfind('=')
                if start_info == -1:
                    out_line = line
                else:
                    out_line = line[start_info + 1 :]
                if out_line.strip() == '':
                    continue
                if out_line.find('ERROR: AddressSanitizer') != -1:
                    # print('hit!')

                    end_index = out_line.find('address')
                    if end_index != -1:
                        out_line = out_line[: end_index]
                begin_index = out_line.find('#')
                # # print(begin_index)
                if begin_index != -1:
                    begin_index = out_line.find('in')
                    out_line = out_line[begin_index:]
                output_info = output_info + out_line + '\n'
        
        
        one_dict = dict()
        one_dict['index'] = rule_index
        one_dict['content'] = output_info
        # print(output_info)
        # if rule_index == '12':

        output_small_list.append(one_dict)
    out_list = list()
    before_content = list()
    for item in output_small_list:
        rule_index = item['index']
        content = item['content']
        
        if content not in before_content:
            new_class = list()
            new_class.append(rule_index)
            before_content.append(content)
        else:
            continue
        for item2 in output_small_list:
            rule_index_match = item2['index']
            content_match = item2['content']
            if rule_index_match == rule_index:
                continue
            if content_match == content:
                # print(rule_index)
                # print(rule_index_match)
                new_class.append(rule_index_match)
        out_list.append(new_class)
    # print(out_list)
    return out_list

def remove_numbers(input_string):
    result = re.sub(r'(0[xX])?[0-9a-fA-F]+', '', input_string)
    return result

def if_other_same(output_list):
    output_small_list = list()
    for item_json in output_list:
        item = item_json['content']
        item = item.replace(',', '')
        start = item.find('==')
        # # print(item)
        if start != -1:
            item = item[start:]
        # # print(item)

        rule_index = item_json['index']
        output_info = remove_numbers(item)
        one_dict = dict()
        one_dict['index'] = rule_index
        one_dict['content'] = output_info
        # print(output_info)
        output_small_list.append(one_dict)


    out_list = list()
    before_content = list()
    for item in output_small_list:
        rule_index = item['index']
        content = item['content']
        
        if content not in before_content:
            new_class = list()
            new_class.append(rule_index)
            before_content.append(content)
        else:
            continue
        for item2 in output_small_list:
            rule_index_match = item2['index']
            content_match = item2['content']
            if rule_index_match == rule_index:
                continue
            if content_match == content:
                # print(rule_index)
                # print(rule_index_match)
                new_class.append(rule_index_match)
        out_list.append(new_class)
    # print(out_list)

    return out_list

def split_msg(msg, flag):
    msg_lines = msg.split('\n')
    section_list = list()
    section_str = ''
    add_flag = False
    if flag == 'val':
        for line in msg_lines:
            # # print(line)
            # line_begin = line.find('== ')
            # line = line[line_begin + 2:].strip()
            # if line == '':
                
            #     # print('continue')
            #     continue
            if line.find('by ') == -1 and line.find('at ') == -1:
                if add_flag:
                    section_list.append(section_str)
                    section_str = line
                    
                else:
                    section_str = line
                    add_flag = True
            else:
                section_str += '\n'
                section_str += line
        if section_str.strip('\n').strip() != '':
            section_list.append(section_str)
    else:
        section_list = list()
    return section_list
                

def if_val_same(output_list, api, code_list, name_list, lib):
    # print(name_list)

    # split section of val result:
    cut_list = list()
    
    i = 0
    for output_json in output_list:
        cut_content_list = list()
        code = code_list[i]
        filename = name_list[i].split('/')[-1]
        i += 1
        # split section
        output = output_json['content']
        section_list = split_msg(output, 'val')
        
        final_list = list()
        cut_output = ''
        # # print('section list')
        # # print(section_list)

        for section in section_list:
            # # print(section)
            tmp_re = remove_numbers(section)
            # print(tmp_re)
            compile_in = compile_cmd_valgrind.replace('FUNC_NAME', 'tmp') + compile_dict[lib]
            if identify_error.if_api_related(code, section, api, filename, [], compile_in):
                # # print('true')
                if section.strip('\n').strip() not in final_list and tmp_re not in cut_content_list:
                    final_list.append(section.strip('\n').strip())
                    cut_output = cut_output + '\n' + section
                    cut_content_list.append(tmp_re)
            # else:
            #     # print('not add')
        
        # tmp_re = remove_numbers(cut_output)
        # # print(tmp_re)

        # print('cut: ')
        # print(output_json['index'])
        # print(cut_output)
        new_dict = dict()
        new_dict['content'] = cut_output
        new_dict['index'] = output_json['index']
        cut_list.append(new_dict)
            


    or_re = if_other_same(cut_list)
    return or_re






def get_all_err(code, lib, name_prefix):
    global root_passwd
    name_prefix = './' + name_prefix.split('/')[-1]
    with open(name_prefix + '.c', 'w') as f:
        f.write(code)

    out_dict = dict()
    out_dict['asan'] = ''
    out_dict['valgrind'] = ''
    out_dict['orig'] = ''
    asan_compile = compile_cmd_prefix.replace('FUNC_NAME', name_prefix) + compile_dict[lib]
    # print(asan_compile)
    valgrind_compile = compile_cmd_valgrind.replace('FUNC_NAME', name_prefix) + compile_dict[lib]
    if lib == 'libpcap':
        run_cmd1 = './' + name_prefix
        asan_run = 'echo %s | sudo -S %s' % (root_passwd, run_cmd1)
        orig_run = 'echo %s | sudo -S %s' % (root_passwd, run_cmd1 + '_val')
    else:
        asan_run = './' + name_prefix
        orig_run = asan_run + '_val'
    
    if lib == 'libpcap':
        run_cmd_val = 'valgrind --leak-check=full --quiet ' + name_prefix + '_val'
        valgrind_run = 'echo %s | sudo -S %s' % (root_passwd, run_cmd_val)
    else:
        valgrind_run = 'valgrind --leak-check=full --quiet ' + name_prefix + '_val'
    # # print(orig_run)

    return_info = subprocess.Popen(asan_compile, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = return_info.communicate(timeout=300)
    res_flag = return_info.returncode
    # print(asan_compile)
    # print(asan_run)
    clear_env()
    return_info = subprocess.Popen(asan_run, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = return_info.communicate(timeout=300)
    res_flag = return_info.returncode
    # print(return_info)

    info = err.decode("utf-8","ignore")
    if res_flag !=0 and res_flag != 123:
        out_dict['asan'] = info
    # else:
    #     # print(info)
    #     # print(res_flag)
 
    
    # valgrind
    return_info = subprocess.Popen(valgrind_compile, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = return_info.communicate(timeout=300)
    res_flag = return_info.returncode
    # print(valgrind_compile)
    # print(valgrind_run)

    clear_env()
    return_info = subprocess.Popen(valgrind_run, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
        res_flag = return_info.returncode
        info = err.decode("utf-8","ignore")
        out_dict['valgrind'] = info
    except:
        out_dict['valgrind'] = ''
        info = ''
    val_if_error = identify_error.parse_errmsg(code, info)
    # print(val_if_error)

    # if (res_flag !=0 and res_flag != 123) or val_if_error:
    #     out_dict['valgrind'] = info
        
    # orig:
    clear_env()
    return_info = subprocess.Popen(orig_run, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=300)
        res_flag = return_info.returncode
        info = err.decode("utf-8","ignore")
        if res_flag !=0 and res_flag != 123:
            out_dict['orig'] = info
    except:
        out_dict['orig'] = ''
    

    os.system('rm ' + name_prefix)
    os.system('rm ' + name_prefix + '_val')
    os.system('rm ' + name_prefix + '.c')
    return out_dict['asan'], out_dict['valgrind'], out_dict['orig']
# 
# def cluster_same_rules(out_code_prefix, rule_out, lib):
#     # out_code_prefix = out_code_prefix.replace('sqlite3_bind_blob64', )
#     # print(out_code_prefix)
#     new_fulter_rule = rule_out + '-parsed'
#     filter_rule = read_json(new_fulter_rule)
#     out_path = rule_out + '-cluster'
#     out_list = list()
#     asan_list = list()
#     val_list = list()
#     orig_list = list()
#     rule_dict= dict()
#     for rule_json in filter_rule:
#         name_prefix = './' + out_code_prefix.split('/')[-1]
#         # output_path = out_code_prefix + rule_json['index'] + '-output'
#         # print(rule_json)
        
#         code_path = out_code_prefix + rule_json['index'] + '.c'
#         code = get_code(code_path)
#         asan, valgrind, orig = get_all_err(code, lib, out_code_prefix + rule_json['index'])
        
#         # output_content = get_code(output_path)
#         # # print(output_content)
#         one_dict = dict()
#         one_dict['index'] = rule_json['index']
#         one_dict['content'] = asan
#         rule_item = dict()
#         rule_item['rule'] = rule_json['rule']
#         rule_item['parameter_index'] = rule_json['parameter_index']
#         rule_dict[rule_json['index']] = rule_item
#         # if output_content.find('AddressSanitizer') != -1:
#         asan_list.append(one_dict)
#         one_dict['content'] = valgrind
#         # else:
#         val_list.append(one_dict)
#         one_dict['content'] = orig
#         orig_list.append(one_dict)
    
#     out_list1 = if_asan_same(asan_list, out_code_prefix)
#     val_cmd = compile_cmd_valgrind.replace('FUNC_NAME', name_prefix) + compile_dict[lib]
#     out_list2 = if_val_same(val_list, val_cmd)
#     # print('asan:')
#     # print(out_list1)
#     # print('val cluster')
#     # print(out_list2)
#     out_list3 = if_other_same(orig_list)
#     # print('orig')
#     # print(out_list3)
#     out_list = list()
#     for item in out_list1:
#         if item not in out_list2 or item not in out_list3:
#             for index in item:
#                 out_list.append(index)
#         else:
#             out_list.append(item)
#     # out_list.extend(out_list2)
#     for item in out_list:
#         out_dict = dict()
#         rule_content = ''
#         for rule_index in item:
#             rule_content = rule_content + rule_dict[rule_index]['rule'] + '\n'
#         out_dict['rule'] = rule_content
#         out_dict['parameter_index'] = rule_dict[item[0]]['parameter_index']
#         out_dict['index'] = item
#         with open(out_path, 'a') as f:
#             f.write(json.dumps(out_dict))
#             f.write('\n')
#     return out_list, rule_dict

def get_same_list(list1, list2, list3):
    result = []
    lists = list1 + list2 + list3
    # print(lists)
    list_parse = sorted(lists,key=lambda i:len(i))
    # print(list_parse)
    parsed_list = list()
    for item in list_parse:
        
        if len(item) == 1:
            if item not in result and item[0] not in parsed_list:
                result.append(item)
            
        else:
            # print(item)
            hit1 = False
            hit2 = False
            hit3 = False
            for l in list1:
                if set(item) <= set(l):
                    hit1 = True
                    break
            for l in list2:
                if set(item) <= set(l):
                    hit2 = True
                    break
            for l in list3:
                if set(item) <= set(l):
                    hit3 = True
                    break
            if hit1 and hit2 and hit3:
                if item not in result:
                    result.append(item)
                # parsed_list.extend(item)
            else:
                # # print(parsed_list)
                # # print(item)

                for item_s in item:
                    if [item_s] not in result and item_s not in parsed_list:
                        result.append([item_s])
                        # parsed_list.extend(item_s)
        parsed_list.extend(item)
    return result

def cluster_same_rules2(out_code_prefix, rule_out, lib, api):
    # out_code_prefix = out_code_prefix.replace('sqlite3_bind_blob64', )
    # print(out_code_prefix)
    new_fulter_rule = rule_out
    # print(new_fulter_rule)
    filter_rule = read_json(new_fulter_rule)
    out_path = rule_out + '-cluster'
    if os.path.exists(out_path):
        os.remove(out_path)
    out_list = list()
    asan_list = list()
    val_list = list()
    orig_list = list()
    rule_dict= dict()
    output_dict = dict()
    out_list_all = list()
    code_list = list()
    name_list = list()
    index_dict = dict()
    for rule_json in filter_rule:
        # output_path = out_code_prefix + rule_json['index'] + '-output'
        # print(rule_json)
        # if rule_json['index'] != '11':
        #     continue
        code_path = out_code_prefix + rule_json['index'] + '.c'
        code = get_code(code_path)
        code_list.append(code)
        name_list.append('./' + out_code_prefix.split('/')[-1] + rule_json['index'] + '.c')
        asan, valgrind, orig= get_all_err(code, lib, out_code_prefix + rule_json['index'])

        asan = asan.strip('\n')
        valgrind = valgrind.strip('\n')
        orig = orig.strip('\n')
        with open(out_code_prefix + rule_json['index'] + 'clusteroutput', 'w') as f:
            f.write(asan + '\n' + valgrind + '\n' + orig +'\n')
        # print(asan)
        # print(valgrind)
        # print(orig)

        if asan == '' and valgrind == '' and orig == '':
            continue
        compile_in = compile_cmd_valgrind.replace('FUNC_NAME', 'tmp') + compile_dict[lib]
        
        if_all_not_related = True
        
        if valgrind != '':
            section_list = split_msg(valgrind, 'val')
            for section in section_list:
                # print(section)
                if identify_error.if_api_related(code, section, api, out_code_prefix.split('/')[-1] + rule_json['index'] + '.c', [], compile_in):
                    # # print('related')
                    # if int(rule_json['index']) > 10:

                    if_all_not_related = False
                    break
            # if if_all_not_related == True:
            #     continue
        # if rule_json['index'] == '3':

        # output_content = get_code(output_path)
        # # print(output_content)
        one_dict = dict()
        one_dict['index'] = rule_json['index']
        one_dict['content'] = asan
        rule_item = dict()
        output_item = dict()
        output_item['asan'] = asan
        output_item['val'] = valgrind
        output_item['orig'] = orig
        rule_item['rule'] = rule_json['rule']
        # rule_item['parameter_index'] = rule_json['parameter_index']
        rule_dict[rule_json['index']] = rule_item
        index_dict[rule_json['index']] = rule_index = get_related_index(rule_json['rule'])
        output_dict[rule_json['index']] = output_item
        # if output_content.find('AddressSanitizer') != -1:
        asan_list.append(one_dict)
        val_one_dict = copy.deepcopy(one_dict)
        val_one_dict['content'] = valgrind
        # else:
        val_list.append(val_one_dict)
        
        orig_dict = copy.deepcopy(one_dict)
        orig_dict['content'] = orig
        orig_list.append(orig_dict)

        # # print(asan_list)
        # # print(val_list)
        # # print(orig_list)

    
    out_list1 = if_asan_same(asan_list, out_code_prefix)
    out_list2 = if_val_same(val_list, api, code_list, name_list, lib)
    out_list3 = if_other_same(orig_list)
    # print('asan')
    # print(out_list1)
    # print('val_same: ')
    # print(out_list2)
    # print('orig')
    # print(out_list3)
    out_list1 = get_same_list(out_list1, out_list2, out_list3)
    # 0317-diff para-index
    # print(out_list1)

    out_list = list()
    for item in out_list1:
        if len(item) == 1:
            out_list.append(item)
        else:
            before_list = list()
            tmp_dict = dict()
            
            for rule_index in item:
                this_index = index_dict[rule_index]
                if this_index not in tmp_dict.keys():
                    tmp_dict[this_index] = [rule_index]
                else:
                    tmp_dict[this_index].append(rule_index)
            for key in tmp_dict.keys():
                items = tmp_dict[key]
                out_list.append(items)
    # print(out_list)
    # exit(1)
    # end
    for item in out_list:
        out_dict = dict()
        rule_content = ''
        for rule_index in item:
            rule_content = rule_content + rule_dict[rule_index]['rule'] + '\n'
        out_dict['rule'] = rule_content
        # out_dict['parameter_index'] = rule_dict[item[0]]['parameter_index']
        out_dict['index'] = item
        with open(out_path, 'a') as f:
            f.write(json.dumps(out_dict))
            f.write('\n')
    # print('final list:')
    # print(out_list)
    return out_list, rule_dict, output_dict

def if_para_match(API, para_list, rule):
    # print(rule)
    rule_index = get_related_index(rule)
    # print('Rule index: ' + str(rule_index))
    if rule_index == -1:
        return rule, False
    if rule_index > len(para_list):
        if len(para_list) == 1:
            rule_index = 1
            rule = rule.replace('Parameter ' + str(rule_index), 'Parameter ' + str(1))
            return rule, True
        else:
            return 'None', True
    para_index = 0
    match_index = list()
    for item in para_list:
        name = item['name']
        para_index += 1
        match_str = '`' + name + '`'
        if rule.find(match_str) != -1:
            match_index.append(para_index)
            # break
    if len(match_index) == 0:
        return rule, False
    if rule_index not in match_index:
        
       
        return rule, True
    else:
        return rule, False

# call this after cluster
def parse_final_rule_2(api, lib, rule_list, question_dict, out_log_prefix, out_code_prefix, right_code, rule_out, cluster_list, rule_dict, output_dict, declaration):
    # print(out_log_prefix)
    # filter_rule = read_json(rule_out)
    new_fulter_rule = rule_out + '-parsed'
    out_list = list()
    class_index = 0
    all_token = 0
    para_list, flag = parse_wrong_diff.get_parameter_list(declaration)
    exit_flag = False
    for one_class in cluster_list:
        token = 0
        class_index += 1
        wrong_code = ''
        i  = 0
        for item in one_class:
            i += 1
            rule = rule_dict[item]['rule']
            rule_index = item
            this_wrong_code = get_code(out_code_prefix + rule_index + '.c')
            this_wrong_code = parse_wrong_diff.del_comment_re(this_wrong_code)
            wrong_code = wrong_code + 'Code' + str(i) + ':\n```\n' + this_wrong_code + '\n```\n'
            begin = rule.lower().find('parameter ')
            # print(rule)
            
            num_str = list(rule[begin + len('parameter ') :])[0]
            # print(num_str)
            if num_str.isdigit():
                para_index = num_str
            else:
                para_index = ''
        log_path = out_log_prefix + '-' + str(class_index)
        response_path = log_path + '-response'
        # get para index:
        output_info = output_dict[one_class[0]]
        if len(one_class) > 1:
            response, parsed_rule, token = gen_final_rule(right_code, wrong_code, api, para_index, question_dict['parse_final_rule2'], log_path, output_info, declaration)
        else:
            prompt_prefix = question_dict['parse_final_rule2-one'].replace('RULE_NAME', rule_dict[one_class[0]]['rule'])
            response, parsed_rule, token = gen_final_rule(right_code, wrong_code, api, para_index, prompt_prefix, log_path, output_info, declaration)
        # if parsed_rule.strip().find('Parameter ' + para_index) != 0:
        #     parsed_rule = 'Parameter ' + para_index + ': ' + parsed_rule
        all_token += token
        with open(response_path, 'w') as f:
            f.write(response)
            f.write('\n')
        out_dict = dict()
        
        if flag == 0:
            parsed_rule['notdo'], flag_change1 = if_para_match(api, para_list, parsed_rule['notdo'])
            if flag_change1:
                exit_flag = True
            parsed_rule['do'], flag_change2 = if_para_match(api, para_list, parsed_rule['do'])
            if flag_change2:
                exit_flag = True
        if get_related_index(parsed_rule['notdo']) != get_related_index(parsed_rule['do']):
            if parsed_rule['notdo'] != '' and parsed_rule['do'] != '':
                exit_flag = True
                parsed_rule['notdo'] = 'ParaMatchError-None'
                parsed_rule['do'] = 'ParaMatchError-None'
        out_dict['rule-notdo'] = parsed_rule['notdo']
        out_dict['rule-do'] = parsed_rule['do']
        
        out_dict['index'] = class_index
        out_dict['parameter_index'] = para_index
        out_dict['cluster_class'] = one_class
        with open(new_fulter_rule, 'a') as f:
            f.write(json.dumps(out_dict))
            f.write('\n')
        out_list.append(parsed_rule['notdo'])
    return out_list, all_token, exit_flag

def parse_final_rule(api, lib, rule_list, question_dict, out_log_prefix, out_code_prefix, right_code, rule_out):
    # print(out_log_prefix)
    filter_rule = read_json(rule_out)
    new_fulter_rule = rule_out + '-parsed'
    out_list = list()
    for rule_json in filter_rule:
        rule = rule_json['rule']
        wrong_code = get_code(out_code_prefix + rule_json['index'] + '.c')
        log_path = out_log_prefix + '-' + rule_json['index']
        response_path = log_path + '-response'
        # get para index:
        begin = rule.lower().find('parameter ')
        # print(rule)
        
        num_str = list(rule[begin + len('parameter ') :])[0]
        # print(num_str)
        if num_str.isdigit():
            para_index = num_str
        else:
            para_index = ''
        response, parsed_rule, token = gen_final_rule(right_code, wrong_code, api, para_index, question_dict['parse_final_rule'], log_path)
        parsed_rule = 'Parameter ' + para_index + ': ' + parsed_rule
        with open(response_path, 'w') as f:
            f.write(response)
            f.write('\n')
        out_dict = dict()
        out_dict['rule'] = parsed_rule
        out_dict['index'] = rule_json['index']
        out_dict['parameter_index'] = para_index
        with open(new_fulter_rule, 'a') as f:
            f.write(json.dumps(out_dict))
            f.write('\n')
        out_list.append(parsed_rule)
    # print(filter_rule)
    return out_list, token


# TODO 718

    # return right_code, compile_cmd, compile_valgrind_cmd, flag

def generate_filter_rule_prompt(api, rule_list, prefix, declaration):
    prompt = prefix.replace('FUNC_NAME', api)
    prompt += declaration + '\n```\nOrig Rules: \n'
    i = 1
    for rule in rule_list:
        prompt += str(i) + '. ' + rule + '\n'
        i += 1
    return prompt

# def filter_rules(api, rule_list, declaration, prefix, out_log):
#     prompt = generate_filter_rule_prompt(api, rule_list, prefix, declaration)
#     response, token = query_1gpt(prompt, [], 0.1, True)
#     rule_list = parse_rule(response)
#     with open(out_log, 'w') as f:
#         out_content = 'Question: \n' + prompt + '\nAnswer: \n' + response + '\nParsed Rules: \n' + str(rule_list) + '\nNum: \n' + str(len(rule_list))
#         f.write(out_content + '\n')

#     return rule_list, token
# TODO:

def get_related_index(rule):
    prefix = 'Parameter'
    rule = rule.replace(':', ' ')
    begin = rule.find(prefix)
    out_list = list()
    nums_str = rule[begin + len(prefix) : ]
    # print(nums_str)
    num_list = nums_str.split(' ')
    for num_str in num_list:
        try:
            num = int(num_str)
            return num
        except:
            continue
    return -1



def auto_gen(api, lib, func_path, declaration, question_dict, out_dir, all_log):
    clear_env()
    print('Parse API: ' + api)
    global one_query
    global token_num
    # if api != 'pcap_free_datalinks' and api != 'xmlSchemaValPredefTypeNodeNoNorm':
    #     return True
    # rule_out: rule prompt, output and rule-list
    rule_out = out_dir + '/rule_log'
    # right_code_out: prompt, output, final code and final compile_cmd. 
    right_code_out = out_dir + '/right_code_log'
    parse_wrong_out = out_dir + '/parse_code_log'
    # wrong_code_out: prompt, output, final code and final compile_cmd. 
    wrong_code_out_prefix = out_dir + '/wrong_code_log'
    fix_right_code_out = out_dir + '/fix_right_log'
    fix_wrong_code_out_prefix = out_dir + '/fix_wrong_log'
    final_rule_out = out_dir + '/filter_rule'
    func_code_out = out_dir + 'func_code.c'
    fix_times = 0
    fix_times_run = 0
    parse_limit = 3
    all_out_dict = dict()
    token_rule = 0
    token_right = 0
    token_wrong = 0
    func_code = get_code(func_path)
    all_out_dict['Function'] = api
    all_out_dict['Lib'] = lib
    all_out_dict['LOC'] = len(func_code.split('\n'))
    all_out_dict['code_path'] = func_path
    all_out_dict['Output'] = out_dir
    all_out_dict['Orig_Rule'] = list()
    all_out_dict['Orig_Rule_Num'] = 0
    all_out_dict['Rule_Token'] = 0
    all_out_dict['Right_Code'] = ''
    all_out_dict['Compile_CMD'] = ''
    all_out_dict['Right_Fix_Times'] = 0
    all_out_dict['Right_Code_Success'] = False
    all_out_dict['Right_Code_Env'] = ''
    all_out_dict['Token_filter'] = 0
    all_out_dict['Error stage'] = ''
    all_out_dict['Right_Code_Token'] = 0
    all_out_dict['Wrong_Code_Success_Num'] = 0
    all_out_dict['Wrong_Code_Faild_Num'] = 0
    all_out_dict['Wrong_Fix_Times'] = 0
    all_out_dict['Wrong_Code_Token'] = 0
    all_out_dict['Wrong_Code_Faild_List'] = list()
    all_out_dict['Final_Error_Rule'] = list()
    all_out_dict['Final_Handle_Rule'] = list()
    all_out_dict['Final_Rule_Num'] = 0
    all_out_dict['All_Token'] = 0
    all_out_dict['Errmsg'] = ''
    env_info = ''
    
    all_out_dict['All_Query_Times'] = 0

    
    right_code_c = out_dir + '/' + api + '.c'
    wrong_code_c_prefix = out_dir + '/wrong_' + api

    final_out_prefix = out_dir + '/parse_rule'

    
    with open(func_code_out, 'w') as f:
        f.write(func_code)
    
    if auto_flag != 'rule' and auto_flag != 'all' and auto_flag != 'first2':
        # TODO
        if func_path not in info_dict.keys():
            # print('todo path:')
            # print(func_path)
            # print('not in info_dict')
            return False
        all_out_dict = info_dict[func_path]
        rule_list = info_dict[func_path]['Orig_Rule']
        all_out_dict['Orig_Rule'] = rule_list
        all_out_dict['Orig_Rule_Num'] = len(rule_list)
        # all_out_dict['Rule_Token'] = -1
        if len(rule_list) == 0:
            all_out_dict['Errmsg'] = 'Success'
            # all_out_dict['All_Token'] = -1
            # all_out_dict['All_Query_Times'] = -1
            # print('rule = 0')
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return True
        # print('read from info-log')
    
    if auto_flag == 'wrong':
        # TODO
        all_out_dict = info_dict[func_path]
        # todebug
        one_query = info_dict[func_path]['All_Query_Times']
        rule_list = info_dict[func_path]['Rule_Dict']
        token_num = info_dict[func_path]['All_Token']
        # all_out_dict['Before_Rule'] = rule_list
        # all_out_dict['Before_Rule_Num'] = len(rule_list)
        # all_out_dict['Rule_Token'] = -1
        if len(rule_list) == 0:
            all_out_dict['Errmsg'] = 'Success'
            # all_out_dict['All_Token'] = -1
            # all_out_dict['All_Query_Times'] = -1
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return True
        # print('read from info-log')
        right_code = info_dict[func_path]['Right_Code']
        all_out_dict['Right_Code'] = right_code
        # all_out_dict['Right_Fix_Times'] = -1
        all_out_dict['Right_Code_Success'] = info_dict[func_path]['Right_Code_Success']
        # all_out_dict['Right_Code_Token'] = -1
        all_out_dict['Right_Code_Env'] = info_dict[func_path]['Right_Code_Env']
        all_out_dict['Errmsg'] = info_dict[func_path]['Errmsg']
        all_out_dict['All_Query_Times'] = one_query
        all_out_dict['All_Token'] = token_num
        # all_out_dict['Compile_CMD'] = info_dict[func_path]['Compile_CMD']
        compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
        compile_valgrind_cmd = compile_cmd_valgrind.replace('FUNC_NAME', api) + compile_dict[lib]
        # print('read right code from info')
        if all_out_dict['Right_Code_Success'] == False:
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return False
    else:
        # 2.generate right code:
        clear_env()
        # return right_code, compile_cmd, compile_valgrind_cmd, flag, error_stage, fix_times
        right_code, compile_cmd, compile_valgrind_cmd, right_code_flag, error_stage, fix_times, token_right = generate_right_code(api, lib, question_dict, right_code_out, func_code)
        # write right code info to log and continue
        if right_code_flag:
            all_out_dict['Right_Code'] = right_code
            all_out_dict['Error stage'] = error_stage
            all_out_dict['Right_Fix_Times'] = fix_times
            all_out_dict['Compile_CMD'] = compile_cmd
            all_out_dict['Compile_valgrind_cmd'] = compile_valgrind_cmd
            all_out_dict['Right_Code_Success'] = True
            all_out_dict['Errmsg'] = 'Success-right'
            all_out_dict['Right_Code_Token'] = token_right

            with open(right_code_c, 'w') as f:
                f.write(right_code)
        else:
            # all_out_dict['Right_Code'] = right_code
            all_out_dict['Error stage'] = error_stage
            all_out_dict['Right_Fix_Times'] = fix_times
            all_out_dict['Compile_CMD'] = compile_cmd
            all_out_dict['Compile_valgrind_cmd'] = compile_valgrind_cmd
            all_out_dict['Right_Code_Success'] = False
            all_out_dict['Right_Code_Token'] = token_right
            all_out_dict['Errmsg'] ='Right Code Wrong'
            all_out_dict['All_Query_Times'] = one_query
            all_out_dict['All_Token'] = token_num
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return False

        if auto_flag == 'right':
            # all_out_dict['Right_Code'] = right_code
            # all_out_dict['Right_Fix_Times'] = fix_times
            # all_out_dict['Compile_CMD'] = compile_cmd
            # all_out_dict['Right_Code_Success'] = True
            # all_out_dict['Right_Code_Token'] = token_right
            # all_out_dict['Errmsg'] = 'Success'
            all_out_dict['All_Query_Times'] = one_query
            all_out_dict['All_Token'] = token_num
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return True
        
    # 3.generate wrong code=generate question:
    
    # print('parse Wrong code generation')
    # fix_times = 0
    # token_wrong = 0
    # rule_index = 0
    # final_rule_error = list()
    # final_rule_handle = list()
    # for rule in rule_list:
    #     parse_flag = False
    #     i = 0
    #     rule_index += 1
    #     fix_wrong_code_out = fix_wrong_code_out_prefix + str(rule_index)
    #     # print(rule)
    #     wrong_code_out = wrong_code_out_prefix + str(rule_index)
    #     prompt = generate_wrongcode_prompt(api, rule, right_code, declaration, question_wrong)
    #     # i += 1
    #     answer, token = query_1gpt(prompt, [], 0.3, True)
    #     token_wrong += token
    #     wrong_log_content = 'Question: \n' + prompt + '\n\nAnswer: \n' + answer
    #     with open(wrong_code_out, 'w') as f:
    #         f.write(wrong_log_content)
    #     wrong_code = parse_wrong_code(answer)
    #     diff_re = diff_code(right_code, wrong_code, rule, api, declaration)
    #     # diff_re = True
        
    #     if wrong_code == 'ERROR' or wrong_code.find('main') == -1:
    #         with open(parse_wrong_out, 'a') as f:
    #             f.write('Answer: \n' + answer + '\nParse Re: \n' + wrong_code + '\n')
    #         parse_flag = False
    #     else:
    #         parse_flag = True
    #     if not parse_flag:
    #         # all_out_dict['Wrong_Code_Success_Num'] = 0
    #         all_out_dict['Wrong_Code_Faild_Num'] += 1
    #         all_out_dict['Wrong_Code_Faild_List'].append(rule)
    #         # all_out_dict['Wrong_Fix_Times'] = 0
    #         all_out_dict['Wrong_Code_Token'] = token_wrong
    #         continue
    #     if diff_re == False:
    #         info = 'Error: Please check the Rule, and change the code to violate the rule!\n'
    #         result = False
    #     else:
    #         result, msg, info = compile_code(api, wrong_code, compile_cmd)
    #     prev_msgs = list()
    #     prev_msgs.append({"role": "user", "content": prompt})
    #     prev_msgs.append({"role": "assistant", "content": answer})
    #     if not result:
    #         # fix_error(error_type, api, code, cmd, info, before_prompt, question_fix_right, prev_msgs, lib, log_path, parse_wrong_out)
    #         result, wrong_code, compile_cmd, fix_times, token_fix, env_info = fix_error_wrong('compile', api, right_code, wrong_code, declaration, rule, compile_cmd, info, prompt, question_fix_wrong, prev_msgs, lib, fix_wrong_code_out, parse_wrong_out)
    #         # if env_info != '':
    #         #     all_out_dict['Right_Code_Env'] = env_info
    #         token_wrong += token_fix
    #     if not result:
    #         all_out_dict['Wrong_Code_Faild_Num'] += 1
    #         all_out_dict['Wrong_Code_Faild_List'].append(rule)
    #         all_out_dict['Wrong_Fix_Times'] += fix_times
    #         all_out_dict['Wrong_Code_Token'] = token_wrong
    #         continue
        
    #     file_name = 'example.db'
    #     if os.path.exists(file_name):
    #         os.remove(file_name)
    #     os.system('cp ../example_data//example.db .')
    #     result, msg, info = run_code(api, wrong_code)

            
    #     all_out_dict['Wrong_Code_Success_Num'] += 1
    #     all_out_dict['Wrong_Fix_Times'] += fix_times
    #     all_out_dict['Wrong_Code_Token'] = token_wrong
    #     write_debug_wrong(right_code, wrong_code, rule, declaration, api)
    #     if not result:
    #         if msg == 123:
    #             final_rule_handle.append(rule)
    #         else:
    #             final_rule_error.append(rule)
    #     wrong_log_content = '\n\nFinal Code: \n' + wrong_code + '\n\nFinal Compile Cmd: \n' + compile_cmd + '\n\nRun Output: \n' + info + '\n\nRun Flag: \n' + str(result) + '\n'
    #     with open(wrong_code_out, 'a') as f:
    #         f.write(wrong_log_content)
    #     wrong_code_c = wrong_code_c_prefix + str(rule_index) + '.c'
    #     with open(wrong_code_c, 'w') as f:
    #         f.write(wrong_code)
    #     if result:
    #         # print(rule)
    #         # print('wrong rule')
    #         # wrong rule parse
    #     else:
    #         # right rule
    #         # print(rule)
    #         # print('right rule')
    #         with open(final_rule_out, 'a') as f:
    #             out_dict = dict()
    #             out_dict['rule'] = rule
    #             out_dict['wrong_source'] = wrong_code_c
    #             out_dict['api'] = api
    #             f.write(json.dumps(out_dict))
    #             f.write('\n')
    # rule_list, token_filter = filter_rules(api, rule_list, declaration, question_dict['filter'], filter_out)
    # all_out_dict['Orig_Rule'] = rule_list
    # all_out_dict['Orig_Rule_Num'] = len(rule_list)
    # all_out_dict['Token_filter'] = token_filter
    # with open(all_log, 'a') as f:
    #     f.write(json.dumps(all_out_dict))
    #     f.write('\n')
    # return True
    # rule_list, token_split = split_rules(api, rule_list, declaration, question_dict['split'], split_out)
    # all_out_dict['Orig_Rule'] = rule_list
    # all_out_dict['Orig_Rule_Num'] = len(rule_list)
    # all_out_dict['Token_split'] = token_split
    # with open(all_log, 'a') as f:
    #     f.write(json.dumps(all_out_dict))
    #     f.write('\n')
    # return True
    if len(all_out_dict['Final_Error_Rule']) != 0:
        
        # parsed_rule, token = parse_final_rule(api, lib, rule_list, question_dict, final_out_prefix, wrong_code_c_prefix, right_code, final_rule_out)
        
        cluster_list, rule_dict, output_dict = cluster_same_rules2(wrong_code_c_prefix, final_rule_out, lib, api)
        parsed_rule, token, exit_flag = parse_final_rule_2(api, lib, rule_list, question_dict, final_out_prefix, wrong_code_c_prefix, right_code, final_rule_out, cluster_list, rule_dict, output_dict, declaration)
    
    # faild_list, right_rules, fix_times, token_wrong = generate_wrong_code(api, lib, rule_list, question_dict,wrong_code_out_prefix, wrong_code_c_prefix, right_code, declaration, compile_cmd, compile_valgrind_cmd, final_rule_out)
    # 
    else:
        # if_cluster_flag = False
        parsed_rule = list()
        cluster_list = list()
        # diff_list = list()
        token = 0
    # 

    all_out_dict['Parse_Rule_Times'] = len(cluster_list)
    all_out_dict['Parse_Rule_Token'] = token
    all_out_dict['Parsed_Rule'] = parsed_rule
    all_out_dict['All_Query_Times'] = one_query
    all_out_dict['All_Token'] = token_num
    # cluster:
    all_out_dict['Cluster_Rule'] = cluster_list
    # diff:
    # all_out_dict['Diff_Output_Rule'] = diff_list
    # TODO: delete
    # if if_cluster_flag:
    with open(all_log, 'a') as f:
        f.write(json.dumps(all_out_dict))
        f.write('\n')
    # if exit_flag:
    #     # print('something happens exit!')


def read_API(path):
    out_list = list()
    content = ''
    with open(path, 'r') as f:
        content = f.read()
    out_list = content.strip('\n').split('\n')
    return out_list

def if_skip(path, out_dir):
    # # print(out_dir)
    out_dir = out_dir.strip('/').split('/')[-1]
    # # print(path)
    if not os.path.exists(path):
        return False
    res_list = read_json(path)
    dir_list = list()
    for item in res_list:
        dir = item['Output'].strip('/').split('/')[-1]
        # # print(dir)
        dir_list.append(dir)
    # exit(1)
    # # print(dir_list)
    # exit(1)
    if out_dir in dir_list:
        return True
    else:
        return False


if __name__ == '__main__':
    

    parse_temperature = 1
    auto_flag = 'wrong'
    question_dir = '../prompt/'
    
    # CHANGE
    orig_key = ''
    api_key = ''
    api_path = '../test_info/api_info/api_list'
    callgraph_path = '../test_info/api_info/call_graph'
    root_passwd = ''
    out_dir = '../test_info/out_refinement/'
    info_dir = '../test_info/out_wrong_code/'
    # END
    
    all_log = out_dir + 'auto_rule_info'
    gpt_answer_dir = out_dir + 'gpt_re/'
    in_info_list = list()
    info_dict = dict()
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    if not os.path.exists(gpt_answer_dir):
        os.mkdir(gpt_answer_dir)

    info_log = info_dir + '/auto_rule_info'

    if not os.path.exists(out_dir + '/target_api'):
        os.system('cp ' + api_path + ' ' + out_dir + '/target_api')
    if not os.path.exists(out_dir + '/call_graph'):
        os.system('cp ' + callgraph_path + ' ' + out_dir + '/call_graph')
    # TODO
    # read json-dict
    in_info_list = read_json(info_log)
    for item in in_info_list:
        code_path = item['code_path']
        info_dict[code_path] = item
        
    parse_exists_log = out_dir + '/exists_log'
    
    gpt_answer_index = 0
    

    rule_question_prefix = question_dir + 'rule'
    right_question_prefix = question_dir + 'RightCode'
    wrong_question_prefix = question_dir + 'ViolationCode'

    parse_final_rule_prefix2 = question_dir + 'RefineMore'
    parse_final_rule_prefix_one = question_dir + 'RefineOne'
    one_query = 0
    token_num = 0
    token_all_big = 0
    
    callgraph_list = read_json(callgraph_path)
    callgraph_index = dict()
    question_dict = dict()
    for item in callgraph_list:
        func_name = item['func']
        list_index = callgraph_list.index(item)
        if func_name not in callgraph_index.keys():
            callgraph_index[func_name] = [list_index]
        else:
            callgraph_index[func_name].append(list_index)
    api_list = read_API(api_path)
    
    # get question dict:
    with open(rule_question_prefix, 'r') as f:
        question_dict['rule'] = f.read()

    with open(right_question_prefix, 'r') as f:
        question_dict['right'] = f.read()
    with open(wrong_question_prefix, 'r') as f:
        question_dict['wrong'] = f.read()

    with open(parse_final_rule_prefix2, 'r') as f:
        question_dict['parse_final_rule2'] = f.read()
    with open(parse_final_rule_prefix_one, 'r') as f:
        question_dict['parse_final_rule2-one'] = f.read()
    api_num = 0
    for api in api_list:
        # print(api)

        
        file_name = 'example.db'
        if os.path.exists(file_name):
            os.remove(file_name)
        os.system('cp ../example_data//example.db .')
        api_num += 1
        one_query = 0 
        token_num = 0
        token_all_big += token_num
        # get callgraph:
        if api not in callgraph_index.keys():
            # print(api)
            # print('Func info not exists!')
            with open(parse_exists_log, 'a') as f:
                f.write(api + '\n')
            continue
        else:
            out_dir_api = out_dir + '/' + api
            cp_dir = info_dir + '/' + api
            if not os.path.exists(out_dir_api):
                # print('before cp')
                # print(cp_dir)
                # print(out_dir_api)
                os.system('cp -r ' + cp_dir + ' ' + out_dir)
            # exit(1)
            callgraph_index[api] = list(set(callgraph_index[api]))
            if len(callgraph_index[api]) == 1:
                out_dir_api += '/'
                # # print(out_dir_api)
                # # print(all_log)
                # exit(1)
                if if_skip(all_log, out_dir_api):
                    # print(api + ' already parsed')
                    continue
                # debug:
                # # print(out_dir_api)
                
                if not os.path.exists(out_dir_api):
                    os.mkdir(out_dir_api)
                # continue
                info = callgraph_list[callgraph_index[api][0]]
                call_order = info['call_graph']
                lib = info['lib']
                analyse_num = info['analyse_func_num']
                analyse_num = 1
                path = info['path']
                declaration = info['declaration']
                code = get_code(path)
                if analyse_num == 1:
                    # TODO:question_dict
                    auto_gen(api, lib, path, declaration, question_dict, out_dir_api, all_log)
                else:
                    # some fc in this api, need to analyse other func 
                    # TODO
                    prompt = generate_rule_prompt()
                    parse_rule(prompt)

            else:
                # api has multi definition:
                # TODO
                i = 0
                for function_index in callgraph_index[api]:
                    info = callgraph_list[function_index]
                    lib = info['lib']
                    i += 1
                    out_dir1 = out_dir_api + str(i) + '/'
                    if if_skip(all_log, out_dir1):
                        # print(api + ' already parsed')
                        continue
                    # # print(out_dir1)
                    
                    one_query = 0 
                    token_num = 0
                    if not os.path.exists(out_dir1):
                        os.mkdir(out_dir1)
                    # continue
                    call_order = info['call_graph']
                    analyse_num = info['analyse_func_num']
                    analyse_num = 1
                    path = info['path']
                    declaration = info['declaration']
                    code = get_code(path)
                    if analyse_num == 1:
                        # TODO:question_dict
                        auto_gen(api, lib, path, declaration, question_dict, out_dir1, all_log)
                    else:
                        # some fc in this api, need to analyse other func 
                        # TODO
                        prompt = generate_rule_prompt()
                        parse_rule(prompt)
        # generate rule-generate question:
        # if api_num >= 5:
        #     break
        
        file1 = './' + api + '.c'
        file2 = './' + api
        os.system('rm ' + file1)
        os.system('rm ' + file2)
        # print('test')
        # exit(1)
    # print('ALL token:')
    # print(token_all_big)
    rm_env()
