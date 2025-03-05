import json
import os
import sys
import openai
import time
import subprocess
import parse_wrong_diff
import identify_error
import tiktoken

gpt_token_small_limit = 4000
gpt_token_large_limit = 16000
right_temperature = 1
wrong_temperature = 0
fix_temperature = 0


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

# e.g. get_value_from_json(list, 'pcap_freecode', 'func') will get json of pcap_freecode
def get_value_from_json(json_list, key_value, key_match):
    for item in json_list:
        key = item[key_match]
        if key == key_value:
            return item
    return None

def clear_env():
    file_list = ['example.db', 'example.pcap', 'example.xml', 'example.zip']
    for file_name in file_list:
        # file_name = 'example.db'
        if os.path.exists(file_name):
            os.remove(file_name)
        os.system('cp ../example_data/' + file_name + ' .')

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
        print("Warning: model not found. Using cl100k_base encoding.")
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
        print("Warning: gpt-3.5-turbo may update over time. Returning num tokens assuming gpt-4o-mini.")
        return num_tokens_from_messages(messages, model="gpt-4o-mini")
    elif "gpt-4" in model:
        print("Warning: gpt-4 may update over time. Returning num tokens assuming gpt-4-0613.")
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
    global one_query
    global gpt_answer_index
    global token_num
    global orig_key
    global api_key
    answer_path = gpt_answer_dir + '/' + str(gpt_answer_index)
    gpt_answer_index += 1

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
                continue
            token = response['usage']['total_tokens']
            token_num += token
            finish_reason = response["choices"][0]["finish_reason"]
            response = response["choices"][0]["message"]["content"].strip('\n')

            if finish_reason == 'length':
                if model_select == "gpt-4o-mini" and big_flag:
                    model_select = 'gpt-4o-mini'
                    continue
                else:
                    return '', gpt_token_large_limit
            flag = response

            out_string = 'Question: \n' + prompt + '\n\n' + 'Answer: \n' + response

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
                    print("Input text exceeds the maximum token limit.")
                    return '', token_limit
            else:
                # Handle other API errors
                print("An error occurred:", e)
                if str(e).lower().find('connection') != -1:
                    print('Cannot connect to OpenAI!')
                    exit(1)
                return '', token_limit
        except:
            print("Connection refused by the server..")

            print("Let me sleep for 5 seconds")

            print("ZZzzzz...")

            time.sleep(5)

            print("Was a nice sleep, now let me continue...")

            continue
    

def generate_rightcode_prompt(func, lib, func_code, question):
    prompt = question.replace('FUNC_NAME', func).replace('LIB_NAME', lib).replace('SOURCE_CODE', func_code)
    # prompt = prompt + '\n\n' + 'invocation specification of ' + func + ': \n```\n'
    # for rule in rule_list:
    #     prompt = prompt + rule + '\n'
    # prompt = prompt + '```'

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

        return '', ''
    answer = answer.replace('Task 2', 'Task2')
    answer = answer.replace('Task 3', 'Task3')
    answer = answer.replace('Task 4', 'Task4')
    right_code = ''
    compile_cmd = ''
    task_index = answer.find('Task3')
    if task_index == -1:
        code = answer
    else:
        code = answer[task_index:]
    code_format = ['```code', '```cpp', '```c', '```', '```C++', '```python']
    for format in code_format:
        code_begin = code.find(format)
        if code_begin == -1:
            continue
        else:
            code = code[code_begin + len(format): ]
            break
    if code == '':

        return '', ''
    # if code_begin_index == -1:
    #     return right_code, ''
    
    # if code_begin_index == -1:
    #     return right_code, ''
    code_end_index = code.find('```')
    right_code = code[:code_end_index]
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

    if right_code.find('main') == -1:

        return '', ''
    return right_code, env_info
    
def parse_wrong_code(answer, lib):
    if answer.find('```') == -1:

        # exit(1)
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

    if right_code.find('main') == -1:

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

# def auto_fix(prev_msg, prev_cmd, api, lib):
#     parse_flag = False
#     try_limit = 3
#     i = 0
#     token_all = 0
#     env_info = ''
#     while not parse_flag:
#         i += 1
#         if i > try_limit:
#             return '', '', '', token_all, env_info
#         answer, token = query_1gpt('', prev_msg, 0.3, False)
#         token_all += token
#         right_code, compile_cmd, env_info1 = parse_right_code(answer, api, lib)
#         if not (env_info != '' and env_info1 == ''):
#             env_info = env_info1
#         if compile_cmd == '':
#             compile_cmd = prev_cmd
#         if right_code.find('main') == -1 or compile_cmd.find(api + '.c') == -1:
#             parse_flag = False
#         else:
#             parse_flag = True
#     return right_code, compile_cmd, answer, token_all, env_info

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
def generate_fix_continue_prompt(prev_msg, answer_code, errmsg, right_wrong):
    
    
    prompt = 'Run result of the code is: \n' + errmsg + "Please fix this code based on the run result. Please Follow the instruction in the first session! \nNote: I am using the program automation to run the code you gave, so please generate the code directly that will run correctly."
    prompt += '\nAnswer Format: ```code```'
    if right_wrong != None:
        prefix = 'Violate the rule: ' + right_wrong['rule'] + ' \nFollowing this Violation Example: \n```\n' + right_wrong['code'] + '\n```\n'
        prompt = prefix + 'Important: Make sure you violate the rule following the violation example.\nThe violation example might be wrong, You can tweak the example code a bit\n' + prompt
    prev_msg.append({"role": "user", "content": prompt})
    return prev_msg
    
# TODO test
def generate_fix_new_prompt(prev_msg:list, answer_code, error_msg, right_wrong):
    new_prompt = 'Run result of the code is: \n' + error_msg + "Please fix this code based on the run result. Please Follow the instruction in the first session!\nNote: I am using the program automation to run the code you gave, so please generate the code directly that will run correctly"
    new_prompt += '\nAnswer Format: ```code```'
    if right_wrong != None:
        prefix = 'Violate the rule: ' + right_wrong['rule'] + ' \nFollowing this Violation Example: \n```\n' + right_wrong['code'] + '\n```\n'
        new_prompt = prefix + 'Important: Make sure you violate the rule following the violation example.\nThe violation example might be wrong, You can tweak the example code a bit\n' + new_prompt
    
    right_prompt = prev_msg[0]
    prev_msg = list()
    prev_msg.append({"role": "user", "content": right_prompt})
    prev_msg.append({"role": "assistant", "content": answer_code})
    prev_msg.append({"role": "user", "content": new_prompt})
    return prev_msg
    
    
# def fix_error(error_type, api, code, cmd, info, before_prompt, question_fix_right, prev_msgs, lib, log_path, parse_wrong_out):

#     times = 0
#     fix_times_limit = 10
#     big_flag = False
#     if error_type == 'compile':
        
#         extract_error = extract_compile_error
#     elif error_type == 'run':
#         big_flag = True
#         extract_error = extract_run_error
#     prev_error_msg = extract_error(info, code)
#     error_msg = ''
#     result_flag = False
#     repeat_times_limit = 3
#     repeat_times = 0
#     # 该list代表已经尝试过的fix策略，如果两种都尝试过了，那么返回false
#     # : new, continue
#     finished_fix = list()
#     fix_method = 'continue'
#     finished_fix.append(fix_method)
#     token_all = 0
#     first_flag = True
#     # generate fix prompt
#     session_msg = prev_msgs
#     token = 0
#     while not result_flag:
#         times += 1
#         # TODO write log to path
#         if first_flag:
#             first_flag = False
#             out_content = 'Retry 1:\nCode: \n' + code + '\ncompile_cmd: ' + cmd + '\nResult: \n' + info + '\n'
#             with open(log_path, 'a') as f:
#                 f.write(out_content)
#         else:
#             with open(log_path, 'a') as f:
#                 f.write('Retry ' + str(times) + ':\n')
        
#         if times >= fix_times_limit:
#             return False , '', '', times, token_all, ''
#         # TODO: Token 怎么获得
#         if token > gpt_token_large_limit:
#             return False , '', '', times, token_all, ''
#         # 根据fix策略不同，有不同的prompt生成方式
#         if fix_method == 'continue':
#             prompt_new = ''
#             # TODO: 原来的那个prompt，现在的不对
#             # prompt_list = generate_fix_continue_prompt(before_prompt, code, prev_error_msg, error_type)
#             prompt_list = generate_fix_right_prompt(cmd, question_fix_right, prev_error_msg, session_msg)
#             question_add = prompt_list[-1]['content']
#             with open(log_path, 'a') as f:
#                 f.write('Query GPT Question: \n')
#                 f.write(question_add + '\n')
#         elif fix_method == 'new':
#             prompt_new = before_prompt
#             prompt_list = []
#             fix_method = 'continue'
#         else:
#             return False, '', '', times, token_all, ''
#         answer, token = query_1gpt(prompt_new, prompt_list, 0.3, big_flag)
#         token_all += token
#         if error_type == 'compile' and token >= 4000:
#             return False, '', '', times, token_all, ''
#         # 构造会话信息
#         session_msg.append({"role": "assistant", "content": answer})
#         with open(log_path, 'a') as f:
#             f.write('Query GPT Answer: \n')
#             f.write(answer + '\n')
        
#         # 处理gpt结果
#         code, cmd, env_info = parse_right_code(answer, api, lib)
#         if code.find('main') == -1:
#             with open(parse_wrong_out, 'a') as f:
#                 f.write('Answer: \n' + answer + '\nParse Re: \n' + code + '\n')
#             return False, '', '', times, token_all, ''
#         if code.find(api) == -1:
#             result_flag = False
#             info = 'Error: ' + api + ' is not called in this code!\n'
#         else:
#         # 动态执行
#             result_flag, error_type, info = compile_code(api, code, cmd)
#         out_content = '\nCode: \n' + code + '\ncompile_cmd: ' + cmd + '\nResult: \n' + info + '\n'
#         with open(log_path, 'a') as f:
#             f.write(out_content)
#         error_msg = extract_error(info, code)
#         if not result_flag:
#         # 如果连续多次出现同一个错误，说明gpt无法自动修复，那么尝试更换策略
#         # TODO 如何判断是同一错误
#             if error_msg.strip() == prev_error_msg.strip():
#                 repeat_times += 1
#                 if repeat_times > repeat_times_limit:
#                     out_content = '\nUse New Fix method!\n'
#                     with open(log_path, 'a') as f:
#                         f.write(out_content)
#                     fix_method = 'new'
#                     # else:
#                     #     fix_method = 'continue'
#             # 如果错误与之前的错误不同，说明gpt可能修复了一个问题，到达了第二个问题，那么times归零
#             else:
#                 repeat_times = 0
#             prev_error_msg = error_msg
#             continue
#         else:
#             file_name = 'example.db'
#             if os.path.exists(file_name):
#                 os.remove(file_name)
#             os.system('cp ../example_data/example.db .')
#             result_flag, error_type, info = run_code(api, code)
#             out_content = '\nCode: \n' + code + '\ncompile_cmd: ' + cmd + '\nResult: \n' + info + '\n'
#             with open(log_path, 'a') as f:
#                 f.write(out_content)
#             error_msg = extract_error(info, code)
#             prev_error_msg = error_msg
            
#     # query gpt
#     # compile
#     # loop until True
#     return True, code, cmd, times, token_all, env_info

# def fix_error_wrong(error_type, api, orig_code, code, declaration, rule,  cmd, info, before_prompt, question_fix_right, prev_msgs, lib, log_path, parse_wrong_out):

#     times = 0
#     fix_times_limit = 10
#     big_flag = False
#     if error_type == 'compile':
        
#         extract_error = extract_compile_error
#     elif error_type == 'run':
#         big_flag = True
#         extract_error = extract_run_error
#     prev_error_msg = extract_error(info, code)
#     error_msg = ''
#     result_flag = False
#     repeat_times_limit = 3
#     repeat_times = 0
#     # 该list代表已经尝试过的fix策略，如果两种都尝试过了，那么返回false
#     # : new, continue
#     finished_fix = list()
#     fix_method = 'continue'
#     finished_fix.append(fix_method)
#     token_all = 0
#     first_flag = True
#     # generate fix prompt
#     session_msg = prev_msgs
#     token = 0
#     while not result_flag:
#         times += 1
#         # TODO write log to path
#         if first_flag:
#             first_flag = False
#             out_content = 'Retry 1:\nCode: \n' + code + '\ncompile_cmd: ' + cmd + '\nResult: \n' + info + '\n'
#             with open(log_path, 'a') as f:
#                 f.write(out_content)
#         else:
#             with open(log_path, 'a') as f:
#                 f.write('Retry ' + str(times) + ':\n')
        
#         if times >= fix_times_limit:
#             return False , '', '', times, token_all, ''
#         # TODO: Token 怎么获得
#         if token > gpt_token_large_limit:
#             return False , '', '', times, token_all, ''
#         # 根据fix策略不同，有不同的prompt生成方式
#         if fix_method == 'continue':
#             prompt_new = ''
#             # TODO: 原来的那个prompt，现在的不对
#             # prompt_list = generate_fix_continue_prompt(before_prompt, code, prev_error_msg, error_type)
#             # generate_fix_wrong_prompt(compile_cmd, question_fix_wrong, info, prev_msgs)
#             prompt_list = generate_fix_wrong_prompt(cmd, question_fix_right, prev_error_msg, session_msg)
#             question_add = prompt_list[-1]['content']
#             with open(log_path, 'a') as f:
#                 f.write('Query GPT Question: \n')
#                 f.write(question_add + '\n')
#         elif fix_method == 'new':
#             prompt_new = before_prompt
#             prompt_list = []
#             fix_method = 'continue'
#         else:
#             return False, '', '', times, token_all, ''
#         answer, token = query_g1pt(prompt_new, prompt_list, 0.3, big_flag)
#         token_all += token
#         if error_type == 'compile' and token >= 4000:
#             return False, '', '', times, token_all, ''
#         # 构造会话信息
#         session_msg.append({"role": "assistant", "content": answer})
#         with open(log_path, 'a') as f:
#             f.write('Query GPT Answer: \n')
#             f.write(answer + '\n')
        
#         # 处理gpt结果
#         code = parse_wrong_code(answer)
        
#         diff_re = diff_code(orig_code, code, rule, api, declaration)
#         # diff_re = True
#         if diff_re == False:
#             info = 'Error: Please check the Rule, and change the code to violate the rule!\n'
#             with open(parse_wrong_out, 'a') as f:
#                 f.write('Answer: \n' + answer + '\nParse Re: \n' + code + '\n')
#                 # f.write('Error: ')
            
#             result_flag = False
#             parse_flag = False
#         else:
#             if code.find('main') == -1:
#                 with open(parse_wrong_out, 'a') as f:
#                     f.write('Answer: \n' + answer + '\nParse Re: \n' + code + '\n')
#                 return False, '', '', times, token_all, ''
#             if code.find(api) == -1:
#                 result_flag = False
#                 info = 'Error: ' + api + ' is not called in this code!\n'
#             else:
#             # 动态执行
#                 result_flag, error_type, info = compile_code(api, code, cmd)
#         out_content = '\nCode: \n' + code + '\ncompile_cmd: ' + cmd + '\nResult: \n' + info + '\n'
#         with open(log_path, 'a') as f:
#             f.write(out_content)
#         error_msg = extract_error(info, code)
#         if not result_flag:
#         # 如果连续多次出现同一个错误，说明gpt无法自动修复，那么尝试更换策略
#         # TODO 如何判断是同一错误
#             if error_msg.strip() == prev_error_msg.strip():
#                 repeat_times += 1
#                 if repeat_times > repeat_times_limit:
#                     out_content = '\nUse New Fix method!\n'
#                     with open(log_path, 'a') as f:
#                         f.write(out_content)
#                     fix_method = 'new'
#                     # else:
#                     #     fix_method = 'continue'
#             # 如果错误与之前的错误不同，说明gpt可能修复了一个问题，到达了第二个问题，那么times归零
#             else:
#                 repeat_times = 0
#         prev_error_msg = error_msg
#     # query gpt
#     # compile
#     # loop until True
#     return True, code, cmd, times, token_all, ''





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
    if not parse_wrong_diff.if_api_exists(code, api):
        return False, 'The code you generated did not call the API `' + api + '`, I am sure this api exists in this library, please check and make sure you call this api.', 'noapi'
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
        val_if_error, not_use = identify_error.parse_errmsg(code, info_valrun)
    # res_flag_valrun = res_flag_valrun and val_if_error

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
    info_orgrun = ''
    if val_timeout_flag:
        res_flag_orgrun = res_flag_run
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
        return False, info_valrun, 'run'
        
    tmp = info_run.find("Calling " + api)
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


    # return flag, output, error_stage

# TODO test
# 如果method是new，prev_msg中只有一个right_prompt
# 如果method是add，prev_msg是之前的user，assistant，需要再加一个user
def auto_fix_once(errmsg, answer_code, lib, compile_cmd, fix_method, prev_msg, right_wrong):
    right_code = ''
    token = 0
    # generate fix prompt
    if fix_method == 'new':
        # TODO test
        fix_prompt_msg = generate_fix_new_prompt(prev_msg, answer_code, errmsg, right_wrong)
    else:
        # TODO test
        fix_prompt_msg = generate_fix_continue_prompt(prev_msg, answer_code, errmsg, right_wrong)
    # query_1gpt
    response, token_fix = query_gpt('', fix_prompt_msg, fix_temperature, True)
    # parse gpt result
    right_code, env_info = parse_right_code(response, lib)
    
    fix_prompt_msg.append({"role": "assistant", "content": response})
    return right_code, token_fix, fix_prompt_msg

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
# TODO check
def judge_rule_wrong_code(flag, error_stage, code, errmsg, api, fc_list, compile_cmd):

    code = code.replace('\\n', '')
    
    debug = identify_error.get_error_code(code, errmsg, api, api + '.c')
    if error_stage == 'error-handling' or error_stage == 'timeout':
            flag = True
    if flag == True:
        # TODO write to file? this rule is a wrong rule
        return 'wrong-rule', str(debug)
    if flag == False and error_stage == 'compile':
        return 'fix', str(debug)
    if flag == False:
        if error_stage == 'run' and identify_error.if_api_related(code, errmsg, api, api + '.c', fc_list, compile_cmd):

            return 'right-rule', str(debug)
        else:
            return 'fix', str(debug)

def check_right_modify(code1, code2, api, rule, declaration):


    line = dict()
    line['api'] = api
    line['declaration'] = declaration
    line['rule'] = rule
    line['code1'] = code1
    line['code2'] = code2
    flag_add, msg_add, loc_rule_add, rule_list_add, target_str_list2_add, out_dict_debug_add, far_info_add = parse_wrong_diff.auto_check2_add(code1, code2, api, declaration, rule)
    flag_delete, msg_delete, loc_rule_delete, rule_list_delete, target_str_list2_delete, out_dict_debug_delete, far_info_delete = parse_wrong_diff.auto_check2_delete(code1, code2, api, declaration, rule)
    
    if not flag_delete:
        line['diff_re'] = flag_add
        line['rule_list'] = rule_list_add
        line['rule_loc'] = loc_rule_add
        line['diff_info'] = target_str_list2_add
        line['re_msg'] = msg_add
        line['info_dict'] = out_dict_debug_add
    else:
        line['diff_re'] = flag_delete
        line['rule_list'] = rule_list_delete
        line['rule_loc'] = loc_rule_delete
        line['diff_info'] = target_str_list2_delete
        line['re_msg'] = msg_delete
        line['info_dict'] = out_dict_debug_delete
    if flag_delete or flag_add:
        return True, ''
    if msg_add == 'TooFar' or msg_delete == 'TooFar':
        if far_info_add != '':
            return_far = far_info_add
        else:
            return_far = far_info_delete

        return False, return_far

    else:

        return False, ''
    # return True

# TODO later
def get_fix_method():
    return 'add'

# def get_more_descrip(rule, api, right_code, decla, question):
#     out_list = list()
#     session_list = list()
#     # get prompt:
#     prompt = question.replace('FUNC_NAME', api)
#     prompt = prompt.replace('RULE_REPLACE', rule)
#     prompt = prompt.replace('DECLARATION_REPLACE', decla)
#     prompt = prompt.replace('RIGHT_CODE_REPLACE', right_code)
#     # query gpt:1
#     response, token = query1_gpt(prompt, [], 0.3, True)
#     # parse result:TODO debug
#     out_list = parse_desc(response)
#     # gen session_list:
#     session_list.append({"role": "user", "content": prompt})
#     session_list.append({"role": "assistant", "content": response})
#     # return:
#     return out_list, session_list, token

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

def filter_by_rule(rule, declare):
    para_dict_list, parse_flag = parse_wrong_diff.get_parameter_list(declare)
    if parse_flag == 1:
        return False
    else:
        rule_key = get_related_index(rule)
        if len(rule_key) == 0:
            return False
        else:
            rule_key = rule_key[0]
            if len(para_dict_list) < rule_key:
                return False
            match_list = list()
            i = 0
            for para in para_dict_list:
                i += 1
                name = para['name']
                if rule.find('`' + name + '`') != -1:
                    match_list.append(i)
            if rule_key not in match_list and len(match_list) != 0:
                return True
    return False

# TODO 718
def generate_wrong_code(api, lib, rule_list, question_dict, out_log_prefix, out_code_prefix, right_code, declaration, compile_cmd, compile_valgrind_cmd, rule_out, func_json):
    right_rules = list()
    status = ''
    faild_list = list()
    fix_times = 0
    token = 0
    token_before_all = 0
    token_before_one = 0
    token_limit_one = 10000
    token_limit_all = 50000
    fc_list = []
    # TODO later
    rule_list= parse_rule_list(rule_list)
    i = 0

    for rule_dict in rule_list:
        rule = rule_dict['rule']
        violation_code = rule_dict['code']

        i += 1
        if api == 'RSA_private_decrypt' and (3 not in get_related_index(rule)):
            continue

        out_log = out_log_prefix + str(i)
        out_code = out_code_prefix + str(i) + '.c'
        wrong_output = out_code_prefix + str(i) + '-output'

        if code.find('rm -r') != -1 or code.find('/etc/passwd') != -1:
            
            with open(out_log, 'a') as f:
                out_content = 'rm -rf skip\n' 
                f.write(out_content)
            continue
        if filter_by_rule(rule, declaration):
            with open(out_log, 'a') as f:
                out_content = 'wrong rule, inconsistent with parametere\nRule: \n' 
                out_content += rule
                out_content += 'declaration: \n' + declaration + '\n'
                f.write(out_content)
            continue
        # if not filter_by_modal(rule):
        #     with open(out_log, 'a') as f:
        #         out_content = 'not modal skip\n' 
        #         f.write(out_content)
        #     continue
        # generate wrong prompt
        # TODO check 718
        wrong_prompt = generate_wrongcode_prompt(api, rule, violation_code, right_code, declaration, question_dict['wrong'], lib)
        # query gpt:
        response, token = query_gpt(wrong_prompt, [], wrong_temperature, True)
        token_before_all += token
        prev_msg = list()
        prev_msg.append({"role": "user", "content": wrong_prompt})
        prev_msg.append({"role": "assistant", "content": response})
        # parse wrong result and get the modified code
        # TODO check 718
        wrong_code, env_info = parse_right_code(response, lib)
        if wrong_code.find('rm -r') != -1 or wrong_code.find('/etc/passwd') != -1:
            
            with open(out_log, 'a') as f:
                out_content = 'rm -rf skip\n' 
                f.write(out_content)
            continue
        with open(out_log, 'a') as f:
                out_content = 'Question: \n' + wrong_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + wrong_code + '\n' 
                f.write(out_content)
        valid_return_flag, invalid_value = parse_wrong_diff.if_valid_return(wrong_code)
        
        if wrong_code == '' or wrong_code.find('main') == -1:
            with open(out_log, 'a') as f:
                
                out_content = 'Question: \n' + wrong_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + wrong_code + '\nWrong parse  Break!\n' 
                f.write(out_content)
                output = 'Please output the complete code that can be compiled and run automatically, not the code snippet.'
                # rule_list.append(rule_dict)
                # continue
                fix_flag = True
        elif not valid_return_flag:
            with open(out_log, 'a') as f:
                
                out_content = 'Question: \n' + wrong_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + wrong_code + '\nWrong return value  Break!\n' 
                f.write(out_content)
                output = 'Make sure that the return value in the code you give will only be 123 or 0 (123 in case of error, 0 in case of correct). I notice there is `return ' + str(invalid_value) + '` in the code, please change the value to 123 or 0.'
                # rule_list.append(rule_dict)
                # continue
            fix_flag = True
        
        else:
            # faild_list.append(rule)
            # continue
        # TODO later:
            fix_flag = False
            add_flag = parse_wrong_diff.if_add_definition(wrong_code, api)
            check_flag, far_flag = check_right_modify(right_code, wrong_code, api, rule, declaration)
            if check_flag and not add_flag:
                # run the code and see result
                flag, output, error_stage = compile_run(wrong_code, api, compile_cmd, compile_valgrind_cmd, lib)
                if output.find('you do not exist in the passwd database') != -1:
                    exit(1)
                with open(out_log, 'a') as f:
                    # 
                    out_content = '\n Run result: \n' + str(flag) + '\n' + output + '\n' + error_stage + '\n' 
                    f.write(out_content)
                # TODO check
                re, debug = judge_rule_wrong_code(flag, error_stage, wrong_code, output, api, fc_list, compile_valgrind_cmd)
                with open(out_log, 'a') as f:
                    # 
                    out_content = 'judge rule re: ' + re + '\ndebug code: \n' + debug + '\n'
                    f.write(out_content)
                # exit(1)
                if re == 'right-rule':
                    right_rules.append(rule)
                    fix_flag = False
                    with open(rule_out, 'a') as f:
                        tmp_dict = dict()
                        tmp_dict['rule'] = rule
                        tmp_dict['index'] = str(i)
                        f.write(json.dumps(tmp_dict))
                        f.write('\n')
                    with open(out_code, 'w') as f:
                        f.write(wrong_code)
                    with open(wrong_output, 'w') as f:
                        f.write(output)
                    # TODO write log
                    # with open(out_log, 'a') as f:

                    #     f.write(out_content)
                    continue
                elif re == 'wrong-rule':
                    fix_flag = False
                    # TODO write log

                    continue
                else:
                    fix_flag = True

            else:
                if add_flag:
                    output = "Don't add definition of " + api + '! ' + api + ' is an API of library.'
                elif far_flag != '':
                    output = '''You need to modify the code to violate the rule related to the API FUNC_NAME. So, you need to modify/add/delete code closed to this API. Now Your modification is too far.\n'''.replace('FUNC_NAME', api)
                    output = 'Hint: Your modification might be right, but the location is wrong, I want your modification happens after this code: ' + far_flag + '\n'
                    output += 'Please be careful not to make this mistake, and you need to modify the right code in the first session to violate this rule: \n' + rule + '\n'
                    output += 'Violate the rule follow this Violation Example: \n```\n' + violation_code + '\n```'
                else:
                    output = '''Your modification does not meet my requirements. Please check the rule and your violation code in following steps: 
    1. Please analyze the rules carefully, you may modify parameters that are not described by the rules, which is a wrong modify.
    2. Please analyze the rules carefully, and check if the location of your modification relative to the target API is not consistent with the rules(before the API or after the API), which is a wrong modify.\n'''
                    output += 'Please be careful not to make any of these mistakes, and you need to modify the right code in the first session to violate this rule: \n' + rule + '\n'
                    output += 'Violate the rule ffollow this Violation Example: \n```\n' + violation_code + '\n```'
                with open(out_log, 'a') as f:
                    # 
                    out_content = '\n Run result: \n' + output + '\n'
                    f.write(out_content)
                with open(out_log, 'a') as f:
                    out_content = 'Wrong Modify! ' + '\n'
                    f.write(out_content)
                fix_flag = True
        # fix:
        fix_times = 1
        fix_limit = 5
        while fix_flag:
            if fix_times > fix_limit:
                break
            fix_times += 1
            with open(out_log, 'a') as f:
                    out_content = 'Fix: \n'
                    f.write(out_content)
            # TODO later
            fix_method = get_fix_method()
            if fix_method == 'add':
                # prev_stage = error_stage
                # prev_errmsg = errors
                token_before_one += token
            else:
                # prev_stage = error_stage
                token_before_one = token
                # prev_errmsg = errors
                prev_msg = list()
                prev_msg.append(wrong_prompt)
            
            
            wrong_code, token, prev_msg = auto_fix_once(output, wrong_code, lib, compile_cmd, fix_method, prev_msg, rule_dict)
            
            if wrong_code.find('rm -r') != -1 or wrong_code.find('/etc/passwd') != -1:
            
                with open(out_log, 'a') as f:
                    out_content = 'rm -rf skip\n' 
                    f.write(out_content)
                fix_flag = True
                break
            
            q = prev_msg[-2]['content']
            a = prev_msg[-1]['content']
            # fix_times += 1
            token_before_all += token
            with open(out_log, 'a') as f:
                
                out_content = 'Question: \n' + q + '\nAnswer: \n' + a + '\n parse code: \n' + wrong_code + '\n' 
                f.write(out_content)
            add_flag = parse_wrong_diff.if_add_definition(wrong_code, api)
            check_flag, far_flag = check_right_modify(right_code, wrong_code, api, rule, declaration)
            valid_return_flag, invalid_value = parse_wrong_diff.if_valid_return(wrong_code)
        
            if wrong_code == '' or wrong_code.find('main') == -1:
                with open(out_log, 'a') as f:
                    
                    out_content = 'Question: \n' + wrong_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + wrong_code + '\nWrong parse  Break!\n' 
                    f.write(out_content)
                    output = 'Please output the complete code that can be compiled and run automatically, not the code snippet.'
                    # rule_list.append(rule_dict)
                    # continue
                    fix_flag = True
            elif not valid_return_flag:
                with open(out_log, 'a') as f:
                    
                    out_content = 'Question: \n' + wrong_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + wrong_code + '\nWrong return value  Break!\n' 
                    f.write(out_content)
                    output = 'Make sure that the return value in the code you give will only be 123 or 0 (123 in case of error, 0 in case of correct). I notice there is `return ' + str(invalid_value) + '` in the code, please change the value to 123 or 0.'
                    # rule_list.append(rule_dict)
                    # continue
                fix_flag = True
            
            elif check_flag and not add_flag:
                # run the code and see result
                flag, output, error_stage = compile_run(wrong_code, api, compile_cmd, compile_valgrind_cmd, lib)
                with open(out_log, 'a') as f:
                    out_content = '\n Run result: \n' + str(flag) + '\n' + output + '\n' + error_stage + '\n' 
                    f.write(out_content)
                # TODO 718
                re, debug = judge_rule_wrong_code(flag, error_stage, wrong_code, output, api, fc_list, compile_valgrind_cmd)
                with open(out_log, 'a') as f:
                # 
                    out_content = 'judge rule re: ' + re + '\ndebug code: \n' + debug + '\nfix_flag' + str(fix_flag)
                    f.write(out_content)
                if re == 'right-rule':
                    # TODO write log
                    fix_flag = False
                    break
                elif re == 'wrong-rule':
                    # TODO write log
                    fix_flag = True
                    break
                else:
                    fix_flag = True
                with open(out_log, 'a') as f:
                    out_content = 'judge rule re: ' + re + '\n'
                    f.write(out_content)
            else:
                if add_flag:
                    output = "Don't add definition of " + api + '! ' + api + ' is an API of library.'
                elif far_flag != '':
                    output = '''You need to modify the code to violate the rule related to the API FUNC_NAME. So, you need to modify/add/delete code closed to this API. Now Your modification is too far.\n'''.replace('FUNC_NAME', api)
                    output = 'Hint: Your modification might be right, but the location is wrong, I want your modification happens after this code: ' + far_flag + '\n'
                    output += 'Please be careful not to make this mistakes, and you need to modify the right code in the first session to violate this rule: \n' + rule + '\n'
                    output += 'Violate the rule follow this Violation Example: \n```\n' + violation_code + '\n```'
                else:
                    output = '''Your modification does not meet my requirements. Please check the rule and your violation code in following steps: 
1. Please analyze the rules carefully, you may modify parameters that are not described by the rules, which is a wrong modify.
2. Please analyze the rules carefully, and check if the location of your modification relative to the target API is not consistent with the rules(before the API or after the API), which is a wrong modify.\n'''
                    output += 'Please be careful not to make any of these mistakes, and you need to modify the right code in the first session to violate this rule: \n' + rule + '\n'
                    output += 'Violate the rule follow this Violation Example: \n```\n' + violation_code + '\n```'
                with open(out_log, 'a') as f:
                # 
                    out_content = '\n Run result: \n' + output + '\n'
                    f.write(out_content)
                
                with open(out_log, 'a') as f:
                    out_content = 'Wrong Modify! ' + '\n'
                    f.write(out_content)
                fix_flag = True
            if token_before_all > token_limit_all or token> token_limit_one:
                # TODO write log
                with open(out_log, 'a') as f:
                    out_content = 'Break right. token_right: ' + str(token_before_all) + '. Token_one: ' + str(token_before_one) + '\n'
                    f.write(out_content)
                break
        if not fix_flag:
            with open(out_code, 'w') as f:
                f.write(wrong_code)
            with open(wrong_output, 'w') as f:
                    f.write(output)
            right_rules.append(rule)
            with open(rule_out, 'a') as f:
                tmp_dict = dict()
                tmp_dict['rule'] = rule
                tmp_dict['index'] = str(i)
                f.write(json.dumps(tmp_dict))
                f.write('\n')
        else:
            faild_list.append(rule)
    return faild_list, right_rules, fix_times, token_before_all

def generate_right_code(api, lib, question_dict, out_log, code):
    right_code = ''
    flag = ''
    compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
    compile_valgrind_cmd = compile_cmd_valgrind.replace('FUNC_NAME', api) + compile_dict[lib]
    token_limit_one = 10000
    token_limit_all = 50000
    error_handling_code = ''
    
    error_stage = ''
    # generate right code prompt
    right_prompt = generate_rightcode_prompt(api, lib, code, question_dict['right'])
    # query gpt
    response, token = query_gpt(right_prompt, [], right_temperature, True)
    # parse gpt result
    right_code, env_info = parse_right_code(response, lib)
    # test if this code right: right, error-handling right, run-time wrong(can't exec target API/target API wrong), compile wrong 
    # TODO test
    add_flag = parse_wrong_diff.if_add_definition(right_code, api)
    if add_flag:
        output = "Don't add definition of " + api + '! ' + api + ' is an API of library.'
        flag = False
        with open(out_log, 'w') as f:
            out_content = 'Question: \n' + right_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + right_code + '\n Run result: \n' + str(flag) + '\n' + output + '\n'

            f.write(out_content)
    else:

        flag, output, error_stage = compile_run(right_code, api, compile_cmd, compile_valgrind_cmd, lib)
        if error_stage =='error-handling':
            error_handling_code = right_code
        with open(out_log, 'w') as f:
            out_content = 'Question: \n' + right_prompt + '\nAnswer: \n' + response + '\n parse code: \n' + right_code + '\n Run result: \n' + str(flag) + '\n' + output + '\n' + error_stage + '\n' 

            f.write(out_content)
    prev_msg = list()
    prev_msg.append({"role": "user", "content": right_prompt})
    prev_msg.append({"role": "assistant", "content": response})
    prev_errmsg = identify_error.get_error_code(right_code, output, api, api + '.c')
    fix_method = 'add'
    prev_stage = error_stage
    token_before_all = token
    token_before_one = token
    prev_code = right_code
    token_fix = 0
    fix_times = 0
    repeat_times = 0
    fix_limit = 10
    
    
    # if not right, fix + compile_run
    while not flag:
        if fix_times > fix_limit:
            with open(out_log, 'a') as f:
                out_content = 'Break right. times over 10\n'
                f.write(out_content)
                break
        fix_method = 'add'
        # 判断上一个错误是否还未解决，如果是，则继续session，如果不是同一个错误，重新开始一个session
        errors = identify_error.get_error_code(right_code, output, api, api + '.c')
        if len(errors) != 0 and len(prev_errmsg)!= 0:
            if if_same_list(errors, prev_errmsg):
                # token_before_one += token_fix
                fix_method = 'add'
                
            else:
                # prev_errmsg = errors
                # token_before_one = token
                fix_method = 'new'
                # prev_msg = list()
                # prev_msg.append(right_prompt)

        prev_errmsg = errors
        if error_stage != prev_stage:
            # prev_stage = error_stage
            # token_before_one = token
            fix_method = 'new'
            # prev_msg = list()
            # prev_msg.append(right_prompt)
        # else:
        #     # token_before_one += token_fix
        #     fix_method = 'add'
        if repeat_times >= 3:
            fix_method = 'new'    
        if fix_method == 'add':
            prev_stage = error_stage
            prev_errmsg = errors
            token_before_one += token_fix
        else:
            prev_stage = error_stage
            token_before_one = token
            prev_errmsg = errors
            prev_msg = list()
            prev_msg.append(right_prompt)
        # 判断好fix策略后进行fix，这里只fix一次，且fix内不会运行检查
        # TODO test
        right_code, token_fix, prev_msg = auto_fix_once(output, right_code, lib, compile_cmd, fix_method, prev_msg, None)
        fix_times += 1
        token_before_all += token_fix
        if right_code == '':
            with open(out_log, 'a') as f:
                out_content = 'Break cant parse code. token_right: ' + str(token_before_all) + '. Token_one: ' + str(token_before_one) + '\nAnswer: \n' + prev_msg[-1]['content']
                f.write(out_content)
            break
        if right_code == prev_code:
            repeat_times += 1
        else:
            prev_code = right_code
            repeat_times = 0
        add_flag = parse_wrong_diff.if_add_definition(right_code, api)
        if add_flag:
            output = "Don't add definition of " + api + '! ' + api + ' is an API of library.'
            with open(out_log, 'a') as f:
                tmp_a = prev_msg[-2]['content']
                tmp_q = prev_msg[-1]['content']
                out_content = 'Question: \n' + tmp_a + '\nAnswer: \n' + tmp_q + '\n parse code: \n' + right_code + '\n Run result: \n' + str(flag) + '\n' + output + '\n' + error_stage + '\n' 
                out_content += 'token_right: ' + str(token_before_all) + '. Token_one: ' + str(token_before_one) + '\n'
                f.write(out_content)
            flag = False
        # 运行检查
        # TODO test
        else:
            flag, output, error_stage = compile_run(right_code, api, compile_cmd, compile_valgrind_cmd, lib)
            if error_stage =='error-handling':
                error_handling_code = right_code
            with open(out_log, 'a') as f:
                tmp_a = prev_msg[-2]['content']
                tmp_q = prev_msg[-1]['content']
                out_content = 'Question: \n' + tmp_a + '\nAnswer: \n' + tmp_q + '\n parse code: \n' + right_code + '\n Run result: \n' + str(flag) + '\n' + output + '\n' + error_stage + '\n' 
                out_content += 'token_right: ' + str(token_before_all) + '. Token_one: ' + str(token_before_one) + '\n'
                f.write(out_content)
        # 退出循环条件：到达最大token或者 成功
        if flag or token_before_one > token_limit_one or token_before_all > token_limit_all:
            if not flag:
                with open(out_log, 'a') as f:
                    out_content = 'Break right. token_right: ' + str(token_before_all) + '. Token_one: ' + str(token_before_one) + '\n'
                    f.write(out_content)
            break
    # 进行结果判断
    if error_handling_code != '':
        error_stage = 'error-handling'
        right_code = error_handling_code
    if flag:
        return right_code, compile_cmd, compile_valgrind_cmd, flag, 'right', fix_times, token_before_all
    else:
        if error_stage == 'error-handling':
            return right_code, compile_cmd, compile_valgrind_cmd, True, error_stage, fix_times, token_before_all
        else:
            return right_code, compile_cmd, compile_valgrind_cmd, flag, error_stage, fix_times, token_before_all
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
#     response, token = query_gp9t(prompt, [], 0.1, True)
#     rule_list = parse_rule(response)
#     with open(out_log, 'w') as f:
#         out_content = 'Question: \n' + prompt + '\nAnswer: \n' + response + '\nParsed Rules: \n' + str(rule_list) + '\nNum: \n' + str(len(rule_list))
#         f.write(out_content + '\n')

#     return rule_list, token
# TODO:

def get_related_index(rule):
    prefix = 'Parameter'
    begin = rule.find(prefix)
    out_list = list()
    end = rule.find(':')
    nums_str = rule[begin + len(prefix) : end]

    num_list = nums_str.split(',')
    for num_str in num_list:
        try:
            num = int(num_str)
            out_list.append(num)
        except:
            continue
    return out_list



def auto_gen(api, lib, func_path, declaration, question_dict, out_dir, all_log, func_json_list):
    print('Parse API: ' + api)
    global one_query
    global token_num
    # if api == 'DH_get_nid':
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

    # filter_out = out_dir + 'filter_log'
    # split_out = out_dir + 'split_log'

    # question_rule = question_dict['rule']
    # question_right = question_dict['right']
    # question_wrong = question_dict['wrong']

    
    with open(func_code_out, 'w') as f:
        f.write(func_code)
    
    if auto_flag != 'rule' and auto_flag != 'all' and auto_flag != 'first2':
        # TODO
        if func_path not in info_dict.keys():

            return False
        rule_list = info_dict[func_path]['Orig_Rule']
        token_num = info_dict[func_path]['All_Token']
        one_query = info_dict[func_path]['All_Query_Times']
        all_out_dict['Orig_Rule'] = rule_list
        all_out_dict['Orig_Rule_Num'] = len(rule_list)
        all_out_dict['Rule_Dict'] = info_dict[func_path]['Rule_Dict']
        all_out_dict['Rule_Token'] = info_dict[func_path]['Rule_Token']
        if len(rule_list) == 0:
            all_out_dict['Errmsg'] = 'Success-norule'
            all_out_dict['Right_Code_Success'] = True
            all_out_dict['All_Token'] = info_dict[func_path]['All_Token']
            all_out_dict['All_Query_Times'] = info_dict[func_path]['All_Query_Times']
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return True
    # else:
    # # 1.generate rule-generate question:
    #     prompt = generate_rule_prompt(api, func_code, question_rule)
    #     answer, token_rule = query_g8pt(prompt, [], 0.3, True)
    #     # 1.generate rule-parse rule:
    #     rule_list = parse_rule(answer)
    #     log_content = 'Question: \n' + prompt + '\n\nAnswer: \n' + answer + '\n\nRules: \n' + str(rule_list)
    #     with open(rule_out, 'w') as f:
    #         f.write(log_content)
    #     all_out_dict['Orig_Rule'] = rule_list
    #     all_out_dict['Orig_Rule_Num'] = len(rule_list)
    #     all_out_dict['Rule_Token'] = token_rule
    #     if len(rule_list) == 0:
    #         all_out_dict['Errmsg'] = 'Success'
    #         all_out_dict['All_Token'] = token_num
    #         all_out_dict['All_Query_Times'] = one_query
    #         with open(all_log, 'a') as f:
    #             f.write(json.dumps(all_out_dict))
    #             f.write('\n')
    #         return True
    #     if auto_flag == 'rule':
    #         all_out_dict['Errmsg'] = 'Success'
    #         all_out_dict['All_Token'] = token_num
    #         all_out_dict['All_Query_Times'] = one_query
    #         with open(all_log, 'a') as f:
    #             f.write(json.dumps(all_out_dict))
    #             f.write('\n')
    #         return True
    if auto_flag == 'wrong':
        # TODO
        all_out_dict = info_dict[func_path]
        # todebug
        
        rule_list = info_dict[func_path]['Rule_Dict']
        # all_out_dict['Before_Rule'] = rule_list
        # all_out_dict['Before_Rule_Num'] = len(rule_list)
        all_out_dict['Rule_Token'] = info_dict[func_path]['Rule_Token']
        if len(rule_list) == 0:
            all_out_dict['Errmsg'] = 'Success'
            all_out_dict['All_Token'] = info_dict[func_path]['All_Token']
            all_out_dict['All_Query_Times'] = info_dict[func_path]['All_Query_Times']
            with open(all_log, 'a') as f:
                f.write(json.dumps(all_out_dict))
                f.write('\n')
            return True

        right_code = info_dict[func_path]['Right_Code']
        all_out_dict['Right_Code'] = right_code
        all_out_dict['Right_Fix_Times'] = info_dict[func_path]['Right_Fix_Times']
        all_out_dict['Right_Code_Success'] = info_dict[func_path]['Right_Code_Success']
        all_out_dict['Right_Code_Token'] = info_dict[func_path]['Right_Code_Token']
        all_out_dict['Right_Code_Env'] = info_dict[func_path]['Right_Code_Env']
        all_out_dict['Errmsg'] = info_dict[func_path]['Errmsg']
        all_out_dict['All_Query_Times'] = one_query
        all_out_dict['All_Token'] = token_num
        # all_out_dict['Compile_CMD'] = info_dict[func_path]['Compile_CMD']
        compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
        compile_valgrind_cmd = compile_cmd_valgrind.replace('FUNC_NAME', api) + compile_dict[lib]

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
        # exit(1)
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
        
    # 3.generate wrong code:
    
    api_func_json = get_value_from_json(func_json_list, 'pcap_compile', 'func')
    faild_list, right_rules, fix_times, token_wrong = generate_wrong_code(api, lib, rule_list, question_dict,wrong_code_out_prefix, wrong_code_c_prefix, right_code, declaration, compile_cmd, compile_valgrind_cmd, final_rule_out, api_func_json)
    # exit(1)
    all_out_dict['Wrong_Code_Success_Num'] += 1
    all_out_dict['Wrong_Fix_Times'] += fix_times
    all_out_dict['Wrong_Code_Token'] = token_wrong
    all_out_dict['Wrong_Code_Faild_Num'] = len(faild_list)
    all_out_dict['Wrong_Code_Faild_List']= faild_list
    all_out_dict['Wrong_Fix_Times'] += fix_times
    # all_out_dict['Wrong_Code_Token'] = token_wrong
    
    all_out_dict['Final_Error_Rule'] = right_rules
    all_out_dict['Final_Handle_Rule'] = []
    all_out_dict['Final_Rule_Num'] = len(right_rules)
    all_out_dict['All_Token'] = token_wrong + all_out_dict['Right_Code_Token'] + all_out_dict['Rule_Token']
    if all_out_dict['Wrong_Code_Faild_Num'] < all_out_dict['Orig_Rule_Num']:
        all_out_dict['Errmsg'] = 'Success'
    else:
        all_out_dict['Errmsg'] = 'Wrong Code Error'
    all_out_dict['All_Query_Times'] = one_query
    with open(all_log, 'a') as f:
        f.write(json.dumps(all_out_dict))
        f.write('\n')

def read_API(path):
    out_list = list()
    content = ''
    with open(path, 'r') as f:
        content = f.read()
    out_list = content.strip('\n').split('\n')
    return out_list

def if_skip(path, out_dir):

    out_dir = out_dir.strip('/').split('/')[-1]

    if not os.path.exists(path):
        return False
    res_list = read_json(path)
    dir_list = list()
    for item in res_list:
        dir = item['Output'].strip('/').split('/')[-1]

        dir_list.append(dir)

    if out_dir in dir_list:
        return True
    else:
        return False


if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print('please input target operation: right, wrong')
        exit(1)
    auto_flag = sys.argv[1]
    right_temperature = 1
    wrong_temperature = 0
    if auto_flag == 'wrong':
        fix_temperature = wrong_temperature
    else:
        fix_temperature = right_temperature
    question_dir = '../prompt/'
    # CHANGE
    orig_key = ''
    api_key = ''
    root_passwd = ''
    api_path = '../test_info/api_info/api_list'
    callgraph_path = '../test_info/api_info/call_graph'
    
    info_dir = '../test_info/out_right_code/'
    out_dir = '../test_info/out_wrong_code/'
    # END
    
    info_log = info_dir + '/auto_rule_info'
    all_log = out_dir + '/auto_rule_info'
    gpt_answer_dir = out_dir + 'gpt_re/'
    in_info_list = list()
    info_dict = dict()
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    if not os.path.exists(gpt_answer_dir):
        os.mkdir(gpt_answer_dir)

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
    
    # api_path = home_dir + '/data/CheckFunction/' + lib + '_API'
    # callgraph_path = callgraph_dir + '0call_graph.json'
    
    # filter_question_prefix = question_dir + 'filter_rule'
    # split_question_prefix = question_dir + 'split_rules'
    rule_question_prefix = question_dir + 'rule'
    right_question_prefix = question_dir + 'RightCode'
    wrong_question_prefix = question_dir + 'ViolationCode'
    # modified_desc_question_prefix = ''

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
    # with open(filter_question_prefix, 'r') as f:
    #     question_dict['filter'] = f.read()
    # with open(split_question_prefix, 'r') as f:
    #     question_dict['split'] = f.read()
    with open(right_question_prefix, 'r') as f:
        question_dict['right'] = f.read()
    with open(wrong_question_prefix, 'r') as f:
        question_dict['wrong'] = f.read()

    
    api_num = 0
    for api in api_list:
        file_name = 'example.db'
        if os.path.exists(file_name):
            os.remove(file_name)
        os.system('cp ../example_data/example.db .')
        api_num += 1
        one_query = 0 
        token_num = 0
        token_all_big += token_num
        # get callgraph:
        if api not in callgraph_index.keys():
            print(api)
            print('Func info not exists!')
            with open(parse_exists_log, 'a') as f:
                f.write(api + '\n')
            continue
        else:
            out_dir_api = out_dir + '/' + api
            
            # exit(1)
            callgraph_index[api] = list(set(callgraph_index[api]))
            if len(callgraph_index[api]) == 1:
                out_dir_api += '/'

                if if_skip(all_log, out_dir_api):
                    print(api + ' already parsed')
                    continue

                
                if not os.path.exists(out_dir_api):
                    os.mkdir(out_dir_api)
                # continue
                info = callgraph_list[callgraph_index[api][0]]
                call_order = info['call_graph']
                lib = info['lib']
                func_list = read_json(callgraph_path)
                analyse_num = info['analyse_func_num']
                analyse_num = 1
                path = info['path']
                declaration = info['declaration']
                code = get_code(path)
                if analyse_num == 1:
                    # TODO:question_dict
                    auto_gen(api, lib, path, declaration, question_dict, out_dir_api, all_log, func_list)
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
                        print(api + ' already parsed')
                        continue
                    
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
                        auto_gen(api, lib, path, declaration, question_dict, out_dir1, all_log, func_list)
                    else:
                        # some fc in this api, need to analyse other func 
                        # TODO
                        prompt = generate_rule_prompt()
                        parse_rule(prompt)

        file1 = './' + api + '.c'
        file2 = './' + api
        os.system('rm ' + file1)
        os.system('rm ' + file2)

    print('ALL token:')
    print(token_all_big)
    rm_env()
