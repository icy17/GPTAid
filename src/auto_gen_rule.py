import json
import os
import sys
import openai
import time
import subprocess
import parse_wrong_diff
import tiktoken
import re

gpt_token_small_limit = 4000
gpt_token_large_limit = 16000
rule_temperature = 0


compile_cmd_prefix = 'gcc -g -pedantic -fsanitize=address -fsanitize=undefined -o FUNC_NAME FUNC_NAME.c '
# CHANGE
compile_dict = {"sqlite3": "-lsqlite3", "openssl": '-lssl -lcrypto', "libpcap": "-lpcap", "libxml2": "-lxml2"}
# END
include_dict = {"sqlite3": "#include <sqlite3.h>", "libpcap": "#include <pcap.h>", "libxml2": '''#include <libxml/xmlreader.h>
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
'''}


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
# e.g. get_value_from_json(list, 'pcap_freecode', 'func') will get json of pcap_freecode
def get_value_from_json(json_list, key_value, key_match):
    for item in json_list:
        key = item[key_match]
        if key == key_value:
            return item
    return None

def num_tokens_from_messages(messages, model="gpt-4o-mini"):
    """Return the number of tokens used by a list of messages."""
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

# def get_rule(api, rule_list):
#     rule_json = get_value_from_json(rule_list, api, 'func')
#     return rule_json

def generate_rule_small_prompt(func, func_code, question, standard_rule_dict: dict, other_rule_dict: dict, para_index, para_name, if_ret):
    num_Al = chr(ord('A') - 1)
    prefix = question.replace('FUNC_NAME', func)
    # prompt = prefix + '\n\n'
    # prefix = question.replace('FUNC_NAME', func)
    
    prompt = prefix.replace('SOURCE_CODE', func_code)
    prompt = prompt.replace('ADDITIONAL', '')
    if not if_ret:
        prompt = prompt.replace('PARA_NAME', para_name)
        prompt = prompt.replace('Parameter_Info', 'Parameter ' + str(para_index))
    else:
        prompt = prompt.replace('PARA_NAME', para_name)
        prompt = prompt.replace('Parameter_Info', 'return value')
    # prompt = prompt + func_code + '\n```\n'
    return prompt

def generate_rule_prompt(func, func_code, declaration, question, standard_rule_dict: dict, other_rule_dict: dict, para_index, para_name, if_ret):
    num_Al = chr(ord('A') - 1)
    prefix = question.replace('FUNC_NAME', func)
    prompt = prefix.replace('SOURCE_CODE', func_code)
    if not if_ret:
        prompt = prompt.replace('PARA_NAME', para_name)
        prompt = prompt.replace('Parameter_Info', 'Parameter ' + str(para_index))
    else:
        prompt = prompt.replace('PARA_NAME', para_name)
        prompt = prompt.replace('Parameter_Info', 'return value')
    if len(other_rule_dict.keys()) != 0:
        add_info = 'Additional Info: \n'
        
        for key in other_rule_dict.keys():
            num_Al = chr(ord(num_Al) + 1)
            add_info = add_info + '\tRules of function `' + key + '`: \n'
            i = 0
            for rule in other_rule_dict[key]:
                add_info = add_info + '\t' + str(i) + '. ' + rule + '\n'
                i += 1
        prompt = prompt.replace('ADDITIONAL', add_info)
    else:
        prompt = prompt.replace('ADDITIONAL', '')
    # prompt = prefix + '\n\n'
    # prompt = prefix + '\n`' + func + '` source code: \n```\n'
    # prompt = prompt + func_code + '\n```\n'
    # prompt = prompt + 'Input additional info:\n```\n'
    # for key in standard_rule_dict.keys():
    #     # if len(standard_rule_dict[key]) == 0:
    #     #     continue
    #     num_Al = chr(ord(num_Al) + 1)
    #     prompt = prompt + num_Al + '. rules of standard API `' + key + '`: \n'
    #     i = 0
    #     for rule in standard_rule_dict[key]:
    #         prompt = prompt + '\t' + str(i) + '. ' + rule + '\n'
    #         i += 1
    
    # prompt = prompt + '```'
    return prompt
  

def parse_rule(response):
    rule_list = list()
    code_list = list()
    out_dict_list = list()
    response = response.replace('Task 3', 'Task3')
    begin = response.find('Task3')
    if begin == -1:
        begin = response.lower().find('security rule')
        if begin == -1:
            begin = 0
    search_space = response[begin:]
    search_list = search_space.split('\n')
    begin_flag = False
    section_list = list()
    tmp_content = ''
    max_no = 1
    for line in search_list:
        line = line.strip().strip(':')
        strs = list(line)
        if len(strs) == 0:
            continue
        if strs[0].isdigit():
            this_no = int(strs[0])
            if this_no < max_no:
                break
            else:
                max_no = this_no
            if begin_flag == True:
                section_list.append(tmp_content)
                rule_begin = line.find('.')
                rule = line[rule_begin + 1:].strip()
                rule_begin = rule.find('Rule:')
                if rule_begin <= 1 and rule_begin != -1:
                    rule = rule[rule_begin + len('Rule:'):].strip()
                tmp_content = rule + '\n'
            else:
                begin_flag = True
                rule_begin = line.find('.')
                rule = line[rule_begin + 1:].strip()
                rule_begin = rule.find('Rule:')
                if rule_begin <= 1 and rule_begin != -1:
                    rule = rule[rule_begin + len('Rule:'):].strip()
                # rule_begin = rule.find(':')
                # if rule_begin != -1:
                #     rule = rule[rule_begin:]
                tmp_content = rule + '\n'
        else:
            if begin_flag == True:
                tmp_content += line
                tmp_content += '\n'
            else:
                continue
    section_list.append(tmp_content)

    code_format = ['```code', '```cpp', '```c', '```', '```C++']
    for section in section_list:
        section_lines = section.split('\n')
        remain_word = section_lines[0].strip('\n').strip(':')
        code = ''
        out_dict = dict()
        for format in code_format:
            code_begin = section.find(format)
            if code_begin == -1:
                continue
            else:
                code = section[code_begin + len(format): ]
                break
        if code == '':

            out_dict['rule'] = remain_word
            out_dict['code'] = code
            out_dict_list.append(out_dict)
            continue
        code_end = code.find('```')
        if code_end != -1:
            code = code[:code_end]
            # remain_word = section[:code_begin] + section[code_end + 3:]
            # remain_word = section[:code_begin]
        
        code =  code.strip('\n')
        
        if remain_word == '' and code == '':
            continue
        if remain_word == '' or code == '':
            print(response)
            print(remain_word)
            print(code)
            print('wrong rule code')
            exit(1)
        out_dict['rule'] = remain_word
        out_dict['code'] = code
        out_dict_list.append(out_dict)
    return out_dict_list

def query_gpt(prompt, message_before, temprature_in, big_flag):

    print('waiting for gpt...')
    global one_query
    global gpt_answer_index
    global token_num
    global api_key
    global orig_key
    answer_path = gpt_answer_dir + '/' + str(gpt_answer_index)
    gpt_answer_index += 1

    openai.project_key = orig_key
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

    num = num_tokens_from_messages(message_before, model_select)

    if num > gpt_token_small_limit and model_select == 'gpt-4o-mini':
        
        if big_flag:
            model_select = 'gpt-4o-mini'
        else:
            return '', num
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

                if model_select == "gpt-4o-mini":
                    model_select = 'gpt-4o-mini'

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
                return '', token_limit
        except:
            print("Connection refused by the server..")

            print("Let me sleep for 5 seconds")

            print("ZZzzzz...")

            time.sleep(5)

            print("Was a nice sleep, now let me continue...")

            continue
    

def generate_rightcode_prompt(func, lib, func_code, rule_list, question):
    prompt = question.replace('FUNC_NAME', func).replace('LIB_NAME', lib)
    # prompt = prompt + '\n\n' + 'invocation specification of ' + func + ': \n```\n'
    # for rule in rule_list:
    #     prompt = prompt + rule + '\n'
    # prompt = prompt + '```'
    prompt = prompt + '\n\n' + func + ' function code: \n```\n'
    prompt = prompt + func_code + '\n```\n'
    return prompt

    # return prompt


def generate_wrongcode_prompt(api, rule,right_code, declaration, question):
    prompt = question.replace('FUNC_NAME', api)
    prompt = prompt.replace('``', '`' + rule + '`', 1)
    prompt = prompt + '\nDeclaration: \n```\n' + declaration + '\n```\nCode: \n```\n' + right_code + '\n```'

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
    # lines = code.split('\n')
    # for line in lines:
    #     if line.find('#include') != -1:
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
    main_index = code.find('int main')
    if  main_index == -1:
        return ''
    headers = include_dict[lib]
    code = code[main_index: ]
    out_code = fixed_headers + '\n' + headers + '\n' + code
    return out_code

def parse_right_code(answer, api, lib):
    if answer.find('```') == -1:
        return '', '', ''
    answer = answer.replace('Task 2', 'Task2')
    answer = answer.replace('Task 3', 'Task3')
    answer = answer.replace('Task 4', 'Task4')
    right_code = ''
    compile_cmd = ''
    task_index = answer.find('Task3')
    if task_index == -1:
        task_index = 0
    code_begin_index = answer.find('```c', task_index)
    if code_begin_index == -1:
        code_begin_index = answer.find('```', task_index)
    else:
        code_begin_index += 1
    # if code_begin_index == -1:
    #     return right_code, ''
    
    # if code_begin_index == -1:
    #     return right_code, ''
    code_end_index = answer.find('```', code_begin_index + len('```'))
    right_code = answer[code_begin_index + len('```'): code_end_index].strip('\n')
    right_code = add_headers(right_code, lib)
    compile_cmd = compile_cmd_prefix.replace('FUNC_NAME', api) + compile_dict[lib]
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

    return right_code, compile_cmd, env_info


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
#         answer, token = 1('', prev_msg, 0.3, False)

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
        out, err = return_info.communicate(timeout=15)
    except:
        return False, 'compile', compile_cmd + ' timed out after 15 seconds. Please check the code to make sure it is non-interactive. '
    res_flag = return_info.returncode
    info = out.decode("utf-8","ignore") + '\n' + err.decode("utf-8","ignore")
    # res_flag = return_info[0]
    # info = return_info[1]
    if res_flag != 0:
        # os.system('rm ' + code_path)
        return False, 'compile', info
    run_cmd1 = './' + api
    run_cmd = 'echo %s | sudo -S %s' % ('123456', run_cmd1)
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=15)
    except:
        return False, 'timeout', run_cmd + ' timed out after 15 seconds. Please check the code to make sure it is non-interactive. '
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


def compile_code(api, code, compile_cmd):
    run_flag = True
    errmsg = ''
    # write code to out_file file
    code_path = './' + api + '.c'
    with open(code_path, 'w') as f:
        f.write(code)
    if code.find(api) == -1:
        # os.system('rm ' + code_path)
        return False, 'compile', 'No target API `' + api + '`, please check and regenerate the code.'
    # compile
    # os.putenv('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    return_info = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        out, err = return_info.communicate(timeout=15)
    except:
        # os.system('rm ' + code_path)
        return False, 'compile', compile_cmd + ' timed out after 15 seconds. Please check the code to make sure it is non-interactive. '
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
    run_cmd1 = './' + api
    run_cmd = 'echo %s | sudo -S %s' % ('123456', run_cmd1)
    code_path = './' + api + '.c'
    # return_info = subprocess.getstatusoutput(run_cmd)
    return_info = subprocess.Popen(run_cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if code.find(api) == -1:
        # os.system('rm ' + run_cmd1)
        # os.system('rm ' + code_path)
        return False, -1, 'No target API `' + api + '`, please check and regenerate the code.'
    try:
        out, err = return_info.communicate(timeout=15)
    except:
        # os.system('rm ' + code_path)
        # os.system('rm ' + run_cmd1)
        return False, -1, run_cmd + ' timed out after 15 seconds. Please check the code to make sure it is non-interactive. '
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

# TODO LATER
def extract_compile_error(msg, code):
    # list:
    error_msg = msg
    return error_msg
# TODO LATER
def extract_run_error(msg, code):
    # list:
    error_msg = msg
    return error_msg
# TODO
def generate_fix_continue_prompt(right_prompt, answer_code, error_msg, stage):
    prefix = 'Your Answer Code is: \n```' + answer_code + '\n```\nThe ' + stage + ' result is: \n```' + error_msg + '```\nPlease regenerate the code'
    
    
    prompt = 'Question: \n' + right_prompt + '\n\n' + prefix
    return prompt
    
# TODO
def generate_fix_new_prompt(prev_msg:list, question, error_msg):
    prompt = ''
    return prompt
    
    
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
#         answer, token = qu1ery_gpt(prompt_new, prompt_list, 0.3, big_flag)

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
#             os.system('cp ./example_data/example.db .')
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



def get_call_order(api, call_graph_list):
    return [api]


def gen_standard_prompt(api, prefix):
    prefix = prefix.replace('FUNC_NAME', api)
    return prefix

# parameter_info: {'type': 'sqlite3_stmt', 'name': 'pStmt'}
def del_rule_list(rule_dict_list, api, parameter_info, para_index):
    out_list = list()
    if parameter_info['type'] == '':
        parameter_info['type'] = '11CANOTBEMATCHED'
    if parameter_info['name'] == '':
        parameter_info['name'] = '11CANOTBEMATCHED'
    for item in rule_dict_list:
        rule = item['rule']
        code = item['code']
        if code.find(api) == -1:
            continue
        else:
            # if rule.find('`') == -1:
            #     out_list.append(item)
            #     continue
            # else:
            #     pattern = re.compile(r'\`(.*?)\`')
            #     result = pattern.findall(rule)
            #     for one in result:
            #         if one.find(parameter_info['type']) != -1 or one.find(parameter_info['name']) != -1:
            out_list.append(item)
    return out_list

def get_para_index(para_name, para_dict_list):
    hit_index = 0
    for para in para_dict_list:
        hit_index += 1
        if para_name == para['name']:
            return hit_index
    return -1


def gen_rule_list(api, code, prefix_first, prefix_repeat, func_info_list, out_log_prefix, out_rule):
    print('Parse ' + api + '...\n')
    parse_order = get_call_order(api, func_info_list)

    
    if len(parse_order) == 0:
        return [], 0, []
    token_all = 0
    for func in parse_order:
        if not os.path.exists(out_rule):
            rule_list_in = list()
        else:
            rule_list_in = read_json(out_rule)
        out_log = out_log_prefix + '-' + func
        standard_rule_dict = dict()
        other_rule_dict = dict()
        if func != api and get_value_from_json(rule_list_in, func, 'func'):
            continue
        # get standard rules:
        func_json = get_value_from_json(func_info_list, func, 'func')

        func_decla = ''
        if 'declaration' not in func_json.keys() and func_json['type'] == 'macro':
            func_decla = code

            
        else:
            func_decla = func_json['declaration']
            
        if parse_wrong_diff.macro_or_func(declaration) == 'macro':

            para_dict_list, parse_flag = parse_wrong_diff.get_pre_para_list(func_decla)
        else:
            para_dict_list, parse_flag = parse_wrong_diff.get_parameter_list(func_decla)
        if parse_flag == 1:
            print(func_decla)
            print('error when parse declaration')
            # exit(1)
        if func_decla == '':
            # exit(1)
            with open(out_log, 'a') as f:
                f.write('No para parse: ' + func_decla + '\n')
        para_dict_list.append({"type": 'ret', "name": ""})
        path = func_json['path']
        code = get_code(path)
        standard_fc = func_json['standard_fc']

        # get other rules:
        other_fc = func_json['other_fc']

        para_index = 1
        rule_list = list()
        para_num = len(para_dict_list)
        for para in para_dict_list:
            if para['type'] == 'ret':
                para_num -= 1
        orig_dict_list = para_dict_list
        append_times = dict()
        for para in para_dict_list:
        # TODO
            
            para_index = get_para_index(para['name'], orig_dict_list)
            if para_index not in append_times.keys():
                append_times[para_index] = 0
            if para['type'] == 'ret' and api == func:
                continue
            para_prefix = 'Parameter ' + str(para_index) + ': '
            if para['type'] != 'ret':
                prompt_first = generate_rule_prompt(func, code, func_decla, prefix_first, standard_rule_dict, other_rule_dict, para_index, para['name'], False)
            else:
                prompt_first = generate_rule_prompt(func, code, func_decla, prefix_first, standard_rule_dict, other_rule_dict, para_index, para['name'], True)
            # exit(1)
            # prompt_repeat = prefix_repeat.replace('FUNC_NAME', func)
            # repeat_limit = 3
            
            i = 0
            q_list = list()
            # first get rules:
            response, token = query_gpt(prompt_first, [], rule_temperature, True)
            if response == '':
                if para['type'] != 'ret':
                    prompt_first = generate_rule_small_prompt(func, code, prefix_first, standard_rule_dict, other_rule_dict, para_index, para['name'], False)
                else:
                    prompt_first = generate_rule_small_prompt(func, code, prefix_first, standard_rule_dict, other_rule_dict, para_index, para['name'], True)
                
                response, token = query_gpt(prompt_first, [], rule_temperature, True)

                if response == '':
                    print('Too many token when parse small, exit!!')
                    print(token)
                    # print(prompt_first)
                    print(token)
                    exit(1)
            with open(out_log, 'a') as f:
                f.write('SAVED_Question: \n' + prompt_first + '\nSAVED_Answer:\n' + response + '\n')
            token_all += token
            rule_dict_list = parse_rule(response)
            with open(out_log, 'a') as f:
                f.write(str(rule_dict_list) + '\n')
            # delete other rule:
            if para['type'] != 'ret':
                rule_dict_list = del_rule_list(rule_dict_list, func, para_dict_list[para_index - 1], para_index)
            if len(rule_dict_list) == 0:
                with open(out_log, 'a') as f:
                    f.write('append this para\n')
                if append_times[para_index] < 3:
                    para_dict_list.append(para)
                    append_times[para_index] += 1
                
            para_index += 1
            if para['type'] != 'ret':
                for item in rule_dict_list:
                    # tmp = item['rule'].lower().replace('parameter ' + str(para_index), 'parameter' + str(para_index))
                    if item['rule'].lower().find('parameter ' + str(para_index - 1)) != 0:
                        item['rule'] = para_prefix + item['rule']
            else:
                for item in rule_dict_list:
                    # tmp = item['rule'].lower().replace('parameter ' + str(para_index), 'parameter' + str(para_index))
                    if item['rule'].lower().find('ret') != 0:
                        item['rule'] = "Return Value: " + item['rule']
            rule_list.extend(rule_dict_list)    
            with open(out_log, 'a') as f:
                f.write('after parse dict:\n')
                f.write(str(rule_dict_list) + '\n')

        with open(out_log, 'a') as f:
            f.write('Final Rules: \n')
            for item in rule_list:
                
                f.write(str(item['rule']) + '\n')
                f.write(item['code'] + '\n')
            f.write(str(len(rule_list)) + '\n')
        if api == func:
            return rule_list, token_all, parse_order
        else:
            rule_list_desc = list()
            for item in rule_list:
                rule_list_desc.append(item['rule'])
            out_dict = dict()
            out_dict['func'] = func
            out_dict['rules'] = rule_list_desc
            with open(out_rule, 'a') as f:
                f.write(json.dumps(out_dict))
                f.write('\n')
    # return [], 0, parse_order

def get_new_list(response):
    begin_index = response.find('Task 4')
    list_begin = response.find('[', begin_index)
    if list_begin == -1:
        return None
    list_end = response.find(']', list_begin)
    list_new = response[list_begin + 1 : list_end].split(',')
    for item in list_new:
        list_new[list_new.index(item)] = item.strip()

    return list_new


# TODO:
def auto_gen(api, lib, func_path, declaration, question_dict, out_dir, all_log):
    global one_query
    global token_num
    # rule_out: rule prompt, output and rule-list
    rule_out = out_dir + '/rule_log'

    func_code_out = out_dir + 'func_code.c'
    # CHANGE
    func_info_path = '../test_info/' + lib + '-funcs/0func_info.json'
    lib_rule = '../test_info/' + lib + '-funcs/0rules'
    # END
    func_info_list = read_json(func_info_path)

    all_out_dict = dict()
    func_code = get_code(func_path)
    all_out_dict['Function'] = api
    all_out_dict['Lib'] = lib
    all_out_dict['LOC'] = len(func_code.split('\n'))
    all_out_dict['code_path'] = func_path
    all_out_dict['Output'] = out_dir
    all_out_dict['Orig_Rule'] = list()
    all_out_dict['Parse_Order'] = list()
    all_out_dict['Orig_Rule_Num'] = 0
    all_out_dict['Rule_Token'] = 0
    all_out_dict['Right_Code'] = ''
    all_out_dict['Compile_CMD'] = ''
    all_out_dict['Right_Fix_Times'] = 0
    all_out_dict['Right_Code_Success'] = False
    all_out_dict['Right_Code_Env'] = ''
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

    
    all_out_dict['All_Query_Times'] = 0


    

    question_rule = question_dict['rule_first']
    # question_rule_more = question_dict['rule_more']
    with open(func_code_out, 'w') as f:
        f.write(func_code)

    rule_list, token_rule, parse_order = gen_rule_list(api, func_code, question_rule, 'notused', func_info_list, rule_out, lib_rule)
    # return True
    rule_list_desc = list()
    for item in rule_list:
        rule_list_desc.append(item['rule'])
    all_out_dict['Orig_Rule'] = rule_list_desc
    all_out_dict['Rule_Dict'] = rule_list
    # rule_list, token_delete = parse_rule_list(rule_list, api, declaration, question_parse)
    # all_out_dict['Orig_Rule'] = rule_list
    all_out_dict['Parse_Order'] = parse_order
    all_out_dict['Orig_Rule_Num'] = len(rule_list)
    all_out_dict['Rule_Token'] = token_rule
    if len(rule_list) == 0:
        all_out_dict['Errmsg'] = 'Success'
        all_out_dict['All_Token'] = token_num
        all_out_dict['All_Query_Times'] = one_query
        with open(all_log, 'a') as f:
            f.write(json.dumps(all_out_dict))
            f.write('\n')
        return True
    if auto_flag == 'rule':
        all_out_dict['Errmsg'] = 'Success'
        all_out_dict['All_Token'] = token_num
        all_out_dict['All_Query_Times'] = one_query
        with open(all_log, 'a') as f:
            f.write(json.dumps(all_out_dict))
            f.write('\n')
        return True
    

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
    
    auto_flag = 'rule'
    question_dir = '../prompt/'
    
    # CHANGE
    orig_key = ''
    api_key = ''
    
    api_path = '../test_info/api_info/api_list'
    callgraph_path = '../test_info/api_info/call_graph'
    
    out_dir = '../test_info/out_gen_rule/'
    # END
    all_log = out_dir + '/auto_rule_info'
    gpt_answer_dir = out_dir + '/gpt_re/'
    in_info_list = list()
    info_dict = dict()
    
    
    parse_exists_log = out_dir + '/exists_log'
    
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    if not os.path.exists(gpt_answer_dir):
        os.mkdir(gpt_answer_dir)
    gpt_answer_index = 0
    
    
    
    rule_question_prefix = question_dir + 'rule'
    right_question_prefix = question_dir + 'RightCode'
    wrong_question_prefix = question_dir + 'ViolationCode'
    # fix_right_question_prefix = question_dir + 'auto_fix_right'
    # fix_wrong_question_prefix = question_dir + 'auto_fix_wrong'
    # rulemore_question_prefix = question_dir + 'generate_rule_more'
    # parse_question_prefix = question_dir + 'parse_rule_list'
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
    # parse_question_prefix
    # with open(parse_question_prefix, 'r') as f:
    #     question_dict['question_parse'] = f.read()
    with open(rule_question_prefix, 'r') as f:
        question_dict['rule_first'] = f.read()
    # with open(rulemore_question_prefix, 'r') as f:
    #     question_dict['rule_more'] = f.read()
    with open(right_question_prefix, 'r') as f:
        question_dict['right'] = f.read()
    with open(wrong_question_prefix, 'r') as f:
        question_dict['wrong'] = f.read()
    # with open(fix_right_question_prefix, 'r') as f:
    #     question_dict['fix_right'] = f.read()
    # with open(fix_wrong_question_prefix, 'r') as f:
    #     question_dict['fix_wrong'] = f.read()
    api_num = 0
    for api in api_list:
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
                        auto_gen(api, lib, path, declaration, question_dict, out_dir1, all_log)
                    else:
                        # some fc in this api, need to analyse other func 
                        # TODO
                        prompt = generate_rule_prompt()
                        parse_rule(prompt)
        # generate rule-generate question:
        # if api_num >= 5:
        #     break
        # exit(1)
        file1 = './' + api + '.c'
        file2 = './' + api
        os.system('rm ' + file1)
        os.system('rm ' + file2)
    print('ALL token:')
    print(token_all_big)
