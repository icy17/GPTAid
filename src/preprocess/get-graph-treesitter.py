from cinspector.interfaces import CCode
from cinspector.analysis import CallGraph
from cinspector.nodes import CompoundStatementNode, DeclarationNode, IfStatementNode, PreprocDefNode, IdentifierNode, BasicNode
import os
import json

def get_all_file_path(in_dir):
    out_list = list()
    for root, dirs, files in os.walk(in_dir):
        for file in files:
            last_str = file.strip('.').split('.')[-1]
            if (last_str[0] != 'c' and last_str[0] != 'h') or last_str == 'conf' or last_str == 'cnf':
                continue
            out_list.append(root + '/' + file)
        # out_list.extend(files)
    return out_list

def get_macro_function(cc, orig_path, log_out_path, macro_out_path_prefix):
    funcs = cc.get_by_type_name('preproc_function_def')
    all_list = list()
    for func in funcs:
        standard_num = 0
        other_num = 0
        indirect_num = 0
        indirect_fc = list()
        standard_fc = list()
        other_fc = list()
        
        func_name = str(func.name)
        func_content = str(func)
        out_dict = dict()
        macro_out_path = macro_out_path_prefix + '-' + func_name
        out_dict['func'] = func_name
        out_dict['orig_path'] = orig_path
        out_dict['path'] = macro_out_path
        func_body = str(func.value).strip('\n')
        # print(func_body)
        # print(type(func))
        cc2 = CCode(func_body)

        calls = cc2.get_by_type_name('call_expression')
        for call in calls:
            call_name = str(call.function)
            # print(call.function)
            # print(call)
            if call.is_indirect():
                # print(call.identifier)
                indirect_num += 1
                indirect_fc.append(str(call_name))
                # continue
            elif call_name in standard_list:
                standard_num += 1
                standard_fc.append(str(call_name))
            else:
                other_num += 1
                other_fc.append(str(call_name))
        out_dict['standard_num'] = standard_num
        out_dict['other_num'] = other_num
        out_dict['standard_fc'] = standard_fc
        out_dict['other_fc'] = other_fc
        out_dict['indirect_fc'] = indirect_fc
        out_dict['indirect_num'] = indirect_num
        out_dict['type'] = 'macro'
        all_list.append(out_dict)
        # if len(calls) != 0:
        #     print(calls)
        #     print(func)
        #     exit(1)
        with open(log_out_path, 'a') as f:
            f.write(json.dumps(out_dict))
            f.write('\n')
        with open(macro_out_path, 'a') as f:
            f.write(func_content)
            f.write('\n')
    return all_list
            

if __name__ == '__main__':
    standard_path = '../../test_info/standard_api'
    # CHANGE:
    project_dir = '../../test_info/libpcap/'
    lib_name = 'libpcap'
    # out_dir should be libname-funcs. e.g., libpcap-funcs
    out_dir = '../../test_info/' + lib_name + '-funcs/'
    # END
    out_path = out_dir + '/0func_info.json'
    macro_out_path = out_dir + '/0macro_info.json'
    macro_dir = out_dir + '/macro-out/'
    # func_name_path = out_dir + '0name_list'
    # parse_path = out_dir + '0func_list'
    standard_list = list()
    with open(standard_path, 'r') as f:
        tmp = f.read().strip('\n')
        standard_list = tmp.split('\n')
    
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    if not os.path.exists(macro_dir):
        os.mkdir(macro_dir)
    files = get_all_file_path(project_dir)
    # print(files)
    index_start = 0
    # func_list = list()
    # line_list = list()
    fcname_list = list()
    all_list = list()
    for file_path in files:
        file_name = file_path.split('/')[-1]
        # if file_name != 'pcap.c':
        #     continue
        content = ''
        with open(file_path, 'r',errors='ignore') as f:
            content = f.read()
        cc = CCode(content)
        funcs = cc.get_by_type_name('function_definition')
        # print(len(funcs))
        macro_prefix = macro_dir + file_name
        macro_list = get_macro_function(cc, file_path, macro_out_path, macro_prefix)
        all_list.extend(macro_list)
        # print(file_path)
        # exit(1)
        if len(funcs) == 0:
            continue
        print(type(funcs[0]))
        for func in funcs:
            standard_num = 0
            other_num = 0
            indirect_num = 0
            indirect_fc = list()
            standard_fc = list()
            other_fc = list()
            func_name = str(func.name)
            out_func_path = out_dir + '/' + file_name + '-' + func_name
            out_dict = dict()
            out_dict['func'] = func_name
            out_dict['orig_path'] = os.path.abspath(file_path)
            out_dict['path'] = os.path.abspath(out_func_path)
            out_dict['declaration'] = str(func.type).strip('\n') + ' ' + str(func.declarator)
            func_content = str(func.type).strip('\n') + ' ' + str(func.declarator) + str(func.body)
            print(out_dict)
            with open(out_func_path, 'w') as f:
                f.write(func_content + '\n')
            calls = func.children_by_type_name('call_expression')
            call_list = list()
            for call in calls:
                call_name = str(call.function)
                if call_name in call_list:
                    continue
                else:
                    call_list.append(call_name)
                # print(call.function)
                # print(call)
                if call.is_indirect():
                    # print(call.identifier)
                    indirect_num += 1
                    indirect_fc.append(str(call_name))
                    # continue
                elif call_name in standard_list:
                    standard_num += 1
                    standard_fc.append(str(call_name))
                else:
                    other_num += 1
                    other_fc.append(str(call_name))
            # standard_num": 0, "other_num": 0, "standard_fc": [], "other_fc": []
            out_dict['standard_num'] = standard_num
            out_dict['other_num'] = other_num
            out_dict['standard_fc'] = standard_fc
            out_dict['other_fc'] = other_fc
            out_dict['indirect_fc'] = indirect_fc
            out_dict['indirect_num'] = indirect_num
            out_dict['type'] = 'function'
            all_list.append(out_dict)

    all_list.sort(key=lambda k: (k.get('other_num', 0)), reverse=False)
    for item in all_list:
        with open(out_path, 'a') as f:
            f.write(json.dumps(item))
            f.write('\n')