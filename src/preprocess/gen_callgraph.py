import os
import json
import copy

before_list = list()
loop_flag = False

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

def write_out(path, out_dict):
    with open(path, 'a') as f:
        f.write(json.dumps(out_dict))
        f.write('\n')

def get_callees(callee_list):
    out_list = list()
    no_fc_list = list()
    for callee in callee_list:
        before_list.append(callee)
        if callee in func_dict.keys():
            other_fc = func_dict[callee]['other_fc']
            if len(other_fc) == 0 or (len(other_fc) == 1 and callee in other_fc):
                out_list.append(callee)
            
            else:
                flag = True
                tmp_other_fc = list()
                # if recursive before_list:
                for other_callee in other_fc:
                    if other_callee not in before_list:
                        flag = False
                        tmp_other_fc.append(other_callee)
                if flag:
                    loop_flag = True
                    
                    out_list.append(callee)
                else:
                    other_fc = tmp_other_fc
                    tmp_out_list, tmp_no_list = get_callees(other_fc)
                    out_list.extend(tmp_out_list)
                    out_list.append(callee)
                    # before_list = out_list
                    no_fc_list.extend(tmp_no_list)
        else:
            out_list.append(callee)
            no_fc_list.append(callee)
    return out_list, no_fc_list

if __name__ == '__main__':
    standard_path = '../../test_info/standard_api'
    # CHANGE:
    lib_name = 'libpcap'
    out_dir = '../../test_info/' + lib_name + '-funcs/'
    # END
    
    in_path = out_dir + '/0func_info.json'
    prog_path = out_dir + '/0func_list'
    
    out_path = out_dir + '/0call_graph.json'
    in_list = read_json(in_path)
    length = len(in_list)
    print(length)
    i = 0
    func_dict = dict()
    for line in in_list:
        func = line['func']
        other_fc = line['other_fc']
        stand_fc = line['standard_fc']
        if func in func_dict.keys():
            if len(other_fc) + len(stand_fc) > len(func_dict[func]['other_fc']) + len(func_dict[func]['standard_fc']):
                func_dict[func]['other_fc'] = other_fc
                func_dict[func]['standard_fc'] = stand_fc
        else:
            func_dict[func] = dict()
            func_dict[func]['other_fc'] = other_fc
            func_dict[func]['standard_fc'] = stand_fc
    for line in in_list: 
        loop_flag = False
        out_dict = dict()
        before_list = list()
        if line['type'] == 'macro':
            continue
        out_dict['path'] = line['path']
        out_dict['func'] = line['func']
        
        out_dict = copy.deepcopy(line)
        out_dict['lib'] = lib_name
        print(f'{str(i)} / {str(length)}')
        print(line['func'])
        i += 1
        other_num = line['other_num']
        if other_num == 0:
            out_dict['call_graph'] = [line['func']]
            out_dict['analyse_func_num'] = 1
            out_dict['loop_info'] = False
            out_dict['no_fc'] = list()
            out_dict['no_fc_num'] = 0
            write_out(out_path, out_dict)
            continue
        # callee_dict = dict()
        analyse_order_list, no_func_list = get_callees(line['other_fc'])
        analyse_num = len(analyse_order_list) + 1
        analyse_order_list.append(line['func'])
        out_dict['call_graph'] = analyse_order_list
        out_dict['analyse_func_num'] = analyse_num
        out_dict['loop_info'] = loop_flag
        out_dict['no_fc'] = no_func_list
        out_dict['no_fc_num'] = len(no_func_list)
        
        write_out(out_path, out_dict)
        # print(no_func_list)
        print(analyse_order_list)
        # print(loop_flag)
