import idaapi
import ida_funcs
import idc
import requests
import json
import ida_hexrays
import urllib3
import threading
import queue
import ida_kernwin
import ida_loader
from transformers import AutoTokenizer
import tiktoken


urllib3.disable_warnings()

# CodeCheck check flag
CodeCheck_flag = True

AI_return = queue.Queue()
exception_code_collection = []
processed_func = []
processing_func = []

# Function information base of dictionary structure
# func start ea：node object
function_info = {}

# LLM API config
API_KEY = "api_key"  
API_URL = "api_url"  
MODEL = "model name"  

# analyze prompt
chinese_prompt = "你是一个专业的恶意代码分析师,现在分析ida提供的伪代码,以json格式把结果返回给我,要求包含两个对象,'des':对该函数功能的中文描述。'name':给该函数一个合适的英文名称。代码如下："
english_prompt = "You are a professional malware analyst. Now analyze ida's pseudocode and return the result to me in JSON format. The result should contain two objects: 'des' — a English description of the function's purpose, and 'name' — an appropriate English name for the function. The code is as follows: "
analyze_prompt = english_prompt

# conversation prompt
chinese_conversation_promot = "你是一个专业的恶意代码分析师,现在分析ida提供的伪代码。你需要默认遵守以下要求:0.使用中文回答用户的提问,回答用户对于恶意样本中该函数的疑问。1.函数名称以'AI_'的函数名称和函数注释并非完全可信,变量名称有一部分为自动生成,因此并非所有的变量名称都可信,以你的逻辑推理为准。2.ida提供的伪代码并非完全精准准确,有可能存在一些反编译错误,需要你基于自己的推理逻辑进行对话。3.直接返回回复,回复的格式为普通txt格式,并且在回复中不用再次提及要求的内容。"
english_conversation_promot = "You are a professional malware analyst, and now you are analyzing the pseudocode provided by ida. You need to comply with the following requirements by default: 0. Use English to answer the user's questions and answer the user's questions about the function in the malicious sample. 1. Function names and function comments with 'AI_' are not completely credible. Some variable names are automatically generated, so not all variable names are credible. Your logical reasoning is the standard. 2. The pseudocode provided by ida is not completely accurate. There may be some decompilation errors. You need to communicate based on your own reasoning logic. 3. Return the reply directly. The format of the reply is ordinary txt format, and there is no need to mention the required content again in the reply."
conversation_promot = english_conversation_promot


# analyze mode don't use memory, because the context limit
def chat_with_AI(content):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    
    if type(content) is list:
        payload = {
            "model": MODEL,  
            "messages": content,
            "temperature": 0.7 # it you want more creative, set it to 1.0. More rigorous and lower.
        }  
    else:
        payload = {
            "model": MODEL,  
            "messages": [
                {"role": "user", "content": analyze_prompt + content}
            ],
            "temperature": 0.7 # it you want more creative, set it to 1.0. More rigorous and lower.
        }      

    try:
        response = requests.post(
            API_URL,
            headers=headers,
            data=json.dumps(payload)
        )
        response.raise_for_status()
        if type(content) is list:     
            result = response.json()['choices'][0]['message']['content']
        else:
            result = json.loads(response.json()['choices'][0]['message']['content'].split("```json")[-1].split("```")[0])
        return result if response.status_code == 200 else None

    except Exception as e:
        print(f"[REAI] error: {type(e).__name__} - {str(e)}")
        print(f'[REAI] text : {response.text}')
        return None


# conversation module
CLI: ida_kernwin.cli_t = None
func_choose = None
memory: list[dict] = None
idb_path = None
max_tokens = 64000 # 64K
huggingface_model_name = {
    "deepseek-chat": "deepseek-ai/DeepSeek-V3-0324",
    "deepseek-reasoner": "deepseek-ai/DeepSeek-R1"
}


class talk_with_LLM(ida_kernwin.cli_t):
    flags = 0
    sname = "REAI"
    lname  = "REAI"
    hint = "REAI"
    locked = False
    
    def OnExecuteLine(self, line):
        if line == "":
            return False
        elif self.locked == True:
            print("[REAI] Please wait for the previous task to finish.")
            return False
        elif idb_path != ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            print("[REAI] New idb, please choose a function again.")
            return False
        
        if func_choose != None:
            threading.Thread(target=conversation_thread, args=(line,)).start()
            self.locked = True
        else:
            print("[REAI] Please choose a function.")
            return False
        return True

    def OnKeydown(self, line, x, sellen, vkey, shift):
        pass


def conversation_thread(line):
    global memory
    global CLI
    global func_choose
    if memory == None:
        print("[REAI] Start conversation, default max tokens: 64000.")
        memory = []
        memory.extend([
            {"role": "system", "content": conversation_promot},
            {"role": "system", "content": func_choose},
            {"role": "user", "content": line}
        ])
    else:
        memory.append({"role": "user", "content": line})
    

    if "gpt" in MODEL:
        # have not test chatgpt, sry
        enc = tiktoken.encoding_for_model(MODEL)
        token_len = len(enc.encode(str(memory)))
    elif MODEL in huggingface_model_name:
        tokenizer = AutoTokenizer.from_pretrained(huggingface_model_name[MODEL])
        token_len = len(tokenizer.encode(str(memory), add_special_tokens=False))
    else:
        print("[REAI] Can't calculate token length, continue.")
        token_len = 0
    
    if token_len > max_tokens:
        print("[REAI] Token limit exceeded. End conversation.")
        func_choose = None
        memory = None
        return False
    else:
        print(f"[REAI] Token {token_len}/{max_tokens}")
        return_content = chat_with_AI(memory)

    CLI.locked = False
    memory.append({"role": "assistant", "content": return_content})
    print(f"{MODEL}: {return_content}")


# rename function, pre 'AI_' to mark AI recognition
def rename_function(func_ea, new_name):
    current_name = ida_funcs.get_func_name(func_ea)
    if new_name != current_name and 'sub_' not in new_name:
        return idaapi.set_name(func_ea, 'AI_' + new_name, idaapi.SN_NOWARN)
    return False


# get caller address and call address
# eg: 0x2255a7(caller address) call to : 0x784c(next function)
def get_function_calls(func_ea):
    cfunc = ida_hexrays.decompile(func_ea)
    function_calls = {}

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_call:
                function_calls[e.ea] = e.x.obj_ea
            return 0

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)

    return function_calls
    

# add comment to pseudocode
def add_decompiled_comment(ea, comment):
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print(f"[REAI] Failed to decompile function at {hex(ea)}")
        return False

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        def visit_expr(self, e):
            if e.ea == ea:
                loc = ida_hexrays.treeloc_t()
                loc.ea = e.ea
                loc.itp = idaapi.ITP_SEMI
                cfunc.set_user_cmt(loc, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                return 1  
            return 0

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)
    cfunc.refresh_func_ctext()
    return True

# create function for all call insn
def call_add_func(ea):
    try:
        func = ida_funcs.get_func(ea)
        func_start = func.start_ea
        func_end = func.end_ea
        c_func = ida_hexrays.decompile(ea)
        point = func_start        
        while point <= func_end:
            disasm = idc.GetDisasm(point)
            # 'call    near ptr unk_5D5DACB'
            if 'call' in disasm and 'unk_' in disasm:
                address = int(disasm.split(' ')[-1].strip()[4:], 16)
                flag = ida_funcs.add_func(address)
                if flag == True:
                    print(f'[REAI] decompile call insn at {hex(point)}')
                else:
                    print(f'[REAI] fail decompile call insn at {hex(point)}')

            point = idc.next_head(point)
        c_func.refresh_func_ctext()

    except Exception as e:
        raise Exception(f"[REAI] Exception during decompile at {hex(ea)}: {e}")


# exception code check
def exception_code_check(ea, caller_ea_arg = 0):
    global exception_code_collection
    global processed_func
    global processing_func

    func = ida_funcs.get_func(ea)
    func_name = ida_funcs.get_func_name(ea)
    if caller_ea_arg != 0 and (ea in processed_func or ea in processing_func or func == None or 'sub_' not in func_name):
        return True
    
    processing_func.append(ea)
    call_add_func(ea)

    if CodeCheck_flag == True:
        cfunc = idaapi.decompile(ea)
        if "JUMPOUT" in str(cfunc) or 'MEMORY[' in str(cfunc):
            exception_code_collection.append(hex(ea))

    sub_func = get_function_calls(ea)
    for caller_ea, call_ea in sub_func.items():        
        exception_code_check(call_ea, caller_ea)

    processed_func.append(ea)
    if caller_ea_arg == 0:
        processing_func = []
        if exception_code_collection == []:
            return True
        else:
            return False

class node:
    def __init__(self):
        # start ea of parent function
        self.parent = []
        # sub function info. ea:caller_ea
        self.child = {}
        # parent function chain
        self.parent_chain = set()
        # current function start ea
        self.ea = 0
        # caller function address, used to write comments
        self.caller_ea = []

    
# get call topology
def get_call_topology(ea, caller_ea, parent_ea, parent_chain, count):
    # ea = current function start address; caller_ea = address of the function that calls this function; parent_ea = start address of the parent function; parent_chain = parent function chain
    
    global function_info
    
    # func node create
    current_node = node()
    current_node.ea = ea
    current_node.caller_ea.append(caller_ea)
    current_node.parent_chain = parent_chain | {parent_ea}
    current_node.parent.append(parent_ea)

    sub_func = get_function_calls(ea)
    for caller_ea, call_ea in sub_func.items():
        func_name = ida_funcs.get_func_name(call_ea)
        func = ida_funcs.get_func(call_ea)
        if current_node.child.get(call_ea) == None and call_ea not in current_node.parent_chain and call_ea != ea and func != None and 'sub_' in func_name:
            current_node.child[call_ea] = caller_ea

    function_info[ea] = current_node
    count += 1
    func_name = ida_funcs.get_func_name(ea)
    
    for call_ea, caller_ea in current_node.child.items():
        if function_info.get(call_ea) == None:
            get_call_topology(call_ea, caller_ea, ea, current_node.parent_chain, count)
        else:
            function_info[call_ea].caller_ea.append(caller_ea)
            function_info[call_ea].parent.append(ea)
            function_info[call_ea].parent_chain = function_info[call_ea].parent_chain | current_node.parent_chain | {ea}


# print call topology
def pt():
    for ea, func_node in function_info.items():
        parent = [hex(i) for i in func_node.parent]
        parent_chain = [hex(i) for i in func_node.parent_chain]
        del parent_chain[0]
        caller_ea = [hex(i) for i in func_node.caller_ea]
        func_name = ida_funcs.get_func_name(func_node.ea)
        print('----------------------')
        print(f'func name : {func_name}')
        print(f'parent func: {parent}')
        print(f'parent chain: {parent_chain}')
        print(f'caller ea: {caller_ea}')

        for i, j in func_node.child.items():
            print(f'sub func call ea: {hex(i)} caller ea: {hex(j)}')


def select_address_check(ea):
    func = ida_funcs.get_func(ea) 
    c_func = ida_hexrays.decompile(ea)
    if func == None or c_func == None:
        raise Exception(f'[REAI] select wrong address, try again')
    return func.start_ea


def AI_work(ea, pseudocode, func_name):
    if (api_result := chat_with_AI(pseudocode)):
        new_func_name = api_result.get("name", func_name)
        description = api_result.get("des", "None")
        info = []
        info.append(ea)
        info.append(new_func_name)
        info.append(description)
        AI_return.put(info)
    else:
        print(f'[REAI] bad api result, func: {func_name} ea: {hex(ea)}')
        AI_return.put(['bad'])


# use call topology to analyze function
def AI_ananalyze(func_start):
    global function_info
    count = 0
    while(len(function_info[func_start].child) != 0):
        print('------------------------------')
        print(f'[REAI] round {count}')
        if count >= 30:
            # maybe infinite loop, check it
            pt()
            raise Exception('[REAI] out of 30 round, exit')

        round_list = []
        thread_list = []
        for ea, func_node in function_info.items():
            if len(func_node.child) == 0:
                round_list.append(func_node.ea)
                c_func = ida_hexrays.decompile(ea)
                c_func.refresh_func_ctext()
                func_name = ida_funcs.get_func_name(ea)
                sub_thread = threading.Thread(target=AI_work, args=(func_node.ea, str(c_func), func_name))
                thread_list.append(sub_thread)
                sub_thread.start()

        for i in thread_list:
            i.join()
            info = AI_return.get()
            if info[0] == 'bad':
                print('[REAI] detect API error, continue')
                continue
            func_ea = info[0]
            new_func_name = info[1]
            description = info[2]
            name_count = 0
            old_name = ida_funcs.get_func_name(func_ea)
            rename_flag = rename_function(func_ea, new_func_name)
            temp_name = new_func_name + '_'

            while rename_flag == False:
                if name_count >= 5:
                    print('[REAI] multiple rename, fail!')
                    break
                new_func_name = temp_name + str(name_count)
                rename_flag = rename_function(func_ea, new_func_name)
                name_count += 1
                
            if rename_flag == False:
                print(f"[REAI] fail !!! Renamed: {old_name} -> {'AI_' + new_func_name}")
                name = old_name
            else:
                print(f"[REAI] Renamed: {old_name} -> {'AI_' + new_func_name}")
                name = 'AI_' + new_func_name

            ida_hexrays.decompile(func_ea).refresh_func_ctext()

            for i in function_info[func_ea].caller_ea:
                add_decompiled_comment(i, description + f' by func: {name}')
        

        for i in round_list:
            del function_info[i]
        
        for ea, func_node in function_info.items():
            for i in round_list:
                if func_node.child.get(i) != None:
                    del func_node.child[i]
        
        print(f'[REAI] Finish round {count}, parse list: {", ".join([hex(addr) for addr in round_list])}')
        count += 1

    c_func = ida_hexrays.decompile(func_start)
    c_func.refresh_func_ctext()
    func_name = ida_funcs.get_func_name(func_start)
    
    if (api_result := chat_with_AI(str(c_func))):
        if rename_function(func_start, api_result.get("name", func_name)):
            idc.set_func_cmt(func_start,api_result.get("des", "None"), True)
            print(f"[REAI] Renamed: {func_name} -> {api_result['name']}")
    c_func.refresh_func_ctext()


class func_analyze(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global function_info
        global CodeCheck_flag
        global processed_func
        CodeCheck_flag = False
        ea = idc.get_screen_ea()
        func_start = select_address_check(ea)
        exception_code_check(ea)
        processed_func = []
        get_call_topology(func_start, 0, 0, set(), 0)
        print('[REAI] start AI parser')
        AI_ananalyze(func_start)
        function_info = {}
        print("[REAI] Processing completed!")

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    

class exception_code_check_action(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global exception_code_collection
        global processed_func
        global CodeCheck_flag
        CodeCheck_flag = True
        ea = idc.get_screen_ea()
        select_address_check(ea)

        if exception_code_check(ea) != True:
            print("[REAI] There has exception code")
            print(exception_code_collection)
        else:
            print(f"[REAI] Exception code is not exist, all function num: {len(processed_func)}")     
        exception_code_collection = []
        processed_func = []
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class call_topology_print(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global function_info
        global CodeCheck_flag
        global processed_func
        CodeCheck_flag = False
        ea = idc.get_screen_ea()
        func_start = select_address_check(ea)
        exception_code_check(ea)
        processed_func = []
        get_call_topology(func_start, 0, 0, set(), 0)   
        print('[REAI] Print call topology:')
        pt()
        function_info = {}

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class conversation(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global func_choose
        global memory
        global idb_path
        ea = idc.get_screen_ea()
        select_address_check(ea)
        func_choose = str(ida_hexrays.decompile(ea))
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        memory = None
        print("[REAI] Choose function for conversation successfully!")

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_actions():
    action1 = idaapi.action_desc_t(
        "REAI:func_analyze",
        "func_analyze",   
        func_analyze(),
        "", 
        "AI work for you!",
        0
    )

    action2 = idaapi.action_desc_t(
        "REAI:exception_code_check",
        "exception_code_check",   
        exception_code_check_action(),
        "", 
        "exception code check",
        0
    )

    action3 = idaapi.action_desc_t(
        "REAI:call_topology_print",
        "call_topology_print",   
        call_topology_print(),
        "", 
        "call topology print",
        0
    )

    action4 = idaapi.action_desc_t(
        "REAI:conversation",
        "conversation",   
        conversation(),
        "", 
        "LLM conversation",
        0
    )

    idaapi.register_action(action1)
    idaapi.register_action(action2)
    idaapi.register_action(action3)
    idaapi.register_action(action4)

def unregister_actions():
    idaapi.unregister_action("REAI:func_analyze")
    idaapi.unregister_action("REAI:exception_code_check") 
    idaapi.unregister_action("REAI:call_topology_print") 
    idaapi.unregister_action("REAI:conversation")

class REAI_PLUGIN(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "REAI_PLUGIN"
    help = "REAI_PLUGIN"
    wanted_name = "REAI"
    def init(self):
        global CLI
        print('[REAI] REAI is loading...')
        register_actions()
        self.menu = ContextMenuHooks()
        self.menu.hook()
        print('[REAI] REAI is ready')
        CLI = talk_with_LLM()
        CLI.register()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print('[REAI] Right click on pseudocode view')
        return

    def term(self):
        CLI.unregister()
        if self.menu:
            self.menu.unhook()
        unregister_actions()


def PLUGIN_ENTRY():
    return REAI_PLUGIN()


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, "REAI:func_analyze", "REAI/")
            idaapi.attach_action_to_popup(form, popup, "REAI:exception_code_check", "REAI/")
            idaapi.attach_action_to_popup(form, popup, "REAI:call_topology_print", "REAI/")
            idaapi.attach_action_to_popup(form, popup, "REAI:conversation", "REAI/")