import json

try:
    # Python2
    from urllib2 import urlopen
except ImportError:
    # Python3
    from urllib.request import urlopen

import idc
import idaapi
import idautils
from idaapi import plugin_t

# IDA 9.1 imports
from ida_kernwin import Choose
from idc import op_enum

class ChooseMagicNumber(Choose):
    
    def __init__(self, value, results):
        print("[IdaMagnum] Creating magic number chooser dialog for value: 0x%X" % value)
        print("[IdaMagnum] Found %d results from MagnumDB" % len(results))
        
        Choose.__init__(self,
            "[IdaMagnum] Select enum from MagnumDB.com for value : 0x%X" % value,
            [ ["name",   13 | Choose.CHCOL_PLAIN], 
              ["value",  10 | Choose.CHCOL_HEX],
              ["source",  13 | Choose.CHCOL_PLAIN],
            ],
            Choose.CH_MODAL
        )

        self._results = results

    def OnSelectLine(self, n):
        print("[IdaMagnum] User selected line %d" % n)
        pass

    def OnGetLine(self, n):
        res = self._results[n]
        return [
            res["Title"], 
            res.get("HexValue", ""),
            res["DisplayFilePath"]
        ]  

    def OnRefresh(self, n):
        return n

    def OnGetSize(self):
        return len(self._results)

class SearchMagicNumber(idaapi.action_handler_t):

    MAGNUMDB_QUERY = "https://www.magnumdb.com/api.aspx?q=0x{value:X}&key={key:s}"
    MAGNUMDB_KEY = "f344dc86-7796-499f-be38-ec39a5414289"

    def __init__(self, manager):
        idaapi.action_handler_t.__init__(self)
        self._manager = manager
        print("[IdaMagnum] SearchMagicNumber handler initialized")

    def shift_bit_length(self, x):
        return 1<<(x-1).bit_length()

    def activate(self, ctx):
        print("[IdaMagnum] SearchMagicNumber activated at address: 0x%X" % ctx.cur_ea)
        
        instruction = idc.GetDisasm(ctx.cur_ea)
        selection = ctx.cur_extracted_ea
        
        print("[IdaMagnum] Instruction: %s" % instruction)
        print("[IdaMagnum] Raw selection: 0x%X" % selection)

        selected_value = None
        
        import re
        hex_matches = re.findall(r'([0-9A-Fa-f]+)h', instruction)
        if hex_matches:
            for hex_str in hex_matches:
                hex_val = int(hex_str, 16)
                print("[IdaMagnum] Found hex value in instruction: %s = 0x%X" % (hex_str, hex_val))
                if hex_val == selection or (selection & 0xFFFFFFFF) == hex_val:
                    selected_value = hex_val
                    print("[IdaMagnum] Matched hex value: 0x%X" % selected_value)
                    break
        
        if selected_value is None:
            decimal_matches = re.findall(r'\b(\d+)\b', instruction)
            for dec_str in decimal_matches:
                dec_val = int(dec_str)
                print("[IdaMagnum] Found decimal value in instruction: %s = %d (0x%X)" % (dec_str, dec_val, dec_val))
                if dec_val == selection or (selection & 0xFFFFFFFF) == dec_val:
                    selected_value = dec_val
                    print("[IdaMagnum] Matched decimal value: %d (0x%X)" % (selected_value, selected_value))
                    break
        
        if selected_value is None:
            selected_value = selection
            print("[IdaMagnum] Using raw selection value: 0x%X" % selected_value)
        
        if selected_value == 0x10 and '40000000' in instruction:
            full_hex_matches = re.findall(r'([0-9A-Fa-f]{6,})h', instruction)
            if full_hex_matches:
                selected_value = int(full_hex_matches[0], 16)
                print("[IdaMagnum] Corrected selection to full hex value: 0x%X" % selected_value)

        print("[IdaMagnum] Final selected value: 0x%X" % selected_value)

        selected_value_mask = self.shift_bit_length(selected_value) - 1
        print("[IdaMagnum] Using mask: 0x%X for value matching" % selected_value_mask)

        url = SearchMagicNumber.MAGNUMDB_QUERY.format(
            value = selected_value,
            key = SearchMagicNumber.MAGNUMDB_KEY
        )
        
        print("[IdaMagnum] Querying MagnumDB with URL: %s" % url)
        
        try:
            answer = urlopen(url)
            results = json.loads(answer.read())
            print("[IdaMagnum] Successfully received %d results from MagnumDB" % len(results.get("Items", [])))
        except Exception as e:
            print("[IdaMagnum] Error querying MagnumDB: %s" % str(e))
            return 1
        
        c = ChooseMagicNumber(selected_value, results["Items"])
        selected_index = c.Show(modal=True)
        if selected_index < 0:
            print("[IdaMagnum] User cancelled selection dialog")
            return 1

        selected_item = results["Items"][selected_index]
        selected_name = selected_item["Title"]
        if isinstance(selected_name, bytes):
            selected_name = selected_name.decode('utf-8')
        selected_value = int(selected_item["Value"])
        
        print("[IdaMagnum] User selected: %s (value: 0x%X)" % (selected_name, selected_value))

        entryid, serial = self._manager.add_magnumdb_entry(
            selected_name, 
            selected_value
        )
        
        print("[IdaMagnum] Added enum entry with ID: %s, serial: %d" % (entryid, serial))

        insn = idautils.DecodeInstruction(ctx.cur_ea)
        
        operands = insn.ops
        print("[IdaMagnum] Instruction has %d operands" % len(operands))

        for i, op in enumerate(filter(lambda o: o.type == idaapi.o_imm, operands)):
            print("[IdaMagnum] Checking operand %d: type=%d, value=0x%X" % (i, op.type, op.value))
            if op.value & selected_value_mask == selected_value:
                print("[IdaMagnum] Applying enum to operand %d" % op.n)
                op_enum(ctx.cur_ea, op.n, idaapi.get_enum("_IDA_MAGNUMDB"), serial)
                print("[IdaMagnum] Enum applied successfully!")
                break
        else:
            print("[IdaMagnum] No matching operand found for enum application")

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ConfigureIdaMagnum(idaapi.action_handler_t):
    def __init__(self, manager):
        idaapi.action_handler_t.__init__(self)
        self._manager = manager
        print("[IdaMagnum] ConfigureIdaMagnum handler initialized")

    def activate(self, ctx):
        print("[IdaMagnum] Configure action activated")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS 

class IdaMagnumManager(object):

    def __init__(self):
        print("[IdaMagnum] IdaMagnumManager initializing...")
        self._attach_to_menu_items()
        print("[IdaMagnum] IdaMagnumManager initialization complete")

    def _attach_to_menu_items(self):
        print("[IdaMagnum] Attaching menu items...")

        self.search_magic_desc = idaapi.action_desc_t(
            'idamagnum:searchmagic',             
            'search magic number ...',              
            SearchMagicNumber(self),         
            "Shift+M",                     
            'Search this value on MagnumDB', 
        )

        self.configure_plugin_desc = idaapi.action_desc_t(
            'idamagnum:configure',             
            'Configure',              
            ConfigureIdaMagnum(self),         
            "",                     
            'Configure plugin',
        )

        reg1 = idaapi.register_action(self.search_magic_desc)
        reg2 = idaapi.register_action(self.configure_plugin_desc)
        
        print("[IdaMagnum] Action registration results: search=%s, configure=%s" % (reg1, reg2))

        attach1 = idaapi.attach_action_to_menu(
            'Edit/Plugins/IdaMagnum/',
            'idamagnum:searchmagic',
            idaapi.SETMENU_APP
        )

        attach2 = idaapi.attach_action_to_menu(
            'Edit/Plugins/IdaMagnum/',
            'idamagnum:configure',
            idaapi.SETMENU_APP
        )
        
        print("[IdaMagnum] Menu attachment results: search=%s, configure=%s" % (attach1, attach2))

        return 0

    def _detach_from_menu_items(self):
        print("[IdaMagnum] Detaching menu items...")
        idaapi.detach_action_from_menu('Edit/Plugins/IdaMagnum/', 'idamagnum:searchmagic')
        idaapi.detach_action_from_menu('Edit/Plugins/IdaMagnum/', 'idamagnum:configure')
        print("[IdaMagnum] Menu items detached")

    def ensure_magnumdb_enum_type(self):
        print("[IdaMagnum] Ensuring MagnumDB enum type exists...")

        enum_id = idaapi.get_enum("_IDA_MAGNUMDB")
        if enum_id == idaapi.BADADDR:
            print("[IdaMagnum] Creating new _IDA_MAGNUMDB enum")
            enum_id = idaapi.add_enum(idaapi.BADADDR, "_IDA_MAGNUMDB", 0)
            print("[IdaMagnum] Created enum with ID: %s" % enum_id)
        else:
            print("[IdaMagnum] Found existing _IDA_MAGNUMDB enum with ID: %s" % enum_id)

        return enum_id

    def add_magnumdb_entry(self, name, value):
        print("[IdaMagnum] Adding MagnumDB entry: %s = 0x%X" % (name, value))
         
        enum_id = self.ensure_magnumdb_enum_type()

        if isinstance(name, bytes):
            name = name.decode('utf-8')

        serial = 0
        enum_memberid = idaapi.get_enum_member(enum_id, value, serial, 0)
        while enum_memberid != idaapi.BADADDR:

            if idaapi.get_enum_member_name(enum_memberid) == name:
                print("[IdaMagnum] Found existing enum member: %s (serial: %d)" % (name, serial))
                return enum_memberid, serial

            serial += 1
            enum_memberid = idaapi.get_enum_member(enum_id, value, serial, 0)

        if enum_memberid == idaapi.BADADDR:
            enum_memberid = idaapi.add_enum_member(enum_id, name, value)
            print("[IdaMagnum] Created new enum member: %s with ID: %s" % (name, enum_memberid))

        return enum_memberid, serial
        

class IdaMagnumPlugin(plugin_t):

    flags = idaapi.PLUGIN_KEEP | idaapi.PLUGIN_PROC
    comment = "search magic numbers using magnumdb.com"
    help = "search magic numbers using magnumdb.com"
    wanted_name = "IdaMagnum"
    wanted_hotkey = ""

    def init(self):
        print("[IdaMagnum] Plugin init() called")
        print("[IdaMagnum] IDA version info: %s" % idaapi.get_kernel_version())
        print("[IdaMagnum] Plugin flags: %s" % self.flags)
        
        global ida_magnumdb_manager

        try:
            if not 'ida_magnumdb_manager' in globals():
                print("[IdaMagnum] Creating new IdaMagnumManager instance")
                ida_magnumdb_manager = IdaMagnumManager()
                print("[IdaMagnum] Ida plugin for MagnumDB v0.0 initialized")
                print("[IdaMagnum] Use Shift+M to search magic numbers!")
            else:
                print("[IdaMagnum] IdaMagnumManager already exists")

            print("[IdaMagnum] Plugin init() returning PLUGIN_KEEP")
            return idaapi.PLUGIN_KEEP
            
        except Exception as e:
            print("[IdaMagnum] Exception during init(): %s" % str(e))
            import traceback
            traceback.print_exc()
            print("[IdaMagnum] Plugin init() returning PLUGIN_SKIP due to error")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        print("[IdaMagnum] Plugin run() called with arg: %s" % arg)
        pass

    def term(self):
        print("[IdaMagnum] Plugin term() called")
        global ida_magnumdb_manager
        if 'ida_magnumdb_manager' in globals():
            ida_magnumdb_manager._detach_from_menu_items()
            print("[IdaMagnum] Plugin terminated")

def PLUGIN_ENTRY():
    print("[IdaMagnum] PLUGIN_ENTRY() called")
    return IdaMagnumPlugin()
