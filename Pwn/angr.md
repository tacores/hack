# angr

https://docs.angr.io/en/latest/index.html

バイナリコードと適切な制約条件を与えることで、ブルートフォースすることなく正解のインプットを導き出せるツール。

https://tryhackme.com/room/redqueenprotocol?taskNo=5&sharerId=674ed42e2374d1bc93db444c

```sh
pip install angr==9.3.1.post1 claripy==9.3.1
```

memory_unlock というバイナリを逆アセンブルしたら下記のコードが得られたとする。  
コードを読んでも、期待されている文字列を読み解くことは困難だが、文字列長26文字であることと、成功／失敗時に表示される文字列は把握できる。

```c
undefined8 main(void)
{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char acStack_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("=================================");
  puts("  HIVE MEMORY UNLOCK PROTOCOL   ");
  puts("  Umbrella Corporation Internal  ");
  puts("=================================");
  __printf_chk(2,"Enter Memory Key: ");
  fgets(acStack_58,0x40,stdin);
  sVar2 = strcspn(acStack_58,"\n");
  acStack_58[sVar2] = '\0';
  iVar1 = validate(acStack_58);
  if (iVar1 == 0) {
    puts("Invalid key. Memory remains locked.");
  }
  else {
    puts("Memory unlocked. I remember everything.");
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

bool validate(byte *param_1)
{
  size_t sVar1;
  long lVar2;
  byte *pbVar3;
  byte bVar4;
  int iVar5;
  bool bVar6;
  
  sVar1 = strlen((char *)param_1);
  bVar6 = false;
  if ((((((int)sVar1 == 0x1a) && (*param_1 == 0x54)) && (param_1[1] == 0x48)) &&
      ((param_1[2] == 0x4d && (param_1[3] == 0x7b)))) &&
     ((param_1[0x19] == 0x7d && ((param_1[5] == 0x5f && (param_1[0xe] == 0x5f)))))) {
    lVar2 = 4;
    do {
      for (; ((int)lVar2 == 5 || ((int)lVar2 == 0xe)); lVar2 = lVar2 + 1) {
      }
      if (0x19 < (byte)(param_1[lVar2] + 0xbf)) {
        return false;
      }
      lVar2 = lVar2 + 1;
    } while (lVar2 != 0x19);
    iVar5 = 0;
    pbVar3 = param_1;
    do {
      iVar5 = iVar5 + (uint)*pbVar3;
      pbVar3 = pbVar3 + 1;
    } while (pbVar3 != param_1 + 0x1a);
    bVar6 = false;
    if (iVar5 == 0x83c) {
      bVar4 = 0;
      pbVar3 = param_1;
      do {
        bVar4 = bVar4 ^ *pbVar3;
        pbVar3 = pbVar3 + 1;
      } while (pbVar3 != param_1 + 0x1a);
      bVar6 = false;
      if ((bVar4 == 0x18) && ((byte)(param_1[4] * '_') == '\x17')) {
        if (((byte)(param_1[6] * param_1[7]) == '\x1a') &&
           ((uint)param_1[6] - (uint)param_1[7] == 0xd)) {
          if (((byte)(param_1[8] * param_1[9]) == -0x3f) &&
             ((uint)param_1[8] - (uint)param_1[9] == 8)) {
            if (((byte)(param_1[10] * param_1[0xb]) == -0x26) &&
               ((uint)param_1[10] - (uint)param_1[0xb] == 0xb)) {
              if (((byte)(param_1[0xc] * param_1[0xd]) == '\x1a') &&
                 ((uint)param_1[0xc] - (uint)param_1[0xd] == -0xd)) {
                if (((byte)(param_1[0xf] * param_1[0x10]) == '.') &&
                   ((uint)param_1[0xf] - (uint)param_1[0x10] == -0x11)) {
                  if (((byte)(param_1[0x11] * param_1[0x12]) == '\x1a') &&
                     ((uint)param_1[0x11] - (uint)param_1[0x12] == -0xd)) {
                    if (((byte)(param_1[0x13] * param_1[0x14]) == '4') &&
                       ((uint)param_1[0x13] - (uint)param_1[0x14] == 5)) {
                      if (((byte)(param_1[0x15] * param_1[0x16]) == -0x78) &&
                         ((uint)param_1[0x15] - (uint)param_1[0x16] == -1)) {
                        if ((byte)(param_1[0x17] * param_1[0x18]) == -0x5e) {
                          bVar6 = (uint)param_1[0x17] - (uint)param_1[0x18] == 7;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return bVar6;
}
```

solve.py

```python
import logging
logging.basicConfig(level=logging.CRITICAL)
import angr
import claripy

proj = angr.Project('./memory_unlock', auto_load_libs=False)
main_addr = proj.loader.find_symbol('main').rebased_addr

# angr ships no default SimProcedure for strcspn; unresolved with auto_load_libs=False
# it falls back to a stub that fabricates a return value without scanning the buffer.
# Our binaries only ever call strcspn(buf, "\n"), so a targeted hook is enough.
class FixedStrcspn(angr.SimProcedure):
    def run(self, s_addr, reject_addr):
        max_len = 64
        result = claripy.BVV(max_len, self.state.arch.bits)
        for i in range(max_len - 1, -1, -1):
            c = self.state.memory.load(s_addr + i, 1)
            result = claripy.If(c == 0x0a, claripy.BVV(i, self.state.arch.bits), result)
        return result

proj.hook_symbol('strcspn', FixedStrcspn())

# 26文字＋改行の制約
flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(26)]
flag_input = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
state = proj.factory.call_state(
    main_addr,
    stdin=angr.SimFile('<stdin>', content=flag_input, size=27),
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)
# 26文字は全て印字可能文字との制約
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
# 成功時と失敗時に現れる文字列を与える
simgr.explore(
    find=lambda s: b'remember' in s.posix.dumps(1),
    avoid=lambda s: b'locked' in s.posix.dumps(1)
)
if simgr.found:
    sol = simgr.found[0]
    print(sol.posix.dumps(0).decode('latin-1').strip())
else:
    print("No solution found. Full stash summary:")
    for name, stash in simgr.stashes.items():
        print(f"  {name}: {len(stash)}")
    if simgr.avoid:
        a = simgr.avoid[0]
        print(f"[debug] avoid[0] stdin dump: {a.posix.dumps(0)!r}")
```

```sh
python solve.py
THM{I_REMEMBER_[REDACTED]}
```
