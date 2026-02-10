# Radre2

https://github.com/radareorg/radare2

kali にはデフォルトでインストールされている。

pwntools のような攻撃用ツールではなく、解析用ツール。

## 起動

```sh
r2 --help
```

実行ファイルを指定して起動。-A を付けて自動解析。

```sh
r2 -A ./foo
```

デバッグ起動

```sh
r2 -d ./foo
```

## ヘルプ

```sh
[0x00400570]> ?
Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...   
Append '?' to any char command to get detailed help
Prefix with number to repeat command N times (f.ex: 3x)
| %var=value              alias for 'env' command
| *[?] off[=[0x]value]    pointer read/write data/values (see ?v, wx, wv)
| (macro arg0 arg1)       manage scripting macros
| .[?] [-|(m)|f|!sh|cmd]  Define macro or load r2, cparse or rlang file
| _[?]                    Print last output
| =[?] [cmd]              send/listen for remote commands (rap://, raps://, udp://, http://, <fd>)
| <[...]                  push escaped string into the RCons.readChar buffer
| /[?]                    search for bytes, regexps, patterns, ..
| ![?] [cmd]              run given command as in system(3)
| #[?] !lang [..]         Hashbang to run an rlang script
| a[?]                    analysis commands
| b[?]                    display or change the block size
| c[?] [arg]              compare block with given data
| C[?]                    code metadata (comments, format, hints, ..)
| d[?]                    debugger commands
| e[?] [a[=b]]            list/get/set config evaluable vars
| f[?] [name][sz][at]     add flag at current address
| g[?] [arg]              generate shellcodes with r_egg
| i[?] [file]             get info about opened file from r_bin
| k[?] [sdb-query]        run sdb-query. see k? for help, 'k *', 'k **' ...
| l [filepattern]         list files and directories
| L[?] [-] [plugin]       list, unload load r2 plugins
| m[?]                    mountpoints commands
| o[?] [file] ([offset])  open file at optional address
| p[?] [len]              print current block with format and length
| P[?]                    project management utilities
| q[?] [ret]              quit program with a return value
| r[?] [len]              resize file
| s[?] [addr]             seek to address (also for '0x', '0x1' == 's 0x1')
| t[?]                    types, noreturn, signatures, C parser and more
| T[?] [-] [num|msg]      Text log utility (used to chat, sync, log, ...)
| u[?]                    uname/undo seek/write
| v                       visual mode (v! = panels, vv = fcnview, vV = fcngraph, vVV = callgraph)
| w[?] [str]              multiple write operations
| x[?] [len]              alias for 'px' (print hexadecimal)
| y[?] [len] [[[@]addr    Yank/paste bytes from/to memory
| z[?]                    zignatures management
| ?[??][expr]             Help or evaluate math expression
| ?$?                     show available '$' variables and aliases
| ?@?                     misc help for '@' (seek), '~' (grep) (see ~??)
| ?>?                     output redirection
| ?|?                     help for '|' (pipe)
```

a (analyze)コマンドを深堀したい場合

```sh
[0x00400570]> a?
Usage: a  [abdefFghoprxstc] [...]
| a                  alias for aai - analysis information
| a*                 same as afl*;ah*;ax*
| aa[?]              analyze all (fcns + bbs) (aa0 to avoid sub renaming)
| a8 [hexpairs]      analyze bytes
| ab[b] [addr]       analyze block at given address
| abb [len]          analyze N basic blocks in [len] (section.size by default)
| ac[?]              manage classes
| aC[?]              analyze function call
| aCe[?]             same as aC, but uses esil with abte to emulate the function
| ad[?]              analyze data trampoline (wip)
| ad [from] [to]     analyze data pointers to (from-to)
| ae[?] [expr]       analyze opcode eval expression (see ao)
| af[?]              analyze Functions
| aF                 same as above, but using anal.depth=1
| ag[?] [options]    draw graphs in various formats
| ah[?]              analysis hints (force opcode size, ...)
| ai [addr]          address information (show perms, stack, heap, ...)
| aj                 same as a* but in json (aflj)
| aL                 list all asm/anal plugins (e asm.arch=?)
| an [name] [@addr]  show/rename/create whatever flag/function is used at addr
| ao[?] [len]        analyze Opcodes (or emulate it)
| aO[?] [len]        Analyze N instructions in M bytes
| ap                 find prelude for current offset
| ar[?]              like 'dr' but for the esil vm. (registers)
| as[?] [num]        analyze syscall using dbg.reg
| av[?] [.]          show vtables
| ax[?]              manage refs/xrefs (see also afx?)
```

さらに af (analyze functions) を深堀したい場合

```sh
[0x00400570]> af?
Usage: af  
| af ([name]) ([addr])                  analyze functions (start at addr or $$)
| afr ([name]) ([addr])                 analyze functions recursively
| af+ addr name [type] [diff]           hand craft a function (requires afb+)
| af- [addr]                            clean all function analysis data (or function at addr)
| afa                                   analyze function arguments in a call (afal honors dbg.funcarg)
| afb+ fcnA bbA sz [j] [f] ([t]( [d]))  add bb to function @ fcnaddr
| afb[?] [addr]                         List basic blocks of given function
| afbF([0|1])                           Toggle the basic-block 'folded' attribute
| afB 16                                set current function as thumb (change asm.bits)
| afC[lc] ([addr])@[addr]               calculate the Cycles (afC) or Cyclomatic Complexity (afCc)
| afc[?] type @[addr]                   set calling convention for function
| afd[addr]                             show function + delta for given offset
| afF[1|0|]                             fold/unfold/toggle
| afi [addr|fcn.name]                   show function(s) information (verbose afl)
| afj [tableaddr] [count]               analyze function jumptable
| afl[?] [ls*] [fcn name]               list functions (addr, size, bbs, name) (see afll)
| afm name                              merge two functions
| afM name                              print functions map
| afn[?] name [addr]                    rename name for function at address (change flag too)
| afna                                  suggest automatic name for current offset
| afo[?j] [fcn.name]                    show address for the function name or current offset
| afs[!] ([fcnsign])                    get/set function signature at current address (afs! uses cfg.editor)
| afS[stack_size]                       set stack frame size for function at current address
| afsr [function_name] [new_type]       change type for given function
| aft[?]                                type matching, type propagation
| afu addr                              resize and analyze function from current address until addr
| afv[bsra]?                            manipulate args, registers and variables in function
| afx                                   list function references
```

## analyze

analyze function list

```sh
[0x00400570]> afl
0x00400510    1      6 sym.imp.puts
0x00400520    1      6 sym.imp.system
0x00400530    1      6 sym.imp.printf
0x00400540    1      6 sym.imp.gets
0x00400550    1      6 sym.imp.setuid
0x00400560    1      6 sym.imp.sleep
0x00400570    1     42 entry0
0x004005b0    4     37 sym.deregister_tm_clones
0x004005e0    4     55 sym.register_tm_clones
0x00400620    3     29 entry.fini0
0x00400650    1      7 entry.init0
0x00400780    1      2 sym.__libc_csu_fini
0x00400784    1      9 sym._fini
0x00400657    1    129 sym.call_bash
0x00400710    4    101 sym.__libc_csu_init
0x004005a0    1      2 sym._dl_relocate_static_pie
0x004006d8    1     56 main
0x004004e0    3     23 sym._init
```

## debug

```sh
[0x7f64329bfa80]> d?
Usage: d   # Debug commands
| d:[?] [cmd]              run custom debug plugin command
| db[?]                    breakpoints commands
| dbt[?]                   display backtrace based on dbg.btdepth and dbg.btalgo
| dc[?]                    continue execution
| dd[?][*+-tsdfrw]         manage file descriptors for child process
| de[-sc] [perm] [rm] [e]  debug with ESIL (see de?)
| dg <file>                generate a core-file (WIP)
| dh [plugin-name]         select a new debug handler plugin (see dbh)
| dH [handler]             transplant process to a new handler
| di[?]                    show debugger backend information (See dh)
| dk[?]                    list, send, get, set, signal handlers of child
| dL[?]                    list or set debugger handler
| dm[?]                    show memory maps
| do[?]                    open process (reload, alias for 'oo')
| doo[args]                reopen in debug mode with args (alias for 'ood')
| doof[file]               reopen in debug mode from file (alias for 'oodf')
| doc                      close debug session
| dp[?]                    list, attach to process or thread id
| dr[?]                    cpu registers
| ds[?]                    step, over, source line
| dt[?]                    display instruction traces
| dw <pid>                 block prompt until pid dies
| dx[?][aers]              execute code in the child process
| date [-b]                use -b for beat time
```

```sh
# 再開
> dc

# レジスター
> dr
```
