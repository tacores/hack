# PE ヘッダー

https://tryhackme.com/room/dissectingpeheaders

## IMAGE_DOS_HEADER

最初の 64 バイト

e_lfanew: IMAGE_NT_HEADERS の開始アドレス

## DOS_STUB

DOS で実行される場合に代わりに実行される小さいコード

## IMAGE_NT_HEADERS

https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32

### NT_HEADERS

#### Signature

4 バイト

#### FILE_HEADER

- Machine：アーキテクチャ
- NumberOfSections：PE ファイルに含まれるセクション数
- TimeDateStamp：バイナリコンパイルの日時
- SizeOfOptionalHeader：オプショナルヘッダーのサイズ
- Characteristics：PE ファイルの特性を表すフラグ

#### OPTIONAL_HEADER

https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

- Magic： PE ファイルが 32 ビットアプリケーションか 64 ビットアプリケーションかを示す。値が 0x010B の場合、32 ビットアプリケーション、値が 0x020B の場合、64 ビットアプリケーションを表す。
- AddressOfEntryPoint：Windows が実行を開始するアドレス。相対仮想アドレス（RVA）であり、メモリにロードされたイメージのベースアドレス（ImageBase）からのオフセット位置。
- BaseOfCode と BaseOfData：それぞれ ImageBase を基準としたコードセクションとデータセクションのアドレス。
- ImageBase：PE ファイル のメモリ内での優先読み込みアドレス。通常、.exe ファイルの ImageBase は 0x00400000。Windows はすべての PE ファイルをこの優先アドレスに読み込むことはできないため、ファイルがメモリに読み込まれる際にいくつかの再配置が行われる。これらの再配置は、ImageBase を基準として実行される。
- Subsystem： イメージの実行に必要なサブシステムを表す。https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
- DataDirectory：PE ファイル のインポート情報とエクスポート情報（インポートアドレステーブルとエクスポートアドレステーブルと呼ばれる）を格納する構造体。

### IMAGE_SECTION_HEADER

- .text：アプリケーションの実行可能コードを含むセクション。このセクションの特性には CODE、EXECUTE、READ が含まれる。
- .data：アプリケーションの初期化されたデータが含まれる。読み取り/書き込み権限はあるが、実行権限はない。
- .rdata/.idata： PE ファイル のインポート情報が含まれることがよくある。インポート情報は、PE ファイルが他のファイルや Windows API から関数をインポートするのに役立つ。
- .ndata：初期化されていないデータが含まれる。
- .reloc： PE ファイル の再配置情報が含まれる。
- .rsrc：アプリケーション UI に必要なアイコン、画像、その他のリソースが含まれる。

各セクションに含まれる情報

- VirtualAddress：メモリ内のこのセクションの相対仮想アドレス (RVA) を示す。
- VirtualSize：メモリにロードされたセクションのサイズを示す。
- SizeOfRawData：PE ファイルがメモリにロードされる 前にディスクに保存されているセクションサイズを表す。
- Characteristic：セクションが持つ権限を示します。例えば、セクションに読み取り権限、書き込み権限、実行権限があるかどうかが分かる。

### IMAGE_IMPORT_DESCRIPTOR

PE ファイルが実行時に読み込む様々な Windows API に関する情報が含まれる。

## パックと識別

正規のソフトウェア開発者は著作権侵害の懸念に対処するためにパッキングを使用し、マルウェア作成者は検出を回避するためにパッキングを使用する。

### 識別

- セクション名が空
- セクションのエントロピーが 8 に近い
- .text セクション以外に EXECUTE 権限が付いている
- WRITE 権限と EXECUTE 権限を持つセクションで、SizeOfRawData が Misc_VirtualSize よりも大幅に小さい。PE ファイルが実行中にアンパックされる際に、このセクションにデータが書き込まれ、ディスク上のサイズと比較してメモリ上のサイズが増加してから実行されるため。
- kernel32.dll から GetProcAddress、GetModuleHandleA、LoadLibraryA がインポートされ、その他が極端に少ない。
