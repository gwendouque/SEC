# Databases

# TODO -
### MySQL
```
mysql -h <IP> -u <username> -p
```
```
SET PASSWORD FOR root@localhost = PASSWORD('newpassword');
```
```
SHOW DATABASES;
USE <db name>;
SHOW TABLES;
SHOW FIELDS FROM <table>;
```
```
DROP DATABASE <db name>;
```
```
CREATE DATABASE <db name>;
GRANT ALL PRIVILEGES ON <db name>.* TO 'username' @ 'localhost' IDENTIFIED BY 'password';
SHOW GRANTS FOR 'username'@'localhost';
```
```
SELECT * FROM <table>;
SELECT * FROM <table> WHERE <field> = “value”;
```
```
SELECT LOAD_FILE('/etc/passwd')\g;
```
```
DROP TABLE 'table1', 'table2', 'table3';
```
```
ORDER BY <field> <ASC, DESC>
GROUP BY <field>
LIMIT <number>
OFFSET <number>
```
------------------------------------------------------------------------------------------------------

### Postgresql
```
psql -h <IP> -U <username> -d <database>
-W <password>
select username, passwd from pg_shadow;
select current_database();
create table test (input TEXT); copy test from '/etc/passwd'; select input from test;
```
