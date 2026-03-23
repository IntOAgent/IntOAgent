CREATE VIRTUAL TABLE t USING fts4(content); INSERT INTO t VALUES('hello world'); SELECT * FROM t WHERE t MATCH 'hello';
