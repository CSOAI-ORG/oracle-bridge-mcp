import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

SRC="CREATE PACKAGE BODY pay AS PROCEDURE run IS BEGIN SELECT x FROM EMP; END; END;"
def test_parse():
    p=server.parse_plsql(SRC); assert "run" in p.procedures; assert "EMP" in p.tables
def test_govern():
    assert server.govern_oracle("EXECUTE IMMEDIATE v;").risk_flags
