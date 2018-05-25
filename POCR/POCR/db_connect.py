import pymysql

def connection():
    conn = pymysql.connect(host="localhost",
                           user="root",
                           passwd="",
                           db="pocr")

    c = conn.cursor()

    return c, conn