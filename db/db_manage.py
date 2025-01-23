import sqlite3
from datetime import datetime
from os import path

db = 'blocked_ip.db'
exist = path.isfile(db)
con = sqlite3.connect(db)
cur = con.cursor()

if not exist:
    cur.execute("CREATE TABLE blacklist (ip TEXT, date_added DATETIME)")
    cur.execute("CREATE TABLE whitelist (ip TEXT, date_added DATETIME)")
    con.commit()

def add_ip(ip, table):
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Convert to string
    cur.execute(f"""
    INSERT INTO {table} (ip, date_added)
    SELECT ?, ?
    WHERE NOT EXISTS (
        SELECT 1 FROM {table} WHERE ip = ?
    )
""", (ip, current_date_time, ip))
    con.commit()

def remove_ip(ip, table):
    cur.execute(f"DELETE FROM {table} WHERE ip='{ip}'")
    con.commit()

def display_blacklist():
    print("Printing Blacklisted IPs: ")
    for row in cur.execute("SELECT * from blacklist"):
        print(row)

def display_whitelist():
    print("Printing Whitelisted IPs: ")
    for row in cur.execute("SELECT * from whitelist"):
        print(row)

if __name__ == "__main__":
    while True:    
        print("Welcome to Database management for blocked IPs")
        choice = input("""Select a valid operation:
1. Blacklist an IP
2. Remove from Blacklist
3. Display Blacklist
4. Whitelist an IP 
5. Remove from Whitelist
6. Display Whitelist
7. Exit                   
Enter option (1-7): """)
        while choice not in ('1','2','3','4','5','6','7'):
            choice = input("Invalid option, select a valid option(1-7): ")
        if choice=='1':
            ip = input("Enter IP: ")
            add_ip(ip, 'blacklist')
            print("IP Added to Blacklist")
        elif choice=='2':
            ip = input("Enter IP: ")
            remove_ip(ip, 'blacklist')
            print("IP Removed from Blacklist")
        elif choice=='3':
            display_blacklist()
        elif choice=='4':
            ip = input("Enter IP: ")
            add_ip(ip, 'whitelist')
            print("IP Added to Whitelist")
        elif choice=='5':
            ip = input("Enter IP: ")
            remove_ip(ip, 'whitelist')
            print("IP Removed from Whitelist")
        elif choice=='6':
            display_whitelist()
        elif choice=='7':
            print("Quitting....")
            quit(0)

con.close()