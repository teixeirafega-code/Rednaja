import sqlite3
conn = sqlite3.connect('meis.db')
conn.execute("UPDATE users SET is_pro = 1 WHERE email = 'fernando1224gabriel@gmail.com'")
conn.commit()
conn.close()
print('✅ Conta transformada em PRO com sucesso!')


#python ativar_pro.py